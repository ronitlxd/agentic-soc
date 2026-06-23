#!/usr/bin/env python3
"""
INTEL AGENT — SOC V2
====================

ROLE
    Enrich open tickets with threat intelligence before the Orchestrator briefs
    the operator. Adds context only — makes no detection or containment decisions.

INPUTS
    tickets/*.json         — open tickets (from Investigator / Triage pre-flags)
    feeds/*.txt            — locally downloaded free feeds (daily cron, Phase 0)
    attack_stix.json       — MITRE ATT&CK STIX (technique -> threat groups)
    intel_cache.json       — 24h per-IP enrichment cache
    .env                   — optional API keys (AbuseIPDB, IPinfo, GreyNoise, Shodan)

OUTPUT
    Appends a structured `intel_summary` block to the ticket and a finding entry;
    stamps "intel" into agent_trail. Writes results to intel_cache.json (24h TTL).

ROUTING (priority-aware)
    critical -> skip enrichment (speed; goes straight to Orchestrator)
    high     -> full   (free feeds + API keys if present)
    medium   -> free   (local feeds only, no API calls)
    low      -> light  (IP classification only)
    internal -> skip   (internal IPs are NEVER sent to external APIs)

HANDS OFF TO
    Orchestrator (reads intel_summary to build the brief).
"""

import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address, ip_network

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.expanduser("~/.hermes/soc/.env"))
except Exception:
    pass

try:
    import requests
except Exception:
    requests = None

# ── config ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
TICKETS_DIR = os.path.join(BASE_DIR, "tickets")
FEEDS_DIR   = os.path.join(BASE_DIR, "feeds")
CACHE_PATH  = os.path.join(BASE_DIR, "intel_cache.json")
STIX_PATH   = os.path.join(BASE_DIR, "attack_stix.json")

CACHE_TTL_H = 24
CYCLE_SECS  = int(os.environ.get("INTEL_CYCLE_SECS", "60"))
API_TIMEOUT = 10

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
IPINFO_KEY    = os.environ.get("IPINFO_API_KEY", "").strip()
GREYNOISE_KEY = os.environ.get("GREYNOISE_API_KEY", "").strip()
SHODAN_KEY    = os.environ.get("SHODAN_API_KEY", "").strip()

INTERNAL_NETS = [ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                  "127.0.0.0/8", "100.64.0.0/10")]


# ── helpers ───────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def is_internal(ip):
    try:
        a = ip_address(ip)
    except ValueError:
        return True   # unparseable → treat as non-routable, never send out
    return any(a in n for n in INTERNAL_NETS)


# ── free feeds (loaded once, refreshed on mtime change) ───────────────────────
_feed_cache = {"loaded_at": 0, "sets": {}, "cidrs": []}


def _load_feeds():
    # reload if any feed file changed
    paths = {
        "tor_exit":       os.path.join(FEEDS_DIR, "tor_exits.txt"),
        "feodo_c2":       os.path.join(FEEDS_DIR, "feodo_c2.txt"),
        "et_compromised": os.path.join(FEEDS_DIR, "et_compromised.txt"),
    }
    newest = 0
    for p in list(paths.values()) + [os.path.join(FEEDS_DIR, "spamhaus_drop.txt")]:
        try:
            newest = max(newest, os.path.getmtime(p))
        except OSError:
            pass
    if newest and newest <= _feed_cache["loaded_at"]:
        return

    sets = {}
    for name, p in paths.items():
        s = set()
        try:
            with open(p, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("#", ";")):
                        s.add(line.split()[0])
        except OSError:
            pass
        sets[name] = s

    cidrs = []
    try:
        with open(os.path.join(FEEDS_DIR, "spamhaus_drop.txt"), errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith((";", "#")):
                    tok = line.split(";")[0].strip()
                    try:
                        cidrs.append(ip_network(tok, strict=False))
                    except ValueError:
                        pass
    except OSError:
        pass

    _feed_cache.update(loaded_at=newest, sets=sets, cidrs=cidrs)


def feed_hits(ip):
    _load_feeds()
    hits = []
    for name, s in _feed_cache["sets"].items():
        if ip in s:
            hits.append(name)
    try:
        a = ip_address(ip)
        if any(a in net for net in _feed_cache["cidrs"]):
            hits.append("spamhaus_drop")
    except ValueError:
        pass
    return hits


# ── MITRE ATT&CK group lookup (technique_id -> [group names]) ─────────────────
_mitre_map = None


def _build_mitre_map():
    global _mitre_map
    if _mitre_map is not None:
        return _mitre_map
    _mitre_map = {}
    data = _read_json(STIX_PATH, None)
    if not data:
        return _mitre_map
    objects = data.get("objects", [])
    pattern_extid = {}      # stix_id -> Txxxx
    group_name    = {}      # stix_id -> group name
    for o in objects:
        t = o.get("type")
        if t == "attack-pattern":
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    pattern_extid[o["id"]] = ref["external_id"]
                    break
        elif t == "intrusion-set":
            group_name[o["id"]] = o.get("name", "?")
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
            if src in group_name and tgt in pattern_extid:
                _mitre_map.setdefault(pattern_extid[tgt], set()).add(group_name[src])
    return _mitre_map


def groups_for_technique(technique):
    if not technique:
        return []
    m = _build_mitre_map()
    # try exact, then base technique (strip sub-technique)
    groups = m.get(technique) or m.get(technique.split(".")[0])
    return sorted(groups)[:8] if groups else []


# ── optional API feeds (graceful, key-gated) ──────────────────────────────────

def _abuseipdb(ip):
    if not (ABUSEIPDB_KEY and requests):
        return None
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                         timeout=API_TIMEOUT)
        d = r.json().get("data", {})
        return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
                "country": d.get("countryCode"), "isp": d.get("isp"),
                "usage": d.get("usageType")}
    except Exception:
        return None


def _ipinfo(ip):
    if not (IPINFO_KEY and requests):
        return None
    try:
        r = requests.get("https://ipinfo.io/{}/json".format(ip),
                         params={"token": IPINFO_KEY}, timeout=API_TIMEOUT)
        d = r.json()
        return {"country": d.get("country"), "org": d.get("org"),
                "hostname": d.get("hostname"), "city": d.get("city")}
    except Exception:
        return None


def _greynoise(ip):
    if not (GREYNOISE_KEY and requests):
        return None
    try:
        r = requests.get("https://api.greynoise.io/v3/community/{}".format(ip),
                         headers={"key": GREYNOISE_KEY}, timeout=API_TIMEOUT)
        d = r.json()
        return {"classification": d.get("classification"), "name": d.get("name")}
    except Exception:
        return None


def _shodan(ip):
    if not (SHODAN_KEY and requests):
        return None
    try:
        r = requests.get("https://api.shodan.io/shodan/host/{}".format(ip),
                         params={"key": SHODAN_KEY}, timeout=API_TIMEOUT)
        d = r.json()
        return {"ports": d.get("ports", [])}
    except Exception:
        return None


# ── cross-ticket correlation ──────────────────────────────────────────────────

def prior_tickets(ip, exclude_id):
    ids, techs = [], set()
    if not os.path.isdir(TICKETS_DIR):
        return 0, [], []
    for fn in os.listdir(TICKETS_DIR):
        if not fn.endswith(".json"):
            continue
        t = _read_json(os.path.join(TICKETS_DIR, fn), {})
        if t.get("source_ip") == ip and t.get("ticket_id") != exclude_id:
            ids.append(t.get("ticket_id"))
            if t.get("mitre_technique"):
                techs.add(t["mitre_technique"])
    return len(ids), ids, sorted(techs)


# ── enrichment ────────────────────────────────────────────────────────────────

def _cache_get(ip):
    cache = _read_json(CACHE_PATH, {})
    e = cache.get(ip)
    if not e:
        return None
    ts = e.get("enriched_at", "")
    try:
        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - when < timedelta(hours=CACHE_TTL_H):
            return e["summary"]
    except (ValueError, AttributeError):
        pass
    return None


def _cache_put(ip, summary):
    cache = _read_json(CACHE_PATH, {})
    cache[ip] = {"summary": summary, "enriched_at": now_iso()}
    _write_json(CACHE_PATH, cache)


def enrich(ip, technique, mode):
    """Build an intel_summary for one IP. mode in {full, free, light}."""
    cached = _cache_get(ip)
    labels, feeds = [], feed_hits(ip)

    summary = {
        "ip_reputation":    "unknown",
        "reputation_score": None,
        "known_threat":     bool(feeds),
        "threat_labels":    [],
        "geolocation":      None,
        "org":              None,
        "hosting_provider": None,
        "internet_scanner": None,
        "scanner_name":     None,
        "associated_groups": groups_for_technique(technique),
        "feed_hits":        feeds,
        "enrichment_mode":  mode,
        "enriched_at":      now_iso(),
    }

    if "tor_exit" in feeds:       labels.append("Tor exit node")
    if "feodo_c2" in feeds:       labels.append("Known C2 (Feodo)")
    if "et_compromised" in feeds: labels.append("Emerging Threats compromised")
    if "spamhaus_drop" in feeds:  labels.append("Spamhaus DROP")

    if cached and mode != "full":
        return cached   # reuse cache except for full-mode refresh

    if mode == "full":
        ab = _abuseipdb(ip)
        if ab:
            summary["reputation_score"] = ab.get("score")
            if ab.get("score") is not None:
                labels.append("AbuseIPDB {}/100".format(ab["score"]))
            summary["geolocation"] = ab.get("country")
            summary["org"] = ab.get("isp")
        info = _ipinfo(ip)
        if info:
            summary["geolocation"] = summary["geolocation"] or info.get("country")
            summary["org"] = summary["org"] or info.get("org")
            summary["hosting_provider"] = bool(info.get("org") and
                any(h in (info.get("org") or "").lower()
                    for h in ("hosting", "cloud", "digitalocean", "ovh", "vultr", "aws", "linode")))
        gn = _greynoise(ip)
        if gn and gn.get("classification"):
            summary["internet_scanner"] = gn["classification"] == "malicious"
            summary["scanner_name"] = gn.get("name")
            labels.append("GreyNoise: {}".format(gn["classification"]))
        sh = _shodan(ip)
        if sh and sh.get("ports"):
            labels.append("Open ports: {}".format(sh["ports"][:8]))

    summary["threat_labels"] = labels
    if feeds or (summary["reputation_score"] or 0) >= 50:
        summary["ip_reputation"] = "malicious"
    elif summary["reputation_score"] is not None:
        summary["ip_reputation"] = "clean"

    _cache_put(ip, summary)
    return summary


# ── ticket processing ─────────────────────────────────────────────────────────

MODE_BY_SEVERITY = {"high": "full", "medium": "free", "low": "light"}


def process_ticket(path, ticket):
    if ticket.get("intel_summary") is not None:
        return None   # already enriched
    ip = ticket.get("source_ip", "")
    sev = (ticket.get("severity") or "").lower()

    # critical → skip enrichment (routed direct to Orchestrator)
    if sev == "critical":
        summary = {"enrichment_mode": "skipped_critical", "enriched_at": now_iso(),
                   "associated_groups": groups_for_technique(ticket.get("mitre_technique"))}
    elif is_internal(ip):
        summary = {"enrichment_mode": "skipped_internal", "ip_reputation": "internal",
                   "enriched_at": now_iso(),
                   "associated_groups": groups_for_technique(ticket.get("mitre_technique"))}
    else:
        mode = MODE_BY_SEVERITY.get(sev, "free")
        summary = enrich(ip, ticket.get("mitre_technique"), mode)

    # cross-ticket correlation (local, always)
    n, ids, techs = prior_tickets(ip, ticket.get("ticket_id"))
    summary["prior_tickets"] = n
    summary["prior_ticket_ids"] = ids
    summary["prior_techniques"] = techs

    ticket["intel_summary"] = summary
    ticket.setdefault("findings", []).append({
        "agent": "intel", "timestamp": now_iso(),
        "note": "enriched ({}): rep={} feeds={} groups={} prior={}".format(
            summary.get("enrichment_mode"), summary.get("ip_reputation"),
            summary.get("feed_hits"), summary.get("associated_groups"), n),
    })
    if "intel" not in ticket.get("agent_trail", []):
        ticket.setdefault("agent_trail", []).append("intel")
    _write_json(path, ticket)
    return summary


def run_cycle():
    enriched = 0
    if not os.path.isdir(TICKETS_DIR):
        return 0
    for fn in os.listdir(TICKETS_DIR):
        if not fn.endswith(".json"):
            continue
        p = os.path.join(TICKETS_DIR, fn)
        t = _read_json(p, None)
        if t and t.get("status") == "open" and t.get("intel_summary") is None:
            if process_ticket(p, t) is not None:
                enriched += 1
                print("[INTEL] enriched {} ({})".format(t.get("ticket_id"), t.get("source_ip")))
    return enriched


def run_loop():
    print("[INTEL] Intel V2 | cycle={}s | keys: abuseipdb={} ipinfo={} greynoise={} shodan={}".format(
        CYCLE_SECS, bool(ABUSEIPDB_KEY), bool(IPINFO_KEY), bool(GREYNOISE_KEY), bool(SHODAN_KEY)))
    while True:
        try:
            n = run_cycle()
            if n:
                print("[INTEL] cycle enriched {} ticket(s)".format(n))
        except Exception as e:
            print("[INTEL] cycle error: {}: {}".format(type(e).__name__, e))
        time.sleep(CYCLE_SECS)


if __name__ == "__main__":
    import sys
    if "--once" in sys.argv:
        print("[INTEL] enriched {} ticket(s)".format(run_cycle()))
    else:
        run_loop()
