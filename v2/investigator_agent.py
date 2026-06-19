#!/usr/bin/env python3
"""
INVESTIGATOR AGENT — SOC V2
===========================

ROLE
    The central intelligence of the pipeline. Reads Triage's per-IP statistics
    and applies deterministic correlation rules (Stage 1). Any IP with activity
    that matches no rule is passed to an LLM second pass (Stage 2) for novel-
    pattern detection. Opens enriched, MITRE-tagged, severity-scored tickets.

INPUTS
    ip_stats.json      — live per-IP statistics (PRIMARY, from Triage)
    event_buffer.json  — normalized event stream w/ uuid event_id (secondary)
    tickets/*.json     — existing ticket store (for dedup + memory gate)

OUTPUTS
    tickets/SOC-XXXX.json      — new / updated tickets (detection_method: rule|llm)
    investigator_state_v2.json — {last_event_id, last_run, open_ip_set}

DETECTION
    Stage 1 (deterministic, no LLM): R1, R2, R4, R6, R9, R11 as dict lookups.
        R7/R8/R10 are Triage pre-flags — Investigator does not re-run them.
    Stage 2 (LLM, local qwen3-4b via LM Studio): unmatched IPs with activity,
        gated by a 24h ticket-memory check. JSON-only output; parse failure is
        logged and discarded, never crashes the pipeline.

STATE / RESTART SAFETY
    Deduplication is done against the ticket store (open ticket per source_ip +
    rule), NOT timestamps — so restarts never skip or duplicate. This is the V2
    fix for the V1 timestamp-state bug.

HANDS OFF TO
    Intel (enriches the ticket), then Orchestrator (briefs the operator).
"""

import json
import os
import re
import time
import uuid
from datetime import datetime, timezone, timedelta

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
BASE_DIR       = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
IP_STATS_PATH  = os.path.join(BASE_DIR, "ip_stats.json")
EVENT_BUF_PATH = os.path.join(BASE_DIR, "event_buffer.json")
TICKETS_DIR    = os.path.join(BASE_DIR, "tickets")
STATE_PATH     = os.path.join(BASE_DIR, "investigator_state_v2.json")

CYCLE_SECS     = int(os.environ.get("INVESTIGATOR_CYCLE_SECS", "75"))   # 60-90s
STAGE2_ENABLED = os.environ.get("INVESTIGATOR_STAGE2", "true").lower() == "true"

LM_BASE_URL    = os.environ.get("LM_STUDIO_BASE_URL", "http://127.0.0.1:1234/v1")
LM_MODEL       = os.environ.get("LM_STUDIO_MODEL", "qwen/qwen3-4b-2507")
LM_TIMEOUT     = 30

# rule_id -> (technique, tactic, severity)
RULE_MAP = {
    "R1":  ("T1595",     "Reconnaissance",      "medium"),
    "R2":  ("T1110.001", "Credential Access",   "high"),
    "R4":  ("T1021.004", "Lateral Movement",    "medium"),
    "R6":  ("T1078",     "Initial Access",      "medium"),
    "R9":  ("T1053.003", "Persistence",         "medium"),
    "R11": ("T1190",     "Initial Access",      "high"),
    # --- Tier 1 rules ---
    "R12": ("T1110.003", "Credential Access",   "high"),
    "R13": ("T1078.001", "Initial Access",      "high"),
    "R14": ("T1548.003", "Privilege Escalation","medium"),
    "R16": ("T1543.002", "Persistence",         "medium"),
    "R19": ("T1595.002", "Reconnaissance",      "medium"),
    "R20": ("T1110",     "Credential Access",   "medium"),
    "R21": ("T1078",     "Initial Access",      "high"),
}

OFF_HOURS = {2, 3, 4, 5}


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


def _dt(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def seconds_between(a, b):
    da, db = _dt(a), _dt(b)
    if da and db:
        return abs((db - da).total_seconds())
    return 0


# ── ticket store ──────────────────────────────────────────────────────────────

def _all_tickets():
    out = []
    if not os.path.isdir(TICKETS_DIR):
        return out
    for fn in os.listdir(TICKETS_DIR):
        if fn.endswith(".json"):
            t = _read_json(os.path.join(TICKETS_DIR, fn), None)
            if t:
                out.append((os.path.join(TICKETS_DIR, fn), t))
    return out


def find_open_ticket(ip, rule):
    for path, t in _all_tickets():
        if t.get("status") == "open" and t.get("source_ip") == ip and t.get("rule") == rule:
            return path, t
    return None, None


def find_recent_ticket(ip, hours=24):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    for _, t in _all_tickets():
        if t.get("source_ip") == ip:
            c = _dt(t.get("created", ""))
            if c and c > cutoff:
                return t
    return None


def _next_ticket_id():
    os.makedirs(TICKETS_DIR, exist_ok=True)
    mx = 0
    for fn in os.listdir(TICKETS_DIR):
        m = re.match(r"SOC-(\d+)\.json$", fn)
        if m:
            mx = max(mx, int(m.group(1)))
    return "SOC-{:04d}".format(mx + 1)


def _evidence(stats):
    return {
        "auth_failures":    stats.get("auth_failures", 0),
        "auth_successes":   stats.get("auth_successes", 0),
        "success_username": stats.get("success_username"),
        "failed_usernames": stats.get("failed_usernames", []),
        "scan_targets":     len(stats.get("scan_targets", [])),
        "web_posts":        stats.get("web_posts", 0),
        "cron_events":      stats.get("cron_events", 0),
        "active_hours_utc": stats.get("active_hours_utc", []),
        "known_ip":         stats.get("known_ip", False),
    }


def open_ticket(ip, rule, stats, method="rule", technique=None, tactic=None,
                severity=None, confidence=None, note=None):
    """Open a new ticket, or append an update to an existing open one (dedup)."""
    tech, tac, sev = RULE_MAP.get(rule, (technique, tactic, severity or "low"))
    technique = technique or tech
    tactic    = tactic or tac
    severity  = severity or sev

    path, existing = find_open_ticket(ip, rule)
    if existing:
        existing.setdefault("findings", []).append({
            "agent": "investigator", "timestamp": now_iso(),
            "note": "recheck: " + json.dumps(_evidence(stats)),
        })
        _write_json(path, existing)
        return existing["ticket_id"], False

    tid = _next_ticket_id()
    ticket = {
        "ticket_id":        tid,
        "created":          now_iso(),
        "source_ip":        ip,
        "ip_type":          stats.get("ip_type", "unknown"),
        "rule":             rule,
        "detection_method": method,
        "mitre_technique":  technique,
        "mitre_tactic":     tactic,
        "severity":         severity,
        "evidence":         _evidence(stats),
        "findings":         ([{"agent": "investigator", "timestamp": now_iso(),
                               "note": note}] if note else []),
        "status":           "open",
        "agent_trail":      ["triage", "investigator"],
    }
    if confidence:
        ticket["llm_confidence"] = confidence
    _write_json(os.path.join(TICKETS_DIR, tid + ".json"), ticket)
    return tid, True


# ── Stage 1 rule engine (deterministic dict lookups) ──────────────────────────

def stage1(ip, s):
    """Return list of fired rule_ids for this IP."""
    fired = []
    delta = seconds_between(s.get("first_seen", ""), s.get("last_seen", ""))
    hour  = datetime.now(timezone.utc).hour

    # R1 — Recon → Exploit (external scan then auth/web attempt within 10 min)
    if (s.get("ip_type") == "external"
            and len(s.get("scan_targets", [])) > 0
            and (s.get("auth_failures", 0) > 0 or s.get("web_posts", 0) > 0)
            and delta < 600):
        fired.append("R1")

    # R2 — Brute Force Success
    if s.get("auth_failures", 0) >= 5 and s.get("auth_successes", 0) >= 1:
        fired.append("R2")

    # R4 — Lateral Movement (internal host scanning 5+ targets)
    if s.get("ip_type") == "internal" and len(s.get("scan_targets", [])) >= 5:
        fired.append("R4")

    # R6 — Off-Hours Auth Success from Unknown IP (3 conditions)
    if (s.get("auth_successes", 0) >= 1
            and hour in OFF_HOURS
            and not s.get("known_ip", False)):
        fired.append("R6")

    # R9 — Cron Persistence (real crontab modification, per Triage fix)
    if s.get("cron_events", 0) >= 1:
        fired.append("R9")

    # R11 — Suspicious Web POST (unknown path, 200, unknown IP)
    if (s.get("web_posts", 0) >= 1
            and s.get("web_post_to_unknown_path", False)
            and s.get("web_200_response", False)
            and not s.get("known_ip", False)):
        fired.append("R11")

    # ── Tier 1 rules ──────────────────────────────────────────────────────────
    # R12 — Password Spraying (many usernames, few failures each)
    unique_users = len(set(s.get("failed_usernames", [])))
    if (unique_users >= 5
            and s.get("auth_failures", 0) >= 5
            and (s["auth_failures"] / unique_users) < 3.0):
        fired.append("R12")

    # R13 — Default Account Login
    if s.get("default_account_login", False):
        fired.append("R13")

    # R14 — Sudo Abuse
    if s.get("sudo_failures", 0) >= 3 or s.get("sudo_denied", False):
        fired.append("R14")

    # R16 — Unknown Service Enabled
    if s.get("unknown_service_enabled", False):
        fired.append("R16")

    # R19 — Vulnerability Scanning (20+ distinct paths within 5 min)
    if len(s.get("unique_paths_hit", [])) >= 20 and delta < 300:
        fired.append("R19")

    # R20 — Nextcloud Web Brute Force
    if s.get("web_auth_failures_nextcloud", 0) >= 10:
        fired.append("R20")

    # R21 — Nextcloud Web Brute Force Success
    if (s.get("web_auth_failures_nextcloud", 0) >= 5
            and s.get("web_auth_success_nextcloud", False)):
        fired.append("R21")

    return fired


# ── Stage 2 (LLM on unmatched IPs) ────────────────────────────────────────────

STAGE2_PROMPT = (
    "You are a SOC analyst. Review these IP activity summaries. None matched a "
    "known detection rule. Identify credible threats only.\n\n"
    "Respond ONLY with a JSON array. For each IP output an object:\n"
    '{"ip":"...","finding":"threat" or "none","confidence":"low/medium/high",'
    '"mitre_technique":"T1234" or null,"reasoning":"one sentence max"}\n\n'
    "Summaries:\n{summaries}"
)


def _extract_json_array(text):
    """Pull the first JSON array out of an LLM response. Tolerant of prose."""
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def stage2(candidates):
    """candidates: {ip: stats}. Returns list of threat findings (may be empty)."""
    if not (STAGE2_ENABLED and requests and candidates):
        return []

    summaries = {
        ip: {
            "ip_type": s.get("ip_type"),
            "auth_failures": s.get("auth_failures", 0),
            "auth_successes": s.get("auth_successes", 0),
            "failed_usernames": s.get("failed_usernames", []),
            "web_posts": s.get("web_posts", 0),
            "cron_events": s.get("cron_events", 0),
            "active_hours_utc": s.get("active_hours_utc", []),
            "known_ip": s.get("known_ip", False),
        }
        for ip, s in candidates.items()
    }
    prompt = STAGE2_PROMPT.format(summaries=json.dumps(summaries, indent=2))

    try:
        r = requests.post(
            LM_BASE_URL.rstrip("/") + "/chat/completions",
            json={
                "model": LM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 800,
            },
            timeout=LM_TIMEOUT,
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print("[INV] Stage 2 LLM call failed ({}): {}".format(type(e).__name__, e))
        return []

    parsed = _extract_json_array(content)
    if parsed is None:
        print("[INV] Stage 2 JSON parse failed — response discarded")
        return []

    findings = []
    for item in parsed:
        if isinstance(item, dict) and item.get("finding") == "threat" and item.get("ip") in candidates:
            findings.append(item)
    return findings


# ── main cycle ────────────────────────────────────────────────────────────────

def run_cycle():
    """Run one investigation pass. Returns (opened, updated, llm_findings)."""
    ip_stats = _read_json(IP_STATS_PATH, {})
    if not ip_stats:
        return 0, 0, 0

    opened = updated = 0
    matched_ips = set()

    # Stage 1
    for ip, s in ip_stats.items():
        if ip in ("local", "unknown"):
            continue
        for rule in stage1(ip, s):
            matched_ips.add(ip)
            _, is_new = open_ticket(ip, rule, s, method="rule")
            if is_new:
                opened += 1
                print("[INV] {} opened for {} ({})".format(rule, ip, RULE_MAP[rule][1]))
            else:
                updated += 1

    # Stage 2 — unmatched IPs with non-trivial activity, memory-gated
    candidates = {}
    for ip, s in ip_stats.items():
        if ip in ("local", "unknown") or ip in matched_ips:
            continue
        activity = s.get("auth_failures", 0) + s.get("web_posts", 0) + s.get("cron_events", 0)
        if activity > 0 and not find_recent_ticket(ip, hours=24):
            candidates[ip] = s

    llm_findings = stage2(candidates)
    for f in llm_findings:
        ip = f["ip"]
        _, is_new = open_ticket(
            ip, "LLM", ip_stats[ip], method="llm",
            technique=f.get("mitre_technique"), tactic="Unknown",
            severity="low", confidence=f.get("confidence"),
            note="LLM: " + str(f.get("reasoning", ""))[:200])
        if is_new:
            opened += 1
            print("[INV] LLM threat opened for {} ({})".format(ip, f.get("confidence")))

    # state (event_id based, informational — dedup is via ticket store)
    buf = _read_json(EVENT_BUF_PATH, {"events": []})
    last_eid = buf["events"][-1]["event_id"] if buf.get("events") else None
    _write_json(STATE_PATH, {
        "last_event_id": last_eid,
        "last_run": now_iso(),
        "open_ip_set": sorted(matched_ips),
    })
    return opened, updated, len(llm_findings)


def run_loop():
    print("[INV] Investigator V2 | cycle={}s | stage2={}".format(CYCLE_SECS, STAGE2_ENABLED))
    while True:
        try:
            o, u, l = run_cycle()
            print("[INV] cycle done — opened={} updated={} llm_findings={}".format(o, u, l))
        except Exception as e:
            print("[INV] cycle error: {}: {}".format(type(e).__name__, e))
        time.sleep(CYCLE_SECS)


if __name__ == "__main__":
    import sys
    if "--once" in sys.argv:
        o, u, l = run_cycle()
        print("[INV] single cycle — opened={} updated={} llm_findings={}".format(o, u, l))
    else:
        run_loop()
