#!/usr/bin/env python3
"""
ORCHESTRATOR — SOC V2  (the conductor)
======================================

ROLE
    The single process that runs the whole pipeline. Starts Triage, schedules the
    Investigator and Intel cycles, generates operator briefs, pushes a read-only
    Telegram notification (plain text + URL), and polls operator_response.json to
    dispatch the Responder and Auditor.

    In V2, operator DECISIONS happen in the web interface (soc_web.py), not over
    Telegram. Telegram is push-only. This removes the V1 LLM-parsing bug entirely.

INPUTS
    ip_stats.json / tickets/*.json  (via the imported agents)
    operator_response.json          (written by the web interface)

OUTPUTS
    Telegram notifications; dispatches Responder + Auditor; updates tickets.

LLM
    Local qwen3-4b (LM Studio) writes ONE narrative sentence per brief. If the
    model is down, a deterministic template sentence is used — a brief always sends.

SEVERITY ROUTING
    critical -> brief immediately
    high/med -> brief after Intel enrichment
    low      -> 30-minute digest, not per-ticket
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.expanduser("~/.hermes/soc/.env"))
except Exception:
    pass

try:
    import requests
except Exception:
    requests = None

BASE_DIR = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
sys.path.insert(0, BASE_DIR)

import triage_agent
import investigator_agent
import intel_agent

TICKETS_DIR   = os.path.join(BASE_DIR, "tickets")
RESPONSE_PATH = os.path.join(BASE_DIR, "operator_response_v2.json")   # V2-only (avoids V1 collision)

TG_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT    = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
TS_IP      = os.environ.get("SERVER_TAILSCALE_IP", "100.64.0.1")
WEB_PORT   = int(os.environ.get("SOC_WEB_PORT", "5005"))
LM_URL     = os.environ.get("LM_STUDIO_BASE_URL", "http://127.0.0.1:1234/v1")
LM_MODEL   = os.environ.get("LM_STUDIO_MODEL", "qwen/qwen3-4b-2507")

DETECT_SECS   = int(os.environ.get("INVESTIGATOR_CYCLE_SECS", "75"))
POLL_SECS     = 10
# LLM narrative is OFF by default until LM Studio stability is proven (per requirements
# doc). With it off, briefs use the instant deterministic sentence — no blocking.
LLM_NARRATIVE = os.environ.get("ORCH_LLM_NARRATIVE", "false").lower() == "true"
REMIND_AFTER  = 15 * 60    # resend URL after 15 min of no response
DEFAULT_AFTER = 30 * 60    # after 30 min, default to Monitor (never auto-contain)
DIGEST_SECS   = 30 * 60

SEV_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F7E2"}

# in-memory state for this run
_briefed   = {}     # ticket_id -> {"at": ts, "reminded": bool}
_low_queue = []     # ticket_ids awaiting the low-severity digest
_last_digest = time.time()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


# ── telegram (push-only) ──────────────────────────────────────────────────────

def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT and requests):
        print("[ORCH] (telegram not configured) would send:\n" + text + "\n")
        return
    try:
        requests.post("https://api.telegram.org/bot{}/sendMessage".format(TG_TOKEN),
                      json={"chat_id": TG_CHAT, "text": text[:4000],
                            "disable_web_page_preview": True}, timeout=10)
    except Exception as e:
        print("[ORCH] telegram send failed: {}".format(e))


# ── LLM one-sentence narrative (graceful fallback) ────────────────────────────

def narrative(ticket):
    ev = ticket.get("evidence", {})
    isum = ticket.get("intel_summary", {})
    fallback = "{} from {} — {} ({})".format(
        ticket.get("rule"), ticket.get("source_ip"),
        ticket.get("mitre_technique"), ticket.get("mitre_tactic"))
    if not (LLM_NARRATIVE and requests):
        return fallback
    prompt = ("Write ONE plain-English sentence (max 20 words) summarizing this "
              "security incident for a SOC operator. No preamble, just the sentence.\n"
              + json.dumps({"rule": ticket.get("rule"), "ip": ticket.get("source_ip"),
                            "technique": ticket.get("mitre_technique"),
                            "evidence": ev, "reputation": isum.get("ip_reputation"),
                            "groups": isum.get("associated_groups")}))
    try:
        r = requests.post(LM_URL.rstrip("/") + "/chat/completions",
                          json={"model": LM_MODEL, "messages": [{"role": "user", "content": prompt}],
                                "temperature": 0.2, "max_tokens": 60}, timeout=25)
        s = r.json()["choices"][0]["message"]["content"].strip().strip('"')
        return s.split("\n")[0][:200] or fallback
    except Exception:
        return fallback


# ── brief generation ──────────────────────────────────────────────────────────

def build_brief(ticket):
    sev = (ticket.get("severity") or "medium").lower()
    isum = ticket.get("intel_summary", {})
    ev = ticket.get("evidence", {})
    tid = ticket.get("ticket_id")

    line_ctx = []
    if isum.get("geolocation") or isum.get("org"):
        line_ctx.append("{} / {}".format(isum.get("geolocation") or "?", isum.get("org") or "?"))
    if isum.get("reputation_score") is not None:
        line_ctx.append("AbuseIPDB {}/100".format(isum["reputation_score"]))
    if isum.get("feed_hits"):
        line_ctx.append("feeds: " + ", ".join(isum["feed_hits"]))
    if isum.get("associated_groups"):
        line_ctx.append("groups: " + ", ".join(isum["associated_groups"][:3]))
    ctx = "\n".join(line_ctx)

    url = "http://{}:{}/brief/{}".format(TS_IP, WEB_PORT, tid)
    return (
        "{emoji} {tid} | {sev} | {rule} {tech}\n\n"
        "{narr}\n"
        "{ip} ({iptype})\n"
        "{ctx}\n\n"
        "→ {url}"
    ).format(
        emoji=SEV_EMOJI.get(sev, ""), tid=tid, sev=sev.upper(),
        rule=ticket.get("rule"), tech=ticket.get("mitre_technique") or "",
        narr=narrative(ticket), ip=ticket.get("source_ip"),
        iptype=ticket.get("ip_type"), ctx=ctx, url=url)


# ── ticket helpers ────────────────────────────────────────────────────────────

def open_tickets():
    out = []
    if not os.path.isdir(TICKETS_DIR):
        return out
    for fn in os.listdir(TICKETS_DIR):
        if fn.endswith(".json"):
            t = _read_json(os.path.join(TICKETS_DIR, fn), None)
            if t and t.get("status") == "open":
                out.append(t)
    return out


def mark_briefed(ticket):
    p = os.path.join(TICKETS_DIR, ticket["ticket_id"] + ".json")
    ticket["briefed"] = True
    ticket["briefed_at"] = now_iso()
    _write_json(p, ticket)
    _briefed[ticket["ticket_id"]] = {"at": time.time(), "reminded": False}


def brief_new_tickets():
    global _last_digest
    # dedup: don't brief a second open ticket for an IP already awaiting response
    awaiting_ips = {t["source_ip"] for t in open_tickets()
                    if t.get("briefed") and t["ticket_id"] in _briefed}

    for t in sorted(open_tickets(),
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    .get((x.get("severity") or "").lower(), 9)):
        if t.get("briefed"):
            continue
        sev = (t.get("severity") or "medium").lower()

        # high/medium require Intel enrichment first; critical briefs immediately
        if sev != "critical" and t.get("intel_summary") is None:
            continue
        if sev != "critical" and t.get("source_ip") in awaiting_ips:
            continue

        if sev == "low":
            _low_queue.append(t["ticket_id"])
            mark_briefed(t)
            continue

        send_telegram(build_brief(t))
        mark_briefed(t)
        print("[ORCH] briefed {} ({})".format(t["ticket_id"], sev))

    # low-severity digest every 30 min
    if _low_queue and (time.time() - _last_digest) > DIGEST_SECS:
        send_telegram("\U0001F7E2 Low-severity digest: {} item(s)\n".format(len(_low_queue))
                      + "\n".join("→ http://{}:{}/brief/{}".format(TS_IP, WEB_PORT, x)
                                  for x in _low_queue))
        _low_queue.clear()
        _last_digest = time.time()


# ── response handling + dispatch ──────────────────────────────────────────────

def dispatch(ticket_id, option):
    """Hand an approved option to the Responder, then the Auditor.
    Responder/Auditor arrive in Phases 7/8 — import lazily and degrade gracefully."""
    p = os.path.join(TICKETS_DIR, ticket_id + ".json")
    ticket = _read_json(p, None)
    if not ticket:
        print("[ORCH] dispatch: unknown ticket {}".format(ticket_id))
        return
    print("[ORCH] operator chose option {} for {}".format(option, ticket_id))

    result = None
    try:
        import responder_agent
        result = responder_agent.execute(ticket_id, option)
        print("[ORCH] responder: {}".format(result))
    except ImportError:
        print("[ORCH] responder_agent not installed yet (Phase 7) — decision logged only")
        ticket.setdefault("findings", []).append({
            "agent": "orchestrator", "timestamp": now_iso(),
            "note": "operator option {} recorded; responder pending (Phase 7)".format(option)})
        _write_json(p, ticket)
    except Exception as e:
        print("[ORCH] responder error: {}: {}".format(type(e).__name__, e))

    try:
        import auditor_agent
        auditor_agent.audit(ticket_id)
    except ImportError:
        pass
    except Exception as e:
        print("[ORCH] auditor error: {}: {}".format(type(e).__name__, e))

    _briefed.pop(ticket_id, None)


def poll_response():
    if not os.path.exists(RESPONSE_PATH):
        return
    data = _read_json(RESPONSE_PATH, None)
    try:
        os.remove(RESPONSE_PATH)
    except OSError:
        pass
    if data and data.get("ticket_id") and data.get("option") in (1, 2, 3, 4):
        dispatch(data["ticket_id"], data["option"])


def check_timeouts():
    now = time.time()
    for tid, st in list(_briefed.items()):
        age = now - st["at"]
        if age > DEFAULT_AFTER:
            print("[ORCH] {} no response in 30m — defaulting to Monitor".format(tid))
            _write_json(RESPONSE_PATH, {"ticket_id": tid, "option": 1,
                        "received_at": now_iso(), "source": "timeout_default"})
            _briefed.pop(tid, None)
        elif age > REMIND_AFTER and not st["reminded"]:
            t = _read_json(os.path.join(TICKETS_DIR, tid + ".json"), {})
            send_telegram("⏰ Reminder — {} still needs a decision\n→ http://{}:{}/brief/{}"
                          .format(tid, TS_IP, WEB_PORT, tid))
            st["reminded"] = True


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("[ORCH] SOC V2 Orchestrator starting")
    triage_agent.run()
    print("[ORCH] Triage started")
    send_telegram("\U0001F7E2 SOC V2 online. Agents running.")

    next_detect = time.time()
    while True:
        now = time.time()

        # Operator decisions are handled FIRST every loop — never blocked by detect/brief.
        try:
            poll_response()
            check_timeouts()
        except Exception as e:
            print("[ORCH] response loop error: {}: {}".format(type(e).__name__, e))

        if now >= next_detect:
            try:
                o, u, l = investigator_agent.run_cycle()
                n = intel_agent.run_cycle()
                if o or n:
                    print("[ORCH] detect: opened={} updated={} enriched={}".format(o, u, n))
            except Exception as e:
                print("[ORCH] detect error: {}: {}".format(type(e).__name__, e))
            next_detect = now + DETECT_SECS

        try:
            brief_new_tickets()
        except Exception as e:
            print("[ORCH] brief loop error: {}: {}".format(type(e).__name__, e))

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
