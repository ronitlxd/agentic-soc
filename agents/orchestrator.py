#!/usr/bin/env python3
"""
ORCHESTRATOR — Main coordinator. Vega persona.
Starts Triage, polls Investigator every 5 min,
calls Intel + Responder + Auditor per incident,
sends Telegram briefs, polls operator_response.json.
Inbound Telegram handled by Hermes — no polling conflict.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# ── agent imports ─────────────────────────────────────────────────────────────
AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AGENTS_DIR)

import triage
import investigator
import intel
import responder
import auditor

# ── config ────────────────────────────────────────────────────────────────────
ENV_FILE          = os.path.expanduser("~/.hermes/.env")
RESPONSE_FILE     = os.path.expanduser("~/.hermes/soc/operator_response.json")
INVESTIGATOR_INTERVAL = 300   # seconds between Investigator cycles
RESPONSE_POLL_INTERVAL = 15   # seconds between operator response polls
STALE_ALERT_INTERVAL   = 1800  # re-alert on stale triage every 30 min

# Pending incidents waiting for operator choice
# { ticket_id: { "incident": {...}, "sent_at": timestamp, "option_sent": bool } }
_pending = {}
_last_stale_alert = 0


# ── env ────────────────────────────────────────────────────────────────────────

def load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


# ── telegram (outbound only) ──────────────────────────────────────────────────

_telegram_token = None
_telegram_chat  = None


def telegram_init():
    global _telegram_token, _telegram_chat
    env = load_env()
    _telegram_token = env.get("TELEGRAM_BOT_TOKEN")
    _telegram_chat  = env.get("TELEGRAM_CHAT_ID")


def send_telegram(text):
    if not _telegram_token or not _telegram_chat:
        print("[ORCH] Telegram not configured — message would be:", text[:100])
        return
    try:
        url     = "https://api.telegram.org/bot{}/sendMessage".format(_telegram_token)
        payload = json.dumps({
            "chat_id":    _telegram_chat,
            "text":       text[:4000],
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print("[ORCH] Telegram send failed: {}".format(e))


# ── briefs ────────────────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

OPTIONS_TEXT = (
    "\n\n*Select response:*\n"
    "1️⃣  Full containment — block IP, kill sessions, block outbound C2\n"
    "2️⃣  Soft containment — block IP, preserve sessions for forensics\n"
    "3️⃣  Observe only — snapshot evidence, no action\n"
    "4️⃣  False positive — close case\n\n"
    "_Reply with the case ID and option, e.g.:_ `CASE-001 2`"
)


def build_brief(ticket_id, match_info, intel_summaries):
    rule     = match_info.get("rule", "?")
    severity = match_info.get("severity", "medium")
    title    = match_info.get("title", "")
    src_ip   = match_info.get("src_ip", "?")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    intel_block = ""
    if intel_summaries:
        intel_block = "\n\n*Intel:*\n" + "\n".join("• " + s for s in intel_summaries[:5])

    return (
        "{emoji} *{sev}* | {rule}\n"
        "*Case:* `{tid}`\n"
        "*IP:* `{ip}`\n"
        "*Summary:* {title}"
        "{intel}"
        "{options}"
    ).format(
        emoji   = emoji,
        sev     = severity.upper(),
        rule    = rule,
        tid     = ticket_id,
        ip      = src_ip,
        title   = title,
        intel   = intel_block,
        options = OPTIONS_TEXT,
    )


def send_stale_alert():
    send_telegram(
        "⚠️ *TRIAGE STALE*\n"
        "No new log entries in the last 10 minutes.\n"
        "Check if the `soc-orchestrator` service is running and log sources are reachable."
    )


# ── operator response ──────────────────────────────────────────────────────────

def read_response():
    """
    Hermes/Vega writes operator choice here after parsing Telegram message.
    Format: { "ticket_id": "CASE-001", "option": 2, "timestamp": "..." }
    Returns dict or None if no new response.
    """
    if not os.path.exists(RESPONSE_FILE):
        return None
    try:
        with open(RESPONSE_FILE) as f:
            data = json.load(f)
        # Only consume once
        os.remove(RESPONSE_FILE)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def handle_response(resp):
    ticket_id = resp.get("ticket_id")
    option    = resp.get("option")

    if not ticket_id or option is None:
        print("[ORCH] Malformed response: {}".format(resp))
        return

    pending = _pending.get(ticket_id)
    if not pending:
        send_telegram(
            "⚠️ Response received for `{}` but no pending incident found.".format(ticket_id)
        )
        return

    match_info = pending["incident"]
    src_ip     = match_info.get("src_ip", "")
    extra_ips  = pending.get("extra_ips", [])

    send_telegram(
        "🔧 Executing option {} for `{}`…".format(option, ticket_id)
    )

    result = responder.execute(ticket_id, option, src_ip, extra_ips)
    case_path = auditor.audit(ticket_id, match_info)

    msg = (
        "✅ *Response complete* — `{tid}`\n"
        "{result}\n"
        "Case file: `{case}`"
    ).format(
        tid    = ticket_id,
        result = result,
        case   = case_path or "not written",
    )
    send_telegram(msg)

    del _pending[ticket_id]


# ── investigation cycle ────────────────────────────────────────────────────────

def run_investigation():
    global _last_stale_alert

    results, is_stale = investigator.run_cycle()

    if is_stale:
        now_ts = datetime.now(timezone.utc).timestamp()
        if now_ts - _last_stale_alert > STALE_ALERT_INTERVAL:
            send_stale_alert()
            _last_stale_alert = now_ts

    for ticket_id, ioc_list, match_info in results:
        # Skip if already waiting on this ticket
        if ticket_id in _pending:
            continue

        # Enrich IOCs
        intel_summaries = intel.enrich(ticket_id, ioc_list)

        # Extract any C2 IPs from intel (for option 1 outbound blocking)
        extra_ips = [s.split(":")[0].strip() for s in intel_summaries
                     if "KNOWN-C2" in s]

        # Send brief with options to operator
        brief = build_brief(ticket_id, match_info, intel_summaries)
        send_telegram(brief)

        _pending[ticket_id] = {
            "incident":  match_info,
            "extra_ips": extra_ips,
            "sent_at":   datetime.now(timezone.utc).timestamp(),
        }

        print("[ORCH] Incident queued: {} ({})".format(
            ticket_id, match_info.get("rule")))


# ── main loop ─────────────────────────────────────────────────────────────────

def main():
    print("[ORCH] Starting SOC Orchestrator")
    telegram_init()
    send_telegram("🟢 *Vega SOC online.*\nAll agents starting…")

    # Start Triage (returns daemon threads — kept alive by the main loop)
    triage_threads = triage.run()
    print("[ORCH] Triage started — {} watchers".format(len(triage_threads)))

    send_telegram("📡 Triage monitoring {} log sources.".format(
        len(triage_threads)))

    next_investigation = time.time()

    while True:
        now = time.time()

        # Run Investigator on schedule
        if now >= next_investigation:
            try:
                run_investigation()
            except Exception as e:
                print("[ORCH] Investigation error: {}".format(e))
            next_investigation = now + INVESTIGATOR_INTERVAL

        # Poll for operator response
        try:
            resp = read_response()
            if resp:
                handle_response(resp)
        except Exception as e:
            print("[ORCH] Response handler error: {}".format(e))

        time.sleep(RESPONSE_POLL_INTERVAL)


if __name__ == "__main__":
    main()
