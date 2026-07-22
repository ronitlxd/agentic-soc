#!/usr/bin/env python3
"""
INVESTIGATOR — Correlation rules engine.
Reads findings buffer every 5 min, builds IP index,
runs 7 rules, creates tickets on matches. No LLM. Pure Python.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

BUFFER_PATH  = os.path.expanduser("~/.hermes/soc/findings_buffer.json")
TICKET_CLI   = os.path.expanduser("~/.hermes/skills/soc/ticket-manager/ticket_cli.py")
STATE_PATH   = os.path.expanduser("~/.hermes/soc/investigator_state.json")
CYCLE_WINDOW = 1800   # 30 min lookback
STALE_LIMIT  = 600    # 10 min without new entries = stale

INTERNAL_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("127.0.0.0/8"),
]

# IPs of the server itself — used to identify outbound flows.
# Set via env: SOC_SERVER_IPS="10.0.0.10,192.168.1.20,100.x.x.x"
SERVER_IPS = {
    ip.strip()
    for ip in os.environ.get(
        "SOC_SERVER_IPS",
        "10.0.0.10,192.168.1.20"  # placeholder — override in .env
    ).split(",")
    if ip.strip()
}


# ── helpers ───────────────────────────────────────────────────────────────────

def is_internal(ip_str):
    try:
        ip = ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETS)
    except ValueError:
        return False


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ts(entry):
    try:
        return datetime.fromisoformat(entry["timestamp"]).timestamp()
    except (KeyError, ValueError):
        return 0


def load_buffer():
    try:
        with open(BUFFER_PATH) as f:
            return json.load(f).get("entries", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_processed": 0}


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)


def create_ticket(source, severity, title):
    r = subprocess.run(
        [sys.executable, TICKET_CLI, "create",
         "--source", source, "--severity", severity, "--title", title[:120]],
        capture_output=True, text=True,
    )
    out   = r.stdout.strip()
    parts = out.split()
    return parts[1] if len(parts) >= 2 and parts[0] == "CREATED" else None


def append_finding(ticket_id, note):
    subprocess.run(
        [sys.executable, TICKET_CLI, "append",
         "--id", ticket_id, "--agent", "investigator", "--note", note[:500]],
        capture_output=True, text=True,
    )


def fmt_events(events):
    lines = []
    for e in events[:5]:
        lines.append("{} | {} | {} | {}".format(
            e.get("timestamp", "")[:19],
            e.get("source", ""),
            e.get("event_type", ""),
            e.get("src_ip", ""),
        ))
    return " || ".join(lines)


# ── correlation rules ─────────────────────────────────────────────────────────

def rule1_recon_to_exploit(by_ip):
    """Port scan → exploit / auth attempt from same IP within 10 min. (T1595 → T1190)"""
    matches = []
    for ip, entries in by_ip.items():
        if is_internal(ip):
            continue
        scans = [e for e in entries
                 if e.get("event_type") == "alert"
                 and "SCAN" in e.get("signature", "").upper()]
        threats = [e for e in entries
                   if e.get("event_type") in ("auth_fail", "break_in")
                   or (e.get("event_type") == "alert"
                       and "EXPLOIT" in e.get("signature", "").upper())]
        for scan in scans:
            for threat in threats:
                diff = ts(threat) - ts(scan)
                if 0 < diff < 600:
                    matches.append({
                        "rule":       "R1_RECON_TO_EXPLOIT",
                        "severity":   "high",
                        "src_ip":     ip,
                        "title":      "Recon to exploit chain from {}".format(ip),
                        "events":     [scan, threat],
                        "confidence": "HIGH",
                    })
                    break
    return matches


def rule2_brute_force_success(by_ip):
    """5+ failed logins → success from same IP. (T1110.001, T1078)"""
    matches = []
    for ip, entries in by_ip.items():
        fails     = [e for e in entries if e.get("event_type") == "auth_fail"]
        successes = [e for e in entries if e.get("event_type") == "auth_success"]
        if len(fails) >= 5 and successes:
            first_fail = min(ts(e) for e in fails)
            for success in successes:
                if ts(success) > first_fail:
                    matches.append({
                        "rule":       "R2_BRUTE_FORCE_SUCCESS",
                        "severity":   "critical",
                        "src_ip":     ip,
                        "title":      "Brute force success — {} fails then login from {}".format(
                            len(fails), ip),
                        "events":     fails[-3:] + [success],
                        "confidence": "HIGH",
                    })
                    break
    return matches


def rule3_login_to_c2(by_ip, all_entries):
    """Login success → outbound connection within 2 min. Degrades without flow data. (T1078, T1071)"""
    flows = [e for e in all_entries if e.get("event_type") == "flow"]
    if not flows:
        return []  # graceful degradation — no flow data available

    matches = []
    for ip, entries in by_ip.items():
        if is_internal(ip):
            continue
        for success in [e for e in entries if e.get("event_type") == "auth_success"]:
            success_ts = ts(success)
            outbound = [
                f for f in flows
                if success_ts < ts(f) < success_ts + 120
                and f.get("src_ip") in SERVER_IPS
                and not is_internal(f.get("dst_ip", ""))
            ]
            if outbound:
                matches.append({
                    "rule":       "R3_LOGIN_TO_C2",
                    "severity":   "critical",
                    "src_ip":     ip,
                    "title":      "Login then outbound C2 connection from {}".format(ip),
                    "events":     [success] + outbound[:2],
                    "confidence": "HIGH",
                })
    return matches


def rule4_internal_lateral(by_ip):
    """Internal host scanning 5+ other internal hosts. (T1021.004, T1595)"""
    matches = []
    for ip, entries in by_ip.items():
        if not is_internal(ip) or ip in SERVER_IPS:
            continue
        scan_events = [
            e for e in entries
            if (e.get("event_type") == "alert" and "SCAN" in e.get("signature", "").upper())
            or e.get("event_type") == "firewall_block"
        ]
        targets = {e.get("dst_ip") for e in scan_events if e.get("dst_ip") and is_internal(e.get("dst_ip", ""))}
        if len(targets) >= 5:
            matches.append({
                "rule":       "R4_LATERAL_MOVEMENT",
                "severity":   "critical",
                "src_ip":     ip,
                "title":      "Lateral movement — {} scanning {} internal hosts".format(ip, len(targets)),
                "events":     scan_events[:5],
                "confidence": "HIGH",
            })
    return matches


def rule5_exfiltration(by_ip, all_entries):
    """Large outbound transfer (>50MB) after login from new IP. Degrades without flow data. (T1048)"""
    flows = [e for e in all_entries if e.get("event_type") == "flow"]
    if not flows:
        return []  # graceful degradation — no flow data available

    # "new IP" = not seen in entries older than 6 hours
    cutoff     = now_ts() - 21600
    seen_ips   = {e.get("src_ip") for e in all_entries if ts(e) < cutoff}
    matches    = []

    for ip, entries in by_ip.items():
        if is_internal(ip) or ip in seen_ips:
            continue
        for success in [e for e in entries if e.get("event_type") == "auth_success"]:
            success_ts = ts(success)
            out_bytes  = sum(
                f.get("bytes_toserver", 0)
                for f in flows
                if success_ts < ts(f) < success_ts + 600
                and not is_internal(f.get("dst_ip", ""))
            )
            if out_bytes > 50 * 1024 * 1024:
                matches.append({
                    "rule":       "R5_EXFILTRATION",
                    "severity":   "critical",
                    "src_ip":     ip,
                    "title":      "Possible exfiltration — {:.1f}MB outbound after login from new IP {}".format(
                        out_bytes / 1024 / 1024, ip),
                    "events":     [success],
                    "confidence": "HIGH",
                })
    return matches


def rule6_offhours(by_ip):
    """External IP activity between 2am–5am UTC. (T1078)"""
    off_hours = set(range(2, 5))
    matches   = []
    for ip, entries in by_ip.items():
        if is_internal(ip):
            continue
        night_events = [
            e for e in entries
            if datetime.fromisoformat(e["timestamp"]).hour in off_hours
        ]
        if night_events:
            matches.append({
                "rule":       "R6_OFFHOURS",
                "severity":   "high",
                "src_ip":     ip,
                "title":      "Off-hours activity (02:00-05:00 UTC) from {}".format(ip),
                "events":     night_events[:3],
                "confidence": "MEDIUM",
            })
    return matches


def rule7_log_tamper(all_entries):
    """Log file shrinkage detected by Triage. (T1070, T1070.002)"""
    return [
        {
            "rule":       "R7_LOG_TAMPER",
            "severity":   "critical",
            "src_ip":     "local",
            "title":      "Log tampering — {} shrunk".format(e.get("path", "unknown")),
            "events":     [e],
            "confidence": "HIGH",
        }
        for e in all_entries if e.get("event_type") == "log_shrink"
    ]


# ── main cycle ────────────────────────────────────────────────────────────────

SOURCE_MAP = {
    "R1_RECON_TO_EXPLOIT":  "suricata",
    "R2_BRUTE_FORCE_SUCCESS": "wazuh",
    "R3_LOGIN_TO_C2":       "suricata",
    "R4_LATERAL_MOVEMENT":  "suricata",
    "R5_EXFILTRATION":      "suricata",
    "R6_OFFHOURS":          "wazuh",
    "R7_LOG_TAMPER":        "manual",
}


def run_cycle():
    """
    Run one investigation cycle.
    Returns: (results, is_stale)
      results = list of (ticket_id, ioc_list, match_info)
      is_stale = True if buffer has not been updated recently
    """
    state       = load_state()
    all_entries = load_buffer()

    if not all_entries:
        return [], False

    latest_ts = max(ts(e) for e in all_entries)
    is_stale  = (now_ts() - latest_ts) > STALE_LIMIT

    # Only process entries newer than last run and within the 30-min window
    cutoff         = now_ts() - CYCLE_WINDOW
    window_entries = [
        e for e in all_entries
        if ts(e) > max(cutoff, state["last_processed"])
    ]

    if not window_entries:
        save_state({"last_processed": now_ts()})
        return [], is_stale

    # Build index by src_ip
    by_ip = {}
    for e in window_entries:
        ip = e.get("src_ip", "unknown")
        by_ip.setdefault(ip, []).append(e)

    # Run all 7 rules
    all_matches = (
        rule1_recon_to_exploit(by_ip)
        + rule2_brute_force_success(by_ip)
        + rule3_login_to_c2(by_ip, window_entries)
        + rule4_internal_lateral(by_ip)
        + rule5_exfiltration(by_ip, all_entries)
        + rule6_offhours(by_ip)
        + rule7_log_tamper(window_entries)
    )

    # One ticket per (rule, src_ip) per cycle
    seen    = set()
    results = []

    for match in all_matches:
        key = (match["rule"], match["src_ip"])
        if key in seen:
            continue
        seen.add(key)

        source = SOURCE_MAP.get(match["rule"], "manual")
        tid    = create_ticket(source, match["severity"], match["title"])
        if not tid:
            continue

        append_finding(tid,
            "Rule: {} | Confidence: {} | IP: {} | Events: {}".format(
                match["rule"], match["confidence"], match["src_ip"],
                fmt_events(match["events"])))

        # Collect IOCs for Intel
        iocs = [match["src_ip"]]
        for e in match["events"]:
            dst = e.get("dst_ip", "")
            if dst and not is_internal(dst) and dst not in iocs:
                iocs.append(dst)

        results.append((tid, iocs, match))

    save_state({"last_processed": now_ts()})
    return results, is_stale
