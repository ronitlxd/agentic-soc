#!/usr/bin/env python3
"""
AUDITOR — Case file writer.
Fetches ticket, builds structured case file with MITRE ATT&CK mapping,
timeline, IOCs, and recommendations. Closes ticket after writing.
Makes no decisions — records everything for forensic review.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

TICKET_CLI = os.path.expanduser("~/.hermes/skills/soc/ticket-manager/ticket_cli.py")
CASES_DIR  = os.path.expanduser("~/.hermes/soc/cases")

# MITRE ATT&CK mappings — rule → list of techniques
MITRE_MAP = {
    "R1_RECON_TO_EXPLOIT": [
        {"id": "T1595",     "name": "Active Scanning",            "tactic": "Reconnaissance"},
        {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "Initial Access"},
    ],
    "R2_BRUTE_FORCE_SUCCESS": [
        {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
        {"id": "T1078",     "name": "Valid Accounts",                  "tactic": "Initial Access"},
    ],
    "R3_LOGIN_TO_C2": [
        {"id": "T1078",     "name": "Valid Accounts",       "tactic": "Initial Access"},
        {"id": "T1071",     "name": "Standard App Protocol","tactic": "Command and Control"},
    ],
    "R4_LATERAL_MOVEMENT": [
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
        {"id": "T1595",     "name": "Active Scanning",      "tactic": "Reconnaissance"},
    ],
    "R5_EXFILTRATION": [
        {"id": "T1078",     "name": "Valid Accounts",                 "tactic": "Initial Access"},
        {"id": "T1048",     "name": "Exfiltration Over Alt Protocol", "tactic": "Exfiltration"},
    ],
    "R6_OFFHOURS": [
        {"id": "T1078",     "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    "R7_LOG_TAMPER": [
        {"id": "T1070",     "name": "Indicator Removal on Host",      "tactic": "Defense Evasion"},
        {"id": "T1070.002", "name": "Clear Linux/Mac System Logs",    "tactic": "Defense Evasion"},
    ],
}

RECOMMENDATIONS = {
    "R1_RECON_TO_EXPLOIT": [
        "Verify patch level on all exposed services.",
        "Review WAF rules — consider geo-blocking the source country.",
        "Enable Suricata IPS mode (currently IDS) if false positive rate is acceptable.",
    ],
    "R2_BRUTE_FORCE_SUCCESS": [
        "Immediately rotate credentials for the affected account.",
        "Audit all actions taken under that account since first successful login.",
        "Enforce MFA on SSH and all remote access services.",
        "Consider fail2ban or ufw rate-limiting on port 22.",
    ],
    "R3_LOGIN_TO_C2": [
        "Preserve session for forensic analysis before terminating.",
        "Review authorized_keys and ~/.bashrc / ~/.profile for persistence.",
        "Check crontabs (crontab -l and /etc/cron*) for new entries.",
        "Rotate all secrets and API keys accessible from the server.",
    ],
    "R4_LATERAL_MOVEMENT": [
        "Isolate the source host immediately.",
        "Audit internal firewall rules — segment internal network.",
        "Review shared credentials across internal services.",
    ],
    "R5_EXFILTRATION": [
        "Identify what data was accessible from the logged-in account.",
        "Notify data protection officer if PII or regulated data may be involved.",
        "Block destination IPs at border firewall.",
        "Preserve all logs — may be required for breach notification.",
    ],
    "R6_OFFHOURS": [
        "Verify with authorized users whether activity was expected.",
        "Consider time-based access controls for sensitive services.",
        "Cross-check against VPN/Tailscale logs to confirm operator access.",
    ],
    "R7_LOG_TAMPER": [
        "Log tampering is a critical indicator of attacker presence.",
        "Ship logs to remote syslog immediately if not already configured.",
        "Forensically image the affected system before making changes.",
        "Initiate full incident response — assume system is compromised.",
    ],
}


# ── helpers ───────────────────────────────────────────────────────────────────

def now():
    return datetime.now(timezone.utc).isoformat()


def ts_str():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def get_ticket(ticket_id):
    r = subprocess.run(
        [sys.executable, TICKET_CLI, "get", "--id", ticket_id],
        capture_output=True, text=True,
    )
    try:
        return json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None


def close_ticket(ticket_id):
    subprocess.run(
        [sys.executable, TICKET_CLI, "close",
         "--id", ticket_id,
         "--agent", "auditor",
         "--note", "Case file written. Ticket closed by auditor."],
        capture_output=True, text=True,
    )


def append_finding(ticket_id, note):
    subprocess.run(
        [sys.executable, TICKET_CLI, "append",
         "--id", ticket_id, "--agent", "auditor", "--note", note[:500]],
        capture_output=True, text=True,
    )


def extract_iocs(ticket):
    """Pull all IPs and indicators from ticket findings."""
    iocs = set()
    src  = ticket.get("src_ip")
    if src and src != "local":
        iocs.add(src)
    for finding in ticket.get("findings", []):
        note = finding.get("note", "")
        # Extract IPs mentioned in findings
        import re
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", note)
        for ip in ips:
            if not ip.startswith(("10.", "192.168.", "127.", "172.")):
                iocs.add(ip)
    return sorted(iocs)


def extract_rule(ticket):
    """Extract the triggering rule from ticket findings."""
    for finding in ticket.get("findings", []):
        note = finding.get("note", "")
        if "Rule: R" in note:
            import re
            m = re.search(r"Rule: (R\d+_\w+)", note)
            if m:
                return m.group(1)
    return None


def build_timeline(ticket):
    """Build chronological event list from findings."""
    lines = []
    for finding in ticket.get("findings", []):
        agent = finding.get("agent", "?")
        ts    = finding.get("timestamp", "")[:19]
        note  = finding.get("note", "")
        lines.append("{} [{}] {}".format(ts, agent.upper(), note))
    return lines


# ── case file builder ─────────────────────────────────────────────────────────

def write_case(ticket_id, match_info=None):
    """
    Build a forensic case file for ticket_id.
    match_info: optional dict from investigator with rule/severity/events.
    Returns path to case file or None on failure.
    """
    os.makedirs(CASES_DIR, exist_ok=True)

    ticket = get_ticket(ticket_id)
    if not ticket:
        return None

    rule  = (match_info or {}).get("rule") or extract_rule(ticket)
    iocs  = extract_iocs(ticket)
    mitre = MITRE_MAP.get(rule, [])
    recs  = RECOMMENDATIONS.get(rule, ["Review ticket findings manually."])
    timeline = build_timeline(ticket)

    case_path = os.path.join(CASES_DIR, "{}_{}.txt".format(ticket_id, ts_str()))

    with open(case_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("SOC CASE FILE\n")
        f.write("=" * 70 + "\n")
        f.write("Ticket:    {}\n".format(ticket_id))
        f.write("Generated: {}\n".format(now()))
        f.write("Rule:      {}\n".format(rule or "unknown"))
        f.write("Severity:  {}\n".format(ticket.get("severity", "?").upper()))
        f.write("Source:    {}\n".format(ticket.get("source", "?")))
        f.write("Title:     {}\n\n".format(ticket.get("title", "")))

        # IOCs
        f.write("─" * 70 + "\n")
        f.write("INDICATORS OF COMPROMISE\n")
        f.write("─" * 70 + "\n")
        if iocs:
            for ip in iocs:
                f.write("  IP: {}\n".format(ip))
        else:
            f.write("  (none extracted)\n")
        f.write("\n")

        # MITRE ATT&CK
        f.write("─" * 70 + "\n")
        f.write("MITRE ATT&CK\n")
        f.write("─" * 70 + "\n")
        if mitre:
            for t in mitre:
                f.write("  {} — {} [{}]\n".format(t["id"], t["name"], t["tactic"]))
        else:
            f.write("  (no mapping — review manually)\n")
        f.write("\n")

        # Timeline
        f.write("─" * 70 + "\n")
        f.write("TIMELINE\n")
        f.write("─" * 70 + "\n")
        if timeline:
            for entry in timeline:
                f.write("  {}\n".format(entry))
        else:
            f.write("  (no findings)\n")
        f.write("\n")

        # Recommendations
        f.write("─" * 70 + "\n")
        f.write("RECOMMENDATIONS\n")
        f.write("─" * 70 + "\n")
        for i, rec in enumerate(recs, 1):
            f.write("  {}. {}\n".format(i, rec))
        f.write("\n")

        # Disposition
        disposition = ticket.get("disposition", "pending")
        f.write("─" * 70 + "\n")
        f.write("DISPOSITION: {}\n".format(disposition.upper()))
        f.write("=" * 70 + "\n")

    append_finding(ticket_id, "Case file written: {}".format(case_path))
    close_ticket(ticket_id)

    return case_path


# ── entry point ───────────────────────────────────────────────────────────────

def audit(ticket_id, match_info=None):
    """
    Main entry point called by orchestrator.
    Returns case file path or None.
    """
    return write_case(ticket_id, match_info)
