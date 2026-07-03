#!/usr/bin/env python3
"""
AUDITOR AGENT — SOC V2
======================

ROLE
    Write the forensic case file after containment, then close the ticket. Produces
    a portfolio-ready artefact: a human-readable Markdown report, a machine-readable
    OCSF JSON export, and the raw ticket JSON.

CALLED BY
    Orchestrator: auditor_agent.audit(ticket_id)   (after the Responder)

INPUTS
    tickets/SOC-XXXX.json  — the fully-processed ticket (evidence, intel_summary,
                             responder findings, snapshot path, agent_trail)

OUTPUTS
    cases/SOC-XXXX_DATE.md         — human-readable case file
    cases/SOC-XXXX_DATE.ocsf.json  — OCSF Security Finding (class_uid 2001)
    cases/SOC-XXXX_DATE.json       — raw ticket snapshot
    ticket -> status: closed

NARRATIVE
    Structured sections are always Python-generated (precise). The executive
    summary is deterministic by default; set AUDITOR_LLM=true to have local
    qwen3-4b write prose (falls back to template if the model is unavailable).
"""

import json
import os
import shutil
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

BASE_DIR    = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
TICKETS_DIR = os.path.join(BASE_DIR, "tickets")
CASES_DIR   = os.path.join(BASE_DIR, "cases")
AUDITOR_LLM = os.environ.get("AUDITOR_LLM", "false").lower() == "true"
LM_URL      = os.environ.get("LM_STUDIO_BASE_URL", "http://127.0.0.1:1234/v1")
LM_MODEL    = os.environ.get("LM_STUDIO_MODEL", "qwen/qwen3-4b-2507")

# rule -> remediation checklist
REMEDIATION = {
    "R2":  ["Rotate credentials for the affected account", "Disable root SSH login",
            "Audit session/window files for the login window", "Enforce MFA / fail2ban on SSH"],
    "R6":  ["Verify the login was authorized", "Review off-hours access policy",
            "Cross-check against VPN/Tailscale logs"],
    "R9":  ["Review all cron entries (crontab -l, /etc/cron.d/, /etc/crontab)",
            "Audit /tmp and world-writable dirs for payloads", "Restore crontab from backup if malicious"],
    "R10": ["Confirm the security tool is running again", "Review logs for the gap period",
            "Audit who/what stopped the tool", "Ship logs to remote syslog"],
    "R12": ["Force password reset for sprayed accounts", "Enable account lockout thresholds"],
    "R13": ["Disable/rename default accounts", "Enforce key-based auth"],
    "R15": ["Assume account removal is track-covering", "Restore account from backup if needed",
            "Audit what the account had access to"],
    "R16": ["Verify the service is legitimate", "Inspect the unit file and ExecStart",
            "Disable + remove if unrecognized"],
    "R17": ["Inspect the modified startup script", "Restore from known-good backup",
            "Audit for persistence mechanisms"],
    "R18": ["Treat history clearing as evasion", "Recover shell history from backups/audit logs"],
}

NIST_PHASES = ["Preparation", "Detection & Analysis", "Containment",
               "Eradication", "Recovery", "Post-Incident Activity"]


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
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# ── narrative ─────────────────────────────────────────────────────────────────

def executive_summary(ticket):
    ev = ticket.get("evidence", {})
    isum = ticket.get("intel_summary", {})
    fallback = ("Ticket {tid} ({sev}) detected {rule} ({tech} / {tactic}) from {ip}. "
                "{fails} auth failures, {succ} successes. Reputation: {rep}. "
                "Known groups using this technique: {grp}.").format(
        tid=ticket.get("ticket_id"), sev=(ticket.get("severity") or "").upper(),
        rule=ticket.get("rule"), tech=ticket.get("mitre_technique"),
        tactic=ticket.get("mitre_tactic"), ip=ticket.get("source_ip"),
        fails=ev.get("auth_failures", 0), succ=ev.get("auth_successes", 0),
        rep=isum.get("ip_reputation", "unknown"),
        grp=", ".join(isum.get("associated_groups", [])) or "none")
    if not (AUDITOR_LLM and requests):
        return fallback
    try:
        prompt = ("Write a 2-3 sentence executive summary of this security incident "
                  "for a manager. Data:\n" + json.dumps({
                      "rule": ticket.get("rule"), "technique": ticket.get("mitre_technique"),
                      "ip": ticket.get("source_ip"), "evidence": ev,
                      "intel": isum}))
        r = requests.post(LM_URL.rstrip("/") + "/chat/completions",
                          json={"model": LM_MODEL, "messages": [{"role": "user", "content": prompt}],
                                "temperature": 0.3, "max_tokens": 160}, timeout=20)
        return r.json()["choices"][0]["message"]["content"].strip() or fallback
    except Exception:
        return fallback


# ── case file (markdown) ──────────────────────────────────────────────────────

def build_markdown(ticket):
    ev = ticket.get("evidence", {})
    isum = ticket.get("intel_summary", {})
    tid = ticket.get("ticket_id")
    rule = ticket.get("rule", "?")

    # timeline from findings
    timeline = [("{}".format(ticket.get("created", "")), "triage/investigator", "ticket opened ({})".format(rule))]
    for f in ticket.get("findings", []):
        timeline.append((f.get("timestamp", ""), f.get("agent", "?"),
                         f.get("note") or f.get("action") or ""))
    timeline.sort(key=lambda x: x[0])

    # IOCs
    iocs = [ticket.get("source_ip")]
    iocs += ev.get("failed_usernames", [])
    if ev.get("success_username"):
        iocs.append(ev["success_username"])
    iocs = [i for i in dict.fromkeys(iocs) if i]

    # containment actions from responder
    actions = [f for f in ticket.get("findings", []) if f.get("agent") == "responder"]
    rollbacks = [f.get("rollback_command") for f in actions
                 if f.get("rollback_command") and f["rollback_command"] not in ("n/a", "n/a (irreversible)")]

    md = []
    md.append("# Case File — {}\n".format(tid))
    md.append("**Severity:** {} · **Rule:** {} · **Detected:** {}\n".format(
        (ticket.get("severity") or "").upper(), rule, ticket.get("created", "")))
    md.append("**MITRE:** {} — {}\n".format(ticket.get("mitre_technique"), ticket.get("mitre_tactic")))

    md.append("\n## Executive Summary\n")
    md.append(executive_summary(ticket) + "\n")

    md.append("\n## Indicators of Compromise\n")
    for i in iocs:
        md.append("- `{}`\n".format(i))

    md.append("\n## MITRE ATT&CK\n")
    md.append("| Technique | Tactic | Associated Groups |\n|---|---|---|\n")
    md.append("| {} | {} | {} |\n".format(
        ticket.get("mitre_technique"), ticket.get("mitre_tactic"),
        ", ".join(isum.get("associated_groups", [])) or "—"))

    md.append("\n## Threat Intelligence\n")
    md.append("- Reputation: **{}**\n".format(isum.get("ip_reputation", "unknown")))
    md.append("- Feed hits: {}\n".format(", ".join(isum.get("feed_hits", [])) or "none"))
    md.append("- Geolocation / Org: {} / {}\n".format(isum.get("geolocation") or "—", isum.get("org") or "—"))
    md.append("- Prior tickets from this IP: {} {}\n".format(
        isum.get("prior_tickets", 0), isum.get("prior_ticket_ids", [])))

    md.append("\n## Timeline\n")
    for ts, who, what in timeline:
        md.append("- `{}` **{}** — {}\n".format(ts, who, what))

    md.append("\n## Containment Actions\n")
    if actions:
        for a in actions:
            md.append("- **{}** → `{}` (dry_run={}, exit={})\n".format(
                a.get("action"), a.get("command_run") or a.get("note") or "",
                a.get("dry_run"), a.get("exit_code")))
    else:
        md.append("- None taken (monitored / escalated)\n")

    md.append("\n## NIST IR Lifecycle\n")
    md.append("| Phase | Status |\n|---|---|\n")
    statuses = {"Preparation": "complete", "Detection & Analysis": "complete",
                "Containment": "complete" if ticket.get("response") not in (None, "monitor") else "n/a (monitor)",
                "Eradication": "pending", "Recovery": "pending",
                "Post-Incident Activity": "this case file"}
    for p in NIST_PHASES:
        md.append("| {} | {} |\n".format(p, statuses.get(p, "—")))

    md.append("\n## Remediation Checklist\n")
    for item in REMEDIATION.get(rule, ["Review ticket evidence and confirm scope."]):
        md.append("- [ ] {}\n".format(item))

    md.append("\n## Rollback Procedure\n")
    if rollbacks:
        md.append("```bash\n" + "\n".join(rollbacks) + "\n```\n")
    else:
        md.append("No reversible actions were taken.\n")

    md.append("\n## Agent Trail\n")
    md.append("`" + " → ".join(ticket.get("agent_trail", [])) + "`\n")
    if ticket.get("snapshot"):
        md.append("\n**Evidence snapshot:** `{}`\n".format(ticket["snapshot"]))
    return "".join(md)


# ── OCSF export ───────────────────────────────────────────────────────────────

def build_ocsf(ticket):
    sev_map = {"low": 2, "medium": 3, "high": 4, "critical": 5}
    return {
        "class_uid": 2001, "class_name": "Security Finding",
        "category_uid": 2, "category_name": "Findings",
        "activity_id": 1, "type_uid": 200101,
        "severity_id": sev_map.get((ticket.get("severity") or "").lower(), 0),
        "severity": ticket.get("severity"),
        "time": now_iso(),
        "finding_info": {
            "uid": ticket.get("ticket_id"),
            "title": "{} — {}".format(ticket.get("rule"), ticket.get("mitre_technique")),
            "created_time": ticket.get("created"),
        },
        "attacks": [{"technique": {"uid": ticket.get("mitre_technique")},
                     "tactic": {"name": ticket.get("mitre_tactic")}}],
        "observables": [
            {"name": "source_ip", "type": "IP Address", "value": ticket.get("source_ip")},
        ] + [{"name": "username", "type": "User", "value": u}
             for u in (ticket.get("evidence", {}).get("failed_usernames", []))],
        "metadata": {"product": {"name": "Agentic SOC V2"}, "version": "1.0"},
        "status": "closed",
    }


# ── entry point ───────────────────────────────────────────────────────────────

def audit(ticket_id):
    os.makedirs(CASES_DIR, exist_ok=True)
    path = os.path.join(TICKETS_DIR, ticket_id + ".json")
    ticket = _read_json(path, None)
    if not ticket:
        return None

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stem = os.path.join(CASES_DIR, "{}_{}".format(ticket_id, date))

    # markdown
    md_path = stem + ".md"
    with open(md_path, "w") as f:
        f.write(build_markdown(ticket))

    # OCSF + raw ticket
    _write_json(stem + ".ocsf.json", build_ocsf(ticket))
    _write_json(stem + ".json", ticket)

    # close ticket
    ticket["status"] = "closed"
    ticket["closed_at"] = now_iso()
    ticket["case_file"] = md_path
    ticket["ocsf_export"] = stem + ".ocsf.json"
    if "auditor" not in ticket.get("agent_trail", []):
        ticket.setdefault("agent_trail", []).append("auditor")
    ticket.setdefault("findings", []).append({
        "agent": "auditor", "timestamp": now_iso(),
        "note": "case file written; ticket closed", "case_file": md_path})
    _write_json(path, ticket)

    print("[AUDITOR] {} closed — case file {}".format(ticket_id, md_path))
    return md_path


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2:
        print(audit(sys.argv[1]))
    else:
        print("usage: auditor_agent.py SOC-XXXX")
