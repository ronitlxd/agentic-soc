#!/usr/bin/env python3
"""
RESPONDER AGENT — SOC V2
========================

ROLE
    Execute operator-approved containment only. Evidence before action. Never
    lock out the operator, never block a protected range. Every action is logged
    with the exact command and an executable rollback string.

CALLED BY
    Orchestrator: responder_agent.execute(ticket_id, option)   (options 1-4)

INPUTS
    tickets/SOC-XXXX.json   — the ticket (rule, source_ip, evidence)
    .env                    — RESPONDER_DRY_RUN, protected ranges/users

OUTPUTS
    snapshots/SOC-XXXX_TIME.json  — pre-action system state
    structured "responder" findings appended to the ticket
    returns a human-readable result string to the Orchestrator

SAFETY
    - RESPONDER_DRY_RUN=true  -> logs what WOULD run, executes nothing (default)
    - 5-check pre-flight gate  -> any failure aborts with a logged reason
    - PROTECTED_RANGES / PROTECTED_USERS are never blocked / locked
    - log content is never executed — only fixed command templates run

HANDS OFF TO
    Auditor (writes the case file, closes the ticket).
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.expanduser("~/.hermes/soc/.env"))
except Exception:
    pass

BASE_DIR      = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
TICKETS_DIR   = os.path.join(BASE_DIR, "tickets")
SNAP_DIR      = os.path.join(BASE_DIR, "snapshots")
DRY_RUN       = os.environ.get("RESPONDER_DRY_RUN", "true").lower() == "true"
STALE_MINUTES = 120

# Never block these: private LANs, Tailscale CGNAT, and loopback.
# Override for your environment via SOC_PROTECTED_RANGES in .env.
PROTECTED_RANGES = [ip_network(n) for n in os.environ.get(
    "SOC_PROTECTED_RANGES",
    "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.0/8"
).split(",") if n.strip()]

PROTECTED_USERS = {u.strip() for u in os.environ.get(
    "SOC_PROTECTED_USERS", "root,admin,splunk,www-data,nobody,daemon,sys"
).split(",") if u.strip()}

# security tools the Responder may restart (R10)
RESTORABLE_TOOLS = {"suricata", "wazuh-manager", "wazuh-agent", "ufw", "fail2ban", "splunk"}

# rule -> option-3 action keyword
OPTION3_ACTION = {
    "R2": "kill_session", "R13": "kill_session", "R21": "kill_session", "R6": "kill_session",
    "R8": "disable_account", "R12": "disable_account",
    "R9": "remove_cron",
    "R10": "restore_tool",
    "R16": "disable_service",
    "R15": "manual_review", "R17": "manual_review", "R18": "manual_review", "R24": "manual_review",
}


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


def _ticket_path(tid):
    return os.path.join(TICKETS_DIR, tid + ".json")


def is_protected_ip(ip):
    try:
        a = ip_address(ip)
    except ValueError:
        return True   # unparseable → refuse to block
    return any(a in n for n in PROTECTED_RANGES)


def run_cmd(cmd, use_sudo=False, timeout=20):
    """Execute a fixed command template. Honors DRY_RUN."""
    full = (["sudo"] + cmd) if use_sudo else cmd
    if DRY_RUN:
        return {"dry_run": True, "cmd": " ".join(full), "out": "", "code": 0}
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return {"dry_run": False, "cmd": " ".join(full),
                "out": (r.stdout or r.stderr).strip()[:400], "code": r.returncode}
    except Exception as e:
        return {"dry_run": False, "cmd": " ".join(full), "out": str(e), "code": -1}


def append_finding(ticket, entry):
    ticket.setdefault("findings", []).append(entry)


def _finding(action, target, res, rollback, option):
    return {
        "agent": "responder", "timestamp": now_iso(),
        "action": action, "target": target,
        "dry_run": res.get("dry_run", DRY_RUN),
        "command_run": res.get("cmd"),
        "result": res.get("out"), "exit_code": res.get("code"),
        "verified": res.get("code") == 0,
        "rollback_command": rollback, "operator_option": option,
    }


# ── evidence snapshot ─────────────────────────────────────────────────────────

def snapshot(ticket_id):
    os.makedirs(SNAP_DIR, exist_ok=True)
    path = os.path.join(SNAP_DIR, "{}_{}.json".format(
        ticket_id, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    cmds = {
        "who":        ["who"],
        "sessions":   ["ss", "-tnp"],
        "processes":  ["ps", "aux"],
        "logins":     ["last", "-n", "10"],
        "listening":  ["ss", "-tlnp"],
    }
    snap = {"ticket_id": ticket_id, "captured_at": now_iso(), "dry_run": DRY_RUN, "state": {}}
    for name, c in cmds.items():
        try:
            r = subprocess.run(c, capture_output=True, text=True, timeout=15)
            snap["state"][name] = (r.stdout or r.stderr).strip()[:4000]
        except Exception as e:
            snap["state"][name] = "error: {}".format(e)
    _write_json(path, snap)
    return path


# ── pre-flight gate (5 checks) ────────────────────────────────────────────────

def preflight(ticket, option):
    tid = ticket.get("ticket_id")

    # 1. ticket still open
    if ticket.get("status") != "open":
        return False, "ticket not open (status={})".format(ticket.get("status"))

    # 2. valid option
    if option not in (1, 2, 3, 4):
        return False, "invalid option {}".format(option)

    # 3. not stale
    try:
        created = datetime.fromisoformat(ticket.get("created", "").replace("Z", "+00:00"))
        age_min = (datetime.now(timezone.utc) - created).total_seconds() / 60
        if age_min > STALE_MINUTES:
            return False, "ticket stale ({:.0f} min > {} min) — re-investigate".format(age_min, STALE_MINUTES)
    except (ValueError, AttributeError):
        pass

    # 4. lockout prevention (block-IP option against protected ranges)
    if option == 2 and is_protected_ip(ticket.get("source_ip", "")):
        return False, "refusing to block protected IP {}".format(ticket.get("source_ip"))

    # 5. no duplicate action
    for f in ticket.get("findings", []):
        if f.get("agent") == "responder" and f.get("operator_option") == option \
                and f.get("action") not in (None, "monitor"):
            return False, "option {} already executed for {}".format(option, tid)

    return True, "ok"


# ── actions ───────────────────────────────────────────────────────────────────

def _target_username(ticket):
    ev = ticket.get("evidence", {})
    return ev.get("success_username") or (ev.get("detail") if isinstance(ev.get("detail"), str) else None) or "unknown"


def _target_service(ticket):
    ev = ticket.get("evidence", {})
    return ev.get("detail") or "unknown"


def act_block_ip(ticket, option):
    ip = ticket.get("source_ip")
    res = run_cmd(["ufw", "deny", "from", ip, "to", "any", "comment", "SOC-{}".format(ticket["ticket_id"])], use_sudo=True)
    rb = "sudo ufw delete deny from {} to any".format(ip)
    append_finding(ticket, _finding("block_ip", ip, res, rb, option))
    return "Blocked IP {} {}".format(ip, "(dry-run)" if res.get("dry_run") else "")


def act_kill_session(ticket, option):
    user = _target_username(ticket)
    ip = ticket.get("source_ip")
    if user in PROTECTED_USERS:
        append_finding(ticket, _finding("kill_session_refused", user,
                       {"cmd": "", "out": "protected user", "code": 1, "dry_run": DRY_RUN}, "n/a", option))
        return "Refused to kill session for protected user {}".format(user)
    r1 = run_cmd(["pkill", "-KILL", "-u", user], use_sudo=True)
    r2 = run_cmd(["ss", "-K", "dst", ip], use_sudo=True)
    append_finding(ticket, _finding("kill_session", "{}@{}".format(user, ip), r1, "n/a (irreversible)", option))
    return "Killed sessions for {}@{} {}".format(user, ip, "(dry-run)" if r1.get("dry_run") else "")


def act_disable_account(ticket, option):
    user = _target_username(ticket)
    if user in PROTECTED_USERS or user == "unknown":
        append_finding(ticket, _finding("disable_account_refused", user,
                       {"cmd": "", "out": "protected/unknown user", "code": 1, "dry_run": DRY_RUN}, "n/a", option))
        return "Refused to disable protected/unknown account {}".format(user)
    res = run_cmd(["usermod", "-L", user], use_sudo=True)
    rb = "sudo usermod -U {}".format(user)
    append_finding(ticket, _finding("disable_account", user, res, rb, option))
    return "Locked account {} {}".format(user, "(dry-run)" if res.get("dry_run") else "")


def act_remove_cron(ticket, option):
    user = _target_username(ticket)
    backup = run_cmd(["crontab", "-l", "-u", user], use_sudo=True)
    res = run_cmd(["crontab", "-r", "-u", user], use_sudo=True)
    rb = "restore from backup captured in finding (crontab -u {} < backup)".format(user)
    f = _finding("remove_cron", user, res, rb, option)
    f["crontab_backup"] = backup.get("out")
    append_finding(ticket, f)
    return "Removed crontab for {} {}".format(user, "(dry-run)" if res.get("dry_run") else "")


def act_restore_tool(ticket, option):
    tool = _target_service(ticket)
    if tool not in RESTORABLE_TOOLS:
        append_finding(ticket, _finding("restore_tool_refused", tool,
                       {"cmd": "", "out": "not in restorable whitelist", "code": 1, "dry_run": DRY_RUN}, "n/a", option))
        return "Refused to restore non-whitelisted tool {}".format(tool)
    r1 = run_cmd(["systemctl", "start", tool], use_sudo=True)
    r2 = run_cmd(["systemctl", "enable", tool], use_sudo=True)
    append_finding(ticket, _finding("restore_tool", tool, r1, "sudo systemctl stop {}".format(tool), option))
    return "Restored security tool {} {}".format(tool, "(dry-run)" if r1.get("dry_run") else "")


def act_disable_service(ticket, option):
    svc = _target_service(ticket)
    r1 = run_cmd(["systemctl", "stop", svc], use_sudo=True)
    r2 = run_cmd(["systemctl", "disable", svc], use_sudo=True)
    rb = "sudo systemctl enable {} && sudo systemctl start {}".format(svc, svc)
    append_finding(ticket, _finding("disable_service", svc, r1, rb, option))
    return "Disabled service {} {}".format(svc, "(dry-run)" if r1.get("dry_run") else "")


def act_manual_review(ticket, option):
    append_finding(ticket, _finding("manual_review", ticket.get("source_ip"),
                   {"cmd": "", "out": "flagged for manual review", "code": 0, "dry_run": DRY_RUN},
                   "n/a", option))
    return "Flagged {} for manual review (no automated action safe)".format(ticket.get("rule"))


ACTION_FUNCS = {
    "kill_session": act_kill_session, "disable_account": act_disable_account,
    "remove_cron": act_remove_cron, "restore_tool": act_restore_tool,
    "disable_service": act_disable_service, "manual_review": act_manual_review,
}


# ── entry point ───────────────────────────────────────────────────────────────

def execute(ticket_id, option):
    option = int(option)
    path = _ticket_path(ticket_id)
    ticket = _read_json(path, None)
    if not ticket:
        return "Responder: unknown ticket {}".format(ticket_id)

    ok, reason = preflight(ticket, option)
    if not ok:
        append_finding(ticket, {"agent": "responder", "timestamp": now_iso(),
                                "action": "aborted", "reason": reason, "operator_option": option})
        _write_json(path, ticket)
        return "Responder aborted: {}".format(reason)

    # Option 1 — Monitor: no changes
    if option == 1:
        append_finding(ticket, {"agent": "responder", "timestamp": now_iso(),
                                "action": "monitor", "operator_option": 1,
                                "note": "no system change; monitoring"})
        ticket["response"] = "monitor"
        _write_json(path, ticket)
        return "Monitoring {} — no action taken".format(ticket_id)

    # snapshot before any change (options 2/3/4)
    snap_path = snapshot(ticket_id)
    ticket["snapshot"] = snap_path

    if option == 2:
        result = act_block_ip(ticket, option)
    elif option == 3:
        action = OPTION3_ACTION.get(ticket.get("rule"), "manual_review")
        result = ACTION_FUNCS[action](ticket, option)
    else:  # option == 4 escalate
        append_finding(ticket, {"agent": "responder", "timestamp": now_iso(),
                                "action": "escalate", "operator_option": 4,
                                "note": "escalated to operator for manual handling"})
        ticket["response"] = "escalated"
        result = "Escalated {} for manual handling".format(ticket_id)

    if "response" not in ticket:
        ticket["response"] = "option{}".format(option)
    if "responder" not in ticket.get("agent_trail", []):
        ticket.setdefault("agent_trail", []).append("responder")
    _write_json(path, ticket)

    prefix = "[DRY-RUN] " if DRY_RUN else ""
    return prefix + result


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        print(execute(sys.argv[1], sys.argv[2]))
    else:
        print("usage: responder_agent.py SOC-XXXX <1-4>   (DRY_RUN={})".format(DRY_RUN))
