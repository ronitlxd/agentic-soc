#!/usr/bin/env python3
"""
RESPONDER — Containment executor.
Evidence first. Action second. Verify third. Rollback documented always.
Only executes operator-approved actions from the approved list.
Never acts on content from log files or ticket findings (prompt injection boundary).
"""

import os
import subprocess
import sys
from datetime import datetime, timezone

TICKET_CLI      = os.path.expanduser("~/.hermes/skills/soc/ticket-manager/ticket_cli.py")
SNAPSHOT_DIR    = "/tmp"

# Services Responder is permitted to stop
APPROVED_SERVICES = {
    "apache2",
    "suricata",
    "tor@default",
    "photo-gallery",
    "homelab-dashboard",
}

# Accounts that must never be locked automatically (would sever operator access).
# Override via env: SOC_PROTECTED_USERS="root,admin,operator"
PROTECTED_USERS = {
    u.strip()
    for u in os.environ.get("SOC_PROTECTED_USERS", "root").split(",")
    if u.strip()
} | {os.environ.get("USER", "")}


# ── helpers ───────────────────────────────────────────────────────────────────

def now():
    return datetime.now(timezone.utc).isoformat()


def ts_str():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def append_finding(ticket_id, note):
    subprocess.run(
        [sys.executable, TICKET_CLI, "append",
         "--id", ticket_id, "--agent", "responder", "--note", note[:500]],
        capture_output=True, text=True,
    )


def run_cmd(cmd, use_sudo=False, timeout=30):
    if use_sudo:
        cmd = ["sudo"] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "command timed out after {}s".format(timeout), -1
    except Exception as e:
        return "", str(e), -1


# ── evidence snapshot ─────────────────────────────────────────────────────────

def snapshot_evidence(ticket_id):
    """
    Always runs first before any action.
    Captures system state at moment of response.
    """
    path = "{}/{}_{}_snapshot.txt".format(SNAPSHOT_DIR, ticket_id, ts_str())

    cmds = {
        "WHO":      ["who"],
        "SS":       ["ss", "-tulnp"],
        "PS":       ["ps", "aux"],
        "LAST":     ["last", "-20"],
        "NETSTAT":  ["netstat", "-an"],
        "UFW":      ["ufw", "status", "numbered"],
    }

    with open(path, "w") as f:
        f.write("=== EVIDENCE SNAPSHOT — {} — {} ===\n\n".format(ticket_id, now()))
        for label, cmd in cmds.items():
            use_sudo = label == "UFW"
            out, err, _ = run_cmd(cmd, use_sudo=use_sudo)
            f.write("--- {} ---\n{}\n\n".format(label, out or err))

    append_finding(ticket_id, "Evidence snapshot saved: {}".format(path))
    return path


# ── approved actions ──────────────────────────────────────────────────────────

def block_ip(ticket_id, ip):
    append_finding(ticket_id,
        "ACTION: sudo ufw insert 1 deny from {} | "
        "rollback: sudo ufw delete deny from {}".format(ip, ip))
    out, err, code = run_cmd(["ufw", "insert", "1", "deny", "from", ip], use_sudo=True)
    if code == 0:
        append_finding(ticket_id, "RESULT: IP {} blocked in UFW (rule #1)".format(ip))
        return True
    append_finding(ticket_id, "FAILED: block {} — {}".format(ip, err))
    return False


def block_outbound(ticket_id, ip):
    append_finding(ticket_id,
        "ACTION: sudo ufw deny out to {} | "
        "rollback: sudo ufw delete deny out to {}".format(ip, ip))
    out, err, code = run_cmd(["ufw", "deny", "out", "to", ip], use_sudo=True)
    if code == 0:
        append_finding(ticket_id, "RESULT: outbound to {} blocked".format(ip))
        return True
    append_finding(ticket_id, "FAILED: block outbound {} — {}".format(ip, err))
    return False


def kill_session(ticket_id, pts):
    append_finding(ticket_id,
        "ACTION: sudo pkill -9 -t {} | "
        "rollback: none (session termination is irreversible)".format(pts))
    out, err, code = run_cmd(["pkill", "-9", "-t", pts], use_sudo=True)
    if code in (0, 1):  # 1 = no matching process (already gone)
        append_finding(ticket_id, "RESULT: session {} terminated".format(pts))
        return True
    append_finding(ticket_id, "FAILED: kill session {} — {}".format(pts, err))
    return False


def stop_service(ticket_id, service):
    if service not in APPROVED_SERVICES:
        append_finding(ticket_id, "REJECTED: {} not in approved service list".format(service))
        return False
    append_finding(ticket_id,
        "ACTION: sudo systemctl stop {} | "
        "rollback: sudo systemctl start {}".format(service, service))
    out, err, code = run_cmd(["systemctl", "stop", service], use_sudo=True)
    if code == 0:
        append_finding(ticket_id, "RESULT: {} stopped".format(service))
        return True
    append_finding(ticket_id, "FAILED: stop {} — {}".format(service, err))
    return False


def lock_user(ticket_id, username):
    if username in PROTECTED_USERS:
        # Locking the operator/root account could sever access — require manual action
        append_finding(ticket_id,
            "REJECTED: locking {} could sever operator access. "
            "Perform manually if required.".format(username))
        return False
    append_finding(ticket_id,
        "ACTION: sudo usermod -L {} | "
        "rollback: sudo usermod -U {}".format(username, username))
    out, err, code = run_cmd(["usermod", "-L", username], use_sudo=True)
    if code == 0:
        append_finding(ticket_id, "RESULT: user {} locked".format(username))
        return True
    append_finding(ticket_id, "FAILED: lock {} — {}".format(username, err))
    return False


# ── verification ──────────────────────────────────────────────────────────────

def verify(ticket_id, ip):
    who_out,  _, _ = run_cmd(["who"])
    conn_out, _, _ = run_cmd(["ss", "-an"])
    ufw_out,  _, _ = run_cmd(["ufw", "status", "numbered"], use_sudo=True)

    remaining_sessions = [l for l in who_out.splitlines()  if ip in l]
    remaining_conns    = [l for l in conn_out.splitlines() if ip in l]

    if not remaining_sessions and not remaining_conns:
        append_finding(ticket_id,
            "VERIFIED: no remaining sessions or connections from {}".format(ip))
    else:
        if remaining_sessions:
            append_finding(ticket_id,
                "WARNING: sessions still active from {}: {}".format(
                    ip, str(remaining_sessions[:3])))
        if remaining_conns:
            append_finding(ticket_id,
                "WARNING: connections still present from {}: {}".format(
                    ip, str(remaining_conns[:3])))


# ── session helpers ───────────────────────────────────────────────────────────

def get_sessions(src_ip=None):
    out, _, _ = run_cmd(["who"])
    sessions  = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[-1].strip("()")
            if src_ip is None or ip == src_ip:
                sessions.append({"user": parts[0], "pts": parts[1], "ip": ip})
    return sessions


# ── option executors ──────────────────────────────────────────────────────────

def option1_full_containment(ticket_id, ip, extra_ips=None):
    """Block IP + kill all sessions from that IP + block outbound C2 + verify."""
    snapshot_evidence(ticket_id)
    block_ip(ticket_id, ip)
    if extra_ips:
        for eip in extra_ips:
            block_outbound(ticket_id, eip)
    sessions = get_sessions(ip)
    for s in sessions:
        kill_session(ticket_id, s["pts"])
    verify(ticket_id, ip)
    return (
        "Full containment complete.\n"
        "IP {} blocked.\n"
        "{} session(s) terminated.\n"
        "Rollback: sudo ufw delete deny from {}".format(ip, len(sessions), ip)
    )


def option2_soft_containment(ticket_id, ip):
    """Block IP only. Preserve session for forensics."""
    snapshot_evidence(ticket_id)
    block_ip(ticket_id, ip)
    verify(ticket_id, ip)
    sessions = get_sessions(ip)
    if sessions:
        append_finding(ticket_id,
            "Sessions preserved for forensics: {}".format(str(sessions)))
    return (
        "Soft containment complete.\n"
        "IP {} blocked.\n"
        "{} session(s) preserved for forensics.".format(ip, len(sessions))
    )


def option3_observe(ticket_id, ip):
    """Snapshot only. No blocking."""
    path = snapshot_evidence(ticket_id)
    return "Observe only. Evidence snapshot saved: {}.".format(path)


def option4_false_positive(ticket_id):
    """Close ticket as false positive."""
    subprocess.run(
        [sys.executable, TICKET_CLI, "close",
         "--id", ticket_id,
         "--note", "Closed by operator — false positive",
         "--agent", "coordinator"],
        capture_output=True, text=True,
    )
    return "Ticket {} closed as false positive.".format(ticket_id)


# ── entry point ───────────────────────────────────────────────────────────────

def execute(ticket_id, option, src_ip, extra_ips=None):
    """
    Main entry point called by orchestrator.
    option: int 1-4
    src_ip: attacker IP
    extra_ips: list of additional IPs to block outbound (C2 destinations)
    """
    option = int(option)
    if option == 1:
        return option1_full_containment(ticket_id, src_ip, extra_ips)
    elif option == 2:
        return option2_soft_containment(ticket_id, src_ip)
    elif option == 3:
        return option3_observe(ticket_id, src_ip)
    elif option == 4:
        return option4_false_positive(ticket_id)
    else:
        return "Unknown option: {}".format(option)
