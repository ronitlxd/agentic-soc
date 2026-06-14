#!/usr/bin/env python3
"""
TRIAGE AGENT — SOC V2
=====================

ROLE
    Collect and normalize every log source concurrently, in real time, and
    feed the Investigator. Triage makes no correlation decisions — it only
    normalizes, maintains per-IP statistics, and pre-flags a small set of
    high-confidence single-event signals.

INPUTS
    Tails (rotation-safe) the V2 base log sources:
        /var/log/suricata/eve.json   (alert events; flow added in Tier 2)
        /var/log/auth.log            (ssh, sudo, account events)
        /var/log/syslog              (services, cron, defense-tool changes)
        /var/log/apache2/access.log  (web requests)
        /var/log/apache2/error.log   (web errors)
        /var/log/ufw.log             (firewall blocks)
    (In sandbox mode, reads fake logs from SANDBOX_LOG_DIR instead.)

OUTPUTS  (all V2-namespaced — never touches V1 state files)
    ip_stats.json          — live per-IP statistics (PRIMARY Investigator input)
    event_buffer.json      — normalized event stream w/ uuid4 event_id (secondary)
    tickets/SOC-XXXX.json   — pre-flag tickets for R7 / R8 / R10
    v2_log_sizes.json      — inode+size tracker for log-tamper detection
    v2_known_ips.json      — 7-day rolling set of IPs seen in auth.log
    triage_unparsed.log    — lines that matched no parser (never silently dropped)

HANDS OFF TO
    Investigator (reads ip_stats.json + event_buffer.json).
    Pre-flag tickets go straight into the ticket store; the Investigator skips
    any IP that already has an open ticket for the same rule.

SECURITY
    All log content is untrusted input. It is only ever parsed and quoted —
    never evaluated, executed, or interpreted as code.
"""

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address, ip_network

# ── environment / config ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.expanduser("~/.hermes/soc/.env"))
except Exception:
    pass  # dotenv optional; env may already be exported by systemd

BASE_DIR        = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
SERVER_LAN_IP   = os.environ.get("SERVER_LAN_IP", "10.0.0.10")
SERVER_TS_IP    = os.environ.get("SERVER_TAILSCALE_IP", "100.64.0.1")
SANDBOX_MODE    = os.environ.get("SOC_SANDBOX_MODE", "false").lower() == "true"
SANDBOX_LOG_DIR = os.environ.get("SANDBOX_LOG_DIR", os.path.join(BASE_DIR, "sandbox/fake_logs"))

# V2-namespaced state files (do NOT collide with V1's findings_buffer/log_sizes/tickets.json)
IP_STATS_PATH   = os.path.join(BASE_DIR, "ip_stats.json")
EVENT_BUF_PATH  = os.path.join(BASE_DIR, "event_buffer.json")
SIZE_TRACK_PATH = os.path.join(BASE_DIR, "v2_log_sizes.json")
KNOWN_IPS_PATH  = os.path.join(BASE_DIR, "v2_known_ips.json")
TICKETS_DIR     = os.path.join(BASE_DIR, "tickets")
UNPARSED_PATH   = os.path.join(BASE_DIR, "triage_unparsed.log")

EVENT_BUF_MAX   = 5000          # rolling cap on the secondary event buffer
KNOWN_IP_DAYS   = 7             # rolling window for known_ip
SIZE_POLL_SECS  = 60

# Real log paths (V2 base). Suricata flow is added in Tier 2, not here.
BASE_LOG_SOURCES = [
    "/var/log/suricata/eve.json",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/ufw.log",
]

def _resolve_sources():
    if not SANDBOX_MODE:
        return BASE_LOG_SOURCES
    # In sandbox mode, map each real path to a fake file of the same basename
    return [os.path.join(SANDBOX_LOG_DIR, os.path.basename(p)) for p in BASE_LOG_SOURCES]

LOG_SOURCES = _resolve_sources()

# Internal networks (RFC1918 + loopback + Tailscale CGNAT). Everything else = external.
INTERNAL_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("100.64.0.0/10"),   # Tailscale CGNAT
]

# Defense tools whose stop/disable is a critical R10 signal
DEFENSE_TOOLS = ("suricata", "wazuh-manager", "wazuh-agent", "wazuh",
                 "splunk", "splunkd", "ufw", "fail2ban")

# ── Tier 1 constants ──────────────────────────────────────────────────────────
DEFAULT_USERNAMES = {"root", "admin", "ubuntu", "pi", "oracle", "test", "guest",
                     "user", "postgres", "mysql", "ftpuser"}

KNOWN_SERVICES = {"splunk", "splunkd", "suricata", "wazuh-agent", "wazuh-manager",
                  "apache2", "mariadb", "mysql", "nextcloud", "ssh", "sshd", "ufw",
                  "tailscaled", "lm-studio", "homelab-dashboard", "photo-gallery",
                  "hermes", "cron", "systemd-resolved", "networkmanager"}

STARTUP_PATHS = ("/etc/rc.local", "/etc/profile", "/etc/profile.d/",
                 "/etc/bash.bashrc", "/root/.bashrc", "/root/.profile",
                 "/etc/environment")

NEXTCLOUD_LOGIN_PATHS = ("/index.php/login", "/login", "/remote.php/dav",
                         "/ocs/v1.php", "/ocs/v2.php")

_lock = threading.Lock()


# ── time / json helpers ───────────────────────────────────────────────────────

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


def classify_ip(ip_str):
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return "unknown"
    return "internal" if any(ip in net for net in INTERNAL_NETS) else "external"


# ── known-IP 7-day rolling window ─────────────────────────────────────────────

def _load_known():
    return _read_json(KNOWN_IPS_PATH, {})


def _is_known(ip):
    known = _load_known()
    ts = known.get(ip)
    if not ts:
        return False
    try:
        seen = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - seen) < timedelta(days=KNOWN_IP_DAYS)
    except ValueError:
        return False


def _mark_known(ip):
    known = _load_known()
    cutoff = datetime.now(timezone.utc) - timedelta(days=KNOWN_IP_DAYS)
    # prune stale
    known = {
        k: v for k, v in known.items()
        if _safe_dt(v) and _safe_dt(v) > cutoff
    }
    known[ip] = now_iso()
    _write_json(KNOWN_IPS_PATH, known)


def _safe_dt(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ── ip_stats store ────────────────────────────────────────────────────────────

def _stats_template(ip):
    return {
        "ip_type":                 classify_ip(ip),
        "first_seen":              now_iso(),
        "last_seen":               now_iso(),
        "auth_failures":           0,
        "auth_successes":          0,
        "success_username":        None,
        "failed_usernames":        [],
        "scan_targets":            [],
        "services_hit":            [],
        "active_hours_utc":        [],
        "known_ip":                False,
        "bytes_out":               0,
        "web_posts":               0,
        "web_post_to_unknown_path": False,
        "web_200_response":        False,
        "account_events":          0,
        "cron_events":             0,
        "service_stop_events":     0,
        # --- Tier 1 fields ---
        "default_account_login":       False,   # T1078.001
        "sudo_failures":               0,        # T1548.003
        "sudo_denied":                 False,    # T1548.003
        "account_deleted":             False,    # T1531
        "unknown_service_enabled":     False,    # T1543.002
        "unknown_service_name":        None,     # T1543.002
        "startup_script_modified":     False,    # T1037
        "history_cleared":             False,    # T1070.003
        "unique_paths_hit":            [],       # T1595.002 (list; count used)
        "web_auth_failures_nextcloud": 0,        # T1110 web
        "web_auth_success_nextcloud":  False,    # T1110 web
    }


def update_stats(ip, mutate):
    """Load ip_stats, apply mutate(entry), persist. Thread-safe."""
    if not ip or ip == "unknown":
        return
    with _lock:
        stats = _read_json(IP_STATS_PATH, {})
        entry = stats.get(ip)
        if entry is None:
            entry = _stats_template(ip)
            entry["known_ip"] = _is_known(ip)   # known BEFORE this session
        entry["last_seen"] = now_iso()
        hr = datetime.now(timezone.utc).hour
        if hr not in entry["active_hours_utc"]:
            entry["active_hours_utc"].append(hr)
        mutate(entry)
        stats[ip] = entry
        _write_json(IP_STATS_PATH, stats)


# ── event buffer (secondary output) ───────────────────────────────────────────

def append_event(evt):
    with _lock:
        buf = _read_json(EVENT_BUF_PATH, {"events": []})
        buf["events"].append(evt)
        if len(buf["events"]) > EVENT_BUF_MAX:
            buf["events"] = buf["events"][-EVENT_BUF_MAX:]
        _write_json(EVENT_BUF_PATH, buf)


def make_event(source_ip, event_type, log_source, raw,
               dest_ip=SERVER_LAN_IP, username=None, service=None, port=None):
    return {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  now_iso(),
        "source_ip":  source_ip or "unknown",
        "dest_ip":    dest_ip,
        "ip_type":    classify_ip(source_ip or ""),
        "username":   username,
        "service":    service,
        "event_type": event_type,
        "port":       port,
        "log_source": log_source,
        "raw":        (raw or "")[:500],
    }


def emit(evt):
    """Push a normalized event to the buffer and update per-IP stats."""
    append_event(evt)
    ip = evt["source_ip"]
    et = evt["event_type"]

    def mut(e):
        if et == "auth_fail":
            e["auth_failures"] += 1
            u = evt.get("username")
            if u and u not in e["failed_usernames"]:
                e["failed_usernames"].append(u)
            _svc(e, evt.get("service") or "ssh")
        elif et == "auth_success":
            e["auth_successes"] += 1
            e["success_username"] = evt.get("username")
            _svc(e, evt.get("service") or "ssh")
        elif et in ("account_created", "account_modified"):
            e["account_events"] += 1
        elif et == "cron_modified":
            e["cron_events"] += 1
        elif et == "service_stopped":
            e["service_stop_events"] += 1
        elif et == "web_post":
            e["web_posts"] += 1
            if evt.get("_unknown_path"):
                e["web_post_to_unknown_path"] = True
            if evt.get("_status") == 200:
                e["web_200_response"] = True
            _svc(e, "web")
        elif et == "web_get":
            _svc(e, "web")
        elif et == "port_scan":
            tgt = evt.get("dest_ip")
            if tgt and tgt not in e["scan_targets"]:
                e["scan_targets"].append(tgt)
        elif et == "firewall_block":
            tgt = evt.get("dest_ip")
            if tgt and tgt not in e["scan_targets"]:
                e["scan_targets"].append(tgt)
        # --- Tier 1 event handling ---
        elif et == "default_account_login":
            e["default_account_login"] = True
        elif et == "sudo_fail":
            e["sudo_failures"] += 1
        elif et == "sudo_denied":
            e["sudo_denied"] = True
        elif et == "account_deleted":
            e["account_deleted"] = True
        elif et == "unknown_service_enabled":
            e["unknown_service_enabled"] = True
            e["unknown_service_name"] = evt.get("_service_name")
        elif et == "startup_script_modified":
            e["startup_script_modified"] = True
        elif et == "history_cleared":
            e["history_cleared"] = True
        elif et == "web_auth_fail":
            e["web_auth_failures_nextcloud"] += 1
            _svc(e, "nextcloud")
        elif et == "web_auth_success":
            e["web_auth_success_nextcloud"] = True
            _svc(e, "nextcloud")

        # unique-path tracking for any web request (R19 vuln scan)
        p = evt.get("_path")
        if p and p not in e["unique_paths_hit"]:
            e["unique_paths_hit"].append(p)

    update_stats(ip, mut)

    # auth events establish/refresh known_ip window
    if et in ("auth_fail", "auth_success"):
        _mark_known(ip)


def _svc(entry, name):
    if name and name not in entry["services_hit"]:
        entry["services_hit"].append(name)


# ── pre-flag ticket writer (R7 / R8 / R10) ────────────────────────────────────

def _next_ticket_id():
    os.makedirs(TICKETS_DIR, exist_ok=True)
    mx = 0
    for fn in os.listdir(TICKETS_DIR):
        m = re.match(r"SOC-(\d+)\.json$", fn)
        if m:
            mx = max(mx, int(m.group(1)))
    return "SOC-{:04d}".format(mx + 1)


def _open_preflag_exists(source_ip, rule):
    """Dedup: is there already an OPEN pre-flag ticket for this ip+rule?"""
    if not os.path.isdir(TICKETS_DIR):
        return False
    for fn in os.listdir(TICKETS_DIR):
        if not fn.endswith(".json"):
            continue
        t = _read_json(os.path.join(TICKETS_DIR, fn), {})
        if (t.get("status") == "open"
                and t.get("source_ip") == source_ip
                and t.get("rule") == rule):
            return True
    return False


def write_preflag_ticket(source_ip, rule, severity, technique, tactic, raw, detail=None):
    with _lock:
        if _open_preflag_exists(source_ip, rule):
            return None
        tid = _next_ticket_id()
        ticket = {
            "ticket_id":        tid,
            "created":          now_iso(),
            "source_ip":        source_ip,
            "ip_type":          classify_ip(source_ip),
            "rule":             rule,
            "detection_method": "triage_preflag",
            "mitre_technique":  technique,
            "mitre_tactic":     tactic,
            "severity":         severity,
            "evidence":         {"detail": detail, "raw": (raw or "")[:500]},
            "findings":         [],
            "status":           "open",
            "agent_trail":      ["triage"],
        }
        _write_json(os.path.join(TICKETS_DIR, tid + ".json"), ticket)
        return tid


# ── unparsed logging ──────────────────────────────────────────────────────────

def log_unparsed(log_source, line):
    try:
        with open(UNPARSED_PATH, "a") as f:
            f.write("{} [{}] {}\n".format(now_iso(), log_source, line.strip()[:400]))
    except OSError:
        pass


# ── parsers ───────────────────────────────────────────────────────────────────
# Each returns a list of normalized events (usually 0 or 1; auth may return N
# for the sshd "message repeated N times" expansion).

_last_auth_fail = {}   # remembers last failed (user, ip) for repeat-expansion


def parse_auth(line):
    # sshd collapse expansion — emit N synthetic failures for the last IP/user
    m = re.search(r"message repeated (\d+) times:.*Failed password for (?:invalid user )?(\S+) from (\S+)", line)
    if m:
        n = int(m.group(1))
        user, ip = m.group(2), m.group(3)
        return [make_event(ip, "auth_fail", "auth.log", line, username=user, service="ssh")
                for _ in range(n)]

    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        _last_auth_fail[ip] = user
        return [make_event(ip, "auth_fail", "auth.log", line, username=user, service="ssh")]

    m = re.search(r"Invalid user (\S+) from (\S+)", line)
    if m:
        return [make_event(m.group(2), "auth_fail", "auth.log", line, username=m.group(1), service="ssh")]

    m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        evts = [make_event(ip, "auth_success", "auth.log", line, username=user, service="ssh")]
        if user in DEFAULT_USERNAMES:   # T1078.001 — default account used
            evts.append(make_event(ip, "default_account_login", "auth.log", line,
                                    username=user, service="ssh"))
        return evts

    # account creation (T1136) — R8 pre-flag
    m = re.search(r"new user: name=(\S+?),", line)
    if m or "useradd" in line or "adduser" in line:
        user = m.group(1) if m else "unknown"
        return [make_event(SERVER_LAN_IP, "account_created", "auth.log", line, username=user)]

    # account modification (T1098) — R8 pre-flag
    if "usermod" in line or "password changed for" in line or ("passwd" in line and "password for" in line):
        return [make_event(SERVER_LAN_IP, "account_modified", "auth.log", line)]

    # crontab edits via auth (sudo crontab)
    if "crontab" in line and ("COMMAND" in line or "replaced" in line):
        return [make_event(SERVER_LAN_IP, "cron_modified", "auth.log", line)]

    # sudo abuse (T1548.003) — local
    if "sudo:" in line and "authentication failure" in line:
        return [make_event(SERVER_LAN_IP, "sudo_fail", "auth.log", line)]
    if "sudo:" in line and ("command not allowed" in line or "user NOT in sudoers" in line):
        return [make_event(SERVER_LAN_IP, "sudo_denied", "auth.log", line)]

    # account deletion (T1531) — R15 pre-flag
    if "userdel" in line or "deluser" in line:
        return [make_event(SERVER_LAN_IP, "account_deleted", "auth.log", line)]

    return []


def parse_syslog(line):
    low = line.lower()

    # defense-tool disable (T1562.001) — R10 pre-flag, critical
    if ("systemctl" in low and ("stop" in low or "disable" in low)):
        for tool in DEFENSE_TOOLS:
            if tool in low:
                e = make_event(SERVER_LAN_IP, "service_stopped", "syslog", line, service=tool)
                e["_defense_tool"] = tool
                return [e]
    if "ufw" in low and "disable" in low:
        e = make_event(SERVER_LAN_IP, "service_stopped", "syslog", line, service="ufw")
        e["_defense_tool"] = "ufw"
        return [e]
    if "iptables" in low and (" -f" in low or "--flush" in low):
        e = make_event(SERVER_LAN_IP, "service_stopped", "syslog", line, service="iptables")
        e["_defense_tool"] = "iptables"
        return [e]

    # unknown systemd service enabled (T1543.002 — R16)
    if "systemctl" in low and "enable" in low:
        m = re.search(r"enable\s+([\w@.\-]+)", line)
        svc = (m.group(1).replace(".service", "") if m else "")
        if svc and svc.lower() not in KNOWN_SERVICES:
            e = make_event(SERVER_LAN_IP, "unknown_service_enabled", "syslog", line, service=svc)
            e["_service_name"] = svc
            return [e]

    # startup/logon script modified (T1037 — R17 pre-flag)
    if any(p in line for p in STARTUP_PATHS) and any(w in low for w in ("modif", "creat", "write", "chang")):
        return [make_event(SERVER_LAN_IP, "startup_script_modified", "syslog", line)]

    # command history cleared (T1070.003 — R18 pre-flag)
    if ("histfile=/dev/null" in low or "histsize=0" in low
            or "history -c" in low or "history -w /dev/null" in low):
        return [make_event(SERVER_LAN_IP, "history_cleared", "syslog", line)]

    # crontab MODIFICATION (T1053.003 — Investigator R9). NOT normal execution.
    # Real edit signals: crontab install/replace/edit, or writes under cron dirs.
    # (A plain "CRON ... CMD ..." line is a job RUNNING — benign, ignored.)
    if "crontab" in low and ("replace" in low or "new crontab" in low
                             or "begin edit" in low or "end edit" in low):
        return [make_event(SERVER_LAN_IP, "cron_modified", "syslog", line)]
    if any(d in line for d in ("/etc/cron.d/", "/etc/crontab", "/var/spool/cron")) \
            and any(w in low for w in ("write", "modif", "creat", "chang")):
        return [make_event(SERVER_LAN_IP, "cron_modified", "syslog", line)]

    return []


_apache_re = re.compile(
    r'^(\S+).*?"(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})'
)
_known_web_paths = ("/", "/index.php", "/index.html", "/favicon.ico",
                    "/apps/", "/core/", "/settings/")


def parse_apache(line):
    m = _apache_re.search(line)
    if not m:
        return []
    ip, method, path, status = m.group(1), m.group(2), m.group(3), int(m.group(4))

    # Nextcloud web auth (T1110 / R20, R21) — POST to a login endpoint
    if method == "POST" and any(path.startswith(p) for p in NEXTCLOUD_LOGIN_PATHS):
        if status in (401, 403):
            e = make_event(ip, "web_auth_fail", "apache_access", line, service="nextcloud")
        elif status == 200:
            e = make_event(ip, "web_auth_success", "apache_access", line, service="nextcloud")
        else:
            e = make_event(ip, "web_post", "apache_access", line, service="nextcloud")
        e["_path"] = path
        return [e]

    if method == "POST":
        e = make_event(ip, "web_post", "apache_access", line, service="web")
        e["_unknown_path"] = not any(path.startswith(p) for p in _known_web_paths)
        e["_status"] = status
        e["_path"] = path
        e["port"] = 80
        return [e]
    if status >= 500:
        e = make_event(ip, "web_error", "apache_access", line, service="web")
        e["_path"] = path
        return [e]
    e = make_event(ip, "web_get", "apache_access", line, service="web")
    e["_path"] = path
    return [e]


def parse_ufw(line):
    if "UFW BLOCK" not in line:
        return []
    src = re.search(r"SRC=(\S+)", line)
    dst = re.search(r"DST=(\S+)", line)
    dpt = re.search(r"DPT=(\d+)", line)
    ip = src.group(1) if src else "unknown"
    e = make_event(ip, "firewall_block", "ufw.log", line,
                   dest_ip=(dst.group(1) if dst else SERVER_LAN_IP),
                   port=int(dpt.group(1)) if dpt else None)
    return [e]


def parse_suricata(line):
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return []
    if evt.get("event_type") != "alert":
        return []   # flow/stats/dns handled in Tier 2
    sig = evt.get("alert", {}).get("signature", "")
    ip = evt.get("src_ip", "unknown")
    et = "port_scan" if "SCAN" in sig.upper() else "alert"
    e = make_event(ip, et, "suricata", line,
                   dest_ip=evt.get("dest_ip", SERVER_LAN_IP),
                   port=evt.get("dest_port"), service="suricata")
    e["signature"] = sig
    return [e]


PARSERS = {
    "auth.log":          parse_auth,
    "syslog":            parse_syslog,
    "access.log":        parse_apache,
    "error.log":         lambda l: [],   # error.log tailed but not normalized in Phase 1
    "ufw.log":           parse_ufw,
    "eve.json":          parse_suricata,
}


def _parser_for(path):
    return PARSERS.get(os.path.basename(path))


# ── pre-flag dispatch (single-event signals) ──────────────────────────────────

def dispatch_preflags(evt):
    et = evt["event_type"]
    ip = evt["source_ip"]
    raw = evt.get("raw", "")

    if et == "account_created":
        write_preflag_ticket(ip, "R8", "high", "T1136", "Persistence", raw,
                             detail=evt.get("username"))
    elif et == "account_modified":
        write_preflag_ticket(ip, "R8", "high", "T1098", "Persistence", raw)
    elif et == "service_stopped" and evt.get("_defense_tool"):
        write_preflag_ticket(ip, "R10", "critical", "T1562.001", "Defense Evasion", raw,
                             detail=evt.get("_defense_tool"))
    elif et == "account_deleted":
        write_preflag_ticket(ip, "R15", "high", "T1531", "Impact", raw)
    elif et == "startup_script_modified":
        write_preflag_ticket(ip, "R17", "high", "T1037", "Persistence", raw)
    elif et == "history_cleared":
        write_preflag_ticket(ip, "R18", "medium", "T1070.003", "Defense Evasion", raw)


# ── watchers (rotation-safe) ──────────────────────────────────────────────────

def watch_file(path):
    parser = _parser_for(path)
    if not parser:
        return
    reported_missing = False
    while True:
        try:
            with open(path) as f:
                reported_missing = False
                f.seek(0, 2)
                cur_ino = os.fstat(f.fileno()).st_ino
                while True:
                    line = f.readline()
                    if line:
                        try:
                            for evt in (parser(line) or []):
                                emit(evt)
                                dispatch_preflags(evt)
                            if not parser(line) and _is_interesting(line):
                                log_unparsed(path, line)
                        except Exception:
                            pass
                        continue
                    time.sleep(0.5)
                    try:
                        st = os.stat(path)
                    except FileNotFoundError:
                        break
                    if st.st_ino != cur_ino or st.st_size < f.tell():
                        break
        except FileNotFoundError:
            if not reported_missing:
                emit(make_event(SERVER_LAN_IP, "alert", "triage", "source unavailable: " + path))
                reported_missing = True
            time.sleep(30)
        except Exception:
            time.sleep(30)


def _is_interesting(line):
    # heuristic: only record clearly security-relevant unparsed lines to reduce noise
    keys = ("Failed", "Accepted", "sudo", "useradd", "usermod", "POST",
            "UFW", "systemctl", "cron", "alert")
    return any(k in line for k in keys)


def monitor_file_sizes():
    """R7 pre-flag: in-place log truncation (rotation excluded via inode check)."""
    track = _read_json(SIZE_TRACK_PATH, {})
    while True:
        time.sleep(SIZE_POLL_SECS)
        for path in LOG_SOURCES:
            try:
                st = os.stat(path)
                cur = {"size": st.st_size, "ino": st.st_ino}
                prev = track.get(path)
                if isinstance(prev, dict) and prev.get("ino") is not None:
                    rotated = prev["ino"] != cur["ino"]
                    if not rotated and cur["size"] < prev.get("size", cur["size"]):
                        write_preflag_ticket(
                            SERVER_LAN_IP, "R7", "high", "T1070.002", "Defense Evasion",
                            "LOG TAMPER: {} truncated {} -> {} bytes".format(
                                path, prev.get("size"), cur["size"]),
                            detail=path)
                track[path] = cur
            except FileNotFoundError:
                pass
        _write_json(SIZE_TRACK_PATH, track)


# ── entry points ──────────────────────────────────────────────────────────────

def run():
    """Called by the orchestrator. Starts all watchers as daemon threads."""
    os.makedirs(TICKETS_DIR, exist_ok=True)
    threads = []
    for path in LOG_SOURCES:
        t = threading.Thread(target=watch_file, args=(path,), daemon=True,
                             name="triage-" + os.path.basename(path))
        t.start()
        threads.append(t)
    st = threading.Thread(target=monitor_file_sizes, daemon=True, name="triage-size")
    st.start()
    threads.append(st)
    return threads


if __name__ == "__main__":
    # Standalone test mode — run Triage V2 on its own and watch ip_stats.json fill.
    print("[TRIAGE-V2] starting | sandbox={} | server={}".format(SANDBOX_MODE, SERVER_LAN_IP))
    print("[TRIAGE-V2] sources: {}".format(", ".join(LOG_SOURCES)))
    print("[TRIAGE-V2] ip_stats -> {}".format(IP_STATS_PATH))
    run()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n[TRIAGE-V2] stopped")
