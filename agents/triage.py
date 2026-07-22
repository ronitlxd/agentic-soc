#!/usr/bin/env python3
"""
TRIAGE — Pure log collector.
Tails all log sources, parses events into structured format,
writes to findings buffer. No judgment. No filtering. No severity.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone

BUFFER_PATH    = os.path.expanduser("~/.hermes/soc/findings_buffer.json")
SIZE_TRACK_PATH = os.path.expanduser("~/.hermes/soc/log_sizes.json")
BUFFER_MAX_AGE = 86400  # 24 hours rolling window

LOG_SOURCES = [
    "/var/log/suricata/eve.json",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/ufw.log",
    "/var/log/syslog",
    "/var/www/nextcloud/data/nextcloud.log",
]

_buffer_lock = threading.Lock()


# ── helpers ───────────────────────────────────────────────────────────────────

def now():
    return datetime.now(timezone.utc).isoformat()


def load_buffer():
    try:
        with open(BUFFER_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"entries": []}


def save_buffer(data):
    os.makedirs(os.path.dirname(BUFFER_PATH), exist_ok=True)
    tmp = BUFFER_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, BUFFER_PATH)


def write_entry(entry):
    with _buffer_lock:
        data = load_buffer()
        cutoff = datetime.now(timezone.utc).timestamp() - BUFFER_MAX_AGE
        data["entries"] = [
            e for e in data["entries"]
            if _ts(e) > cutoff
        ]
        data["entries"].append(entry)
        save_buffer(data)


def _ts(entry):
    try:
        return datetime.fromisoformat(entry["timestamp"]).timestamp()
    except (KeyError, ValueError):
        return 0


# ── parsers ───────────────────────────────────────────────────────────────────

# Signatures to drop at parse time — known-good internal traffic.
# Dedup+escalation still applies to everything else.
SUPPRESS_SIGS = {
    "ET HUNTING Telegram API Domain in DNS Lookup",
    "ET HUNTING Observed Telegram API Domain (api .telegram .org in TLS SNI)",
}


def parse_suricata(line):
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None

    etype = evt.get("event_type")

    if etype == "alert":
        alert   = evt.get("alert", {})
        sig     = alert.get("signature", "unknown")

        # Drop known-good internal noise at ingest
        if any(sig.startswith(s) for s in SUPPRESS_SIGS):
            return None

        sev_map = {"1": "critical", "2": "high", "3": "medium"}
        return {
            "timestamp":  now(),
            "source":     "suricata",
            "event_type": "alert",
            "src_ip":     evt.get("src_ip", "unknown"),
            "dst_ip":     evt.get("dest_ip", "unknown"),
            "dst_port":   evt.get("dest_port"),
            "signature":  sig,
            "severity":   sev_map.get(str(alert.get("severity", 3)), "medium"),
            "category":   alert.get("category", ""),
            "raw":        line.strip()[:500],
        }

    if etype == "flow":
        # Needed for Rules 3 (C2) and 5 (exfiltration)
        return {
            "timestamp":      now(),
            "source":         "suricata",
            "event_type":     "flow",
            "src_ip":         evt.get("src_ip", "unknown"),
            "dst_ip":         evt.get("dest_ip", "unknown"),
            "dst_port":       evt.get("dest_port"),
            "bytes_toserver": evt.get("flow", {}).get("bytes_toserver", 0),
            "bytes_toclient": evt.get("flow", {}).get("bytes_toclient", 0),
            "raw":            line.strip()[:300],
        }

    return None


def parse_auth(line):
    patterns = [
        (re.compile(r"BREAK-IN ATTEMPT"),
            "break_in", None, None),
        (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
            "auth_fail", 1, 2),
        (re.compile(r"Invalid user (\S+) from (\S+)"),
            "auth_fail", 1, 2),
        (re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
            "auth_success", 1, 2),
        (re.compile(r"authentication failure.*?(?:user=(\S+))?"),
            "auth_fail", 1, None),
        (re.compile(r"session opened for user (\S+)"),
            "session_open", 1, None),
        (re.compile(r"session closed for user (\S+)"),
            "session_close", 1, None),
        (re.compile(r"sudo:.*COMMAND=(.+)"),
            "sudo_command", None, None),
        (re.compile(r"new user: name=(\S+)"),
            "new_user", 1, None),
    ]
    for pattern, event_type, user_group, ip_group in patterns:
        m = pattern.search(line)
        if m:
            username = m.group(user_group) if user_group and m.lastindex and m.lastindex >= user_group else "unknown"
            src_ip   = m.group(ip_group)   if ip_group   and m.lastindex and m.lastindex >= ip_group   else "unknown"
            return {
                "timestamp":  now(),
                "source":     "auth",
                "event_type": event_type,
                "src_ip":     src_ip,
                "username":   username,
                "raw":        line.strip()[:500],
            }
    return None


def parse_apache(line):
    ip_re      = re.compile(r"^(\S+)")
    status_re  = re.compile(r'"[A-Z]+ (\S+) HTTP/[\d.]+" (\d{3})')
    scanner_re = re.compile(
        r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|hydra|metasploit)",
        re.I)
    bytes_re   = re.compile(r'" \d{3} (\d+)')

    m_status = status_re.search(line)
    if not m_status:
        return None

    status    = int(m_status.group(2))
    path      = m_status.group(1)
    src_ip    = (ip_re.match(line) or type("", (), {"group": lambda s, n: "unknown"})()).group(1)
    bytes_out = int(bytes_re.search(line).group(1)) if bytes_re.search(line) else 0
    scanner   = (scanner_re.search(line) or type("", (), {"group": lambda s, n: None})()).group(1)

    event_type = "scanner" if scanner else ("web_error" if status >= 500 else "web_request")

    return {
        "timestamp":  now(),
        "source":     "apache",
        "event_type": event_type,
        "src_ip":     src_ip,
        "path":       path,
        "status":     status,
        "bytes_sent": bytes_out,
        "scanner":    scanner,
        "raw":        line.strip()[:500],
    }


def parse_ufw(line):
    if "UFW BLOCK" not in line and "UFW ALLOW" not in line:
        return None
    src_re = re.compile(r"SRC=(\S+)")
    dst_re = re.compile(r"DST=(\S+)")
    dpt_re = re.compile(r"DPT=(\d+)")

    def grp(pattern, default="unknown"):
        m = pattern.search(line)
        return m.group(1) if m else default

    return {
        "timestamp":  now(),
        "source":     "ufw",
        "event_type": "firewall_block" if "UFW BLOCK" in line else "firewall_allow",
        "src_ip":     grp(src_re),
        "dst_ip":     grp(dst_re),
        "dst_port":   int(grp(dpt_re, "0")),
        "raw":        line.strip()[:500],
    }


def parse_syslog(line):
    patterns = [
        (re.compile(r"CRON.*CMD\s+(.+)"),           "cron_execution"),
        (re.compile(r"systemd.*Started (.+)"),        "service_started"),
        (re.compile(r"systemd.*Stopped (.+)"),        "service_stopped"),
        (re.compile(r"kernel.*OOM"),                  "oom_kill"),
        (re.compile(r"useradd|groupadd|userdel"),     "account_change"),
        (re.compile(r"sshd.*Received disconnect"),    "ssh_disconnect"),
    ]
    for pattern, event_type in patterns:
        m = pattern.search(line)
        if m:
            return {
                "timestamp":  now(),
                "source":     "syslog",
                "event_type": event_type,
                "src_ip":     "local",
                "detail":     (m.group(1) if m.lastindex else line.strip()[:100]),
                "raw":        line.strip()[:500],
            }
    return None


def parse_nextcloud(line):
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None
    level = evt.get("level", 0)
    if level < 2:  # 0=debug, 1=info, 2=warning, 3=error, 4=fatal
        return None
    return {
        "timestamp":  now(),
        "source":     "nextcloud",
        "event_type": "nextcloud_event",
        "src_ip":     evt.get("remoteAddr", "unknown"),
        "username":   evt.get("user", "unknown"),
        "message":    evt.get("message", "")[:200],
        "level":      level,
        "raw":        line.strip()[:500],
    }


PARSERS = {
    "/var/log/suricata/eve.json":               parse_suricata,
    "/var/log/auth.log":                         parse_auth,
    "/var/log/apache2/access.log":               parse_apache,
    "/var/log/apache2/error.log":                lambda l: None,
    "/var/log/ufw.log":                          parse_ufw,
    "/var/log/syslog":                           parse_syslog,
    "/var/www/nextcloud/data/nextcloud.log":     parse_nextcloud,
}


# ── watchers ─────────────────────────────────────────────────────────────────

def watch_file(path):
    parser = PARSERS.get(path)
    if not parser:
        return
    try:
        with open(path) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    entry = parser(line)
                    if entry:
                        write_entry(entry)
                except Exception:
                    pass
    except FileNotFoundError:
        write_entry({
            "timestamp":  now(),
            "source":     "triage",
            "event_type": "system",
            "src_ip":     "local",
            "detail":     "source unavailable: {}".format(path),
            "raw":        "",
        })
    except Exception as e:
        write_entry({
            "timestamp":  now(),
            "source":     "triage",
            "event_type": "system",
            "src_ip":     "local",
            "detail":     "watcher crashed: {} — {}".format(path, str(e)),
            "raw":        "",
        })


def monitor_file_sizes():
    """Detect log file shrinkage — supports Rule 7 (log tampering)."""
    size_track = {}
    try:
        with open(SIZE_TRACK_PATH) as f:
            size_track = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    while True:
        time.sleep(60)
        for path in LOG_SOURCES:
            try:
                current  = os.path.getsize(path)
                previous = size_track.get(path, current)
                if current < previous:
                    write_entry({
                        "timestamp":     now(),
                        "source":        "triage",
                        "event_type":    "log_shrink",
                        "src_ip":        "local",
                        "path":          path,
                        "previous_size": previous,
                        "current_size":  current,
                        "raw":           "LOG TAMPER SUSPECTED: {} shrunk {} -> {} bytes".format(
                            path, previous, current),
                    })
                size_track[path] = current
            except FileNotFoundError:
                pass

        tmp = SIZE_TRACK_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(size_track, f)
        os.replace(tmp, SIZE_TRACK_PATH)


# ── entry point ───────────────────────────────────────────────────────────────

def run():
    """Called by orchestrator. Starts all watchers as daemon threads."""
    threads = []
    for path in LOG_SOURCES:
        t = threading.Thread(
            target=watch_file,
            args=(path,),
            daemon=True,
            name="triage-{}".format(os.path.basename(path)),
        )
        t.start()
        threads.append(t)

    size_t = threading.Thread(
        target=monitor_file_sizes,
        daemon=True,
        name="triage-size-monitor",
    )
    size_t.start()
    threads.append(size_t)

    return threads
