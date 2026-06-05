# SOC V2 — Coverage Expansion Implementation Guide
**Target system:** Ubuntu Server 24.04 LTS | user: `user` | IP: `10.0.0.108`  
**Working directory:** `/home/user/.hermes/soc/`  
**Purpose:** Step-by-step implementation guide for each coverage tier, ordered by when to implement.  
**Audience:** Claude Code — implement exactly as written, in order, one tier at a time.

---

## Implementation order and dependencies

```
Tier 1 → no dependencies, implement first
Tier 2 → no dependencies, implement alongside Tier 1
Tier 3 (Suricata flow) → implement after Tier 1+2 are verified working
Tier 4 (Wazuh) → implement after Tier 3, requires Wazuh already installed
Tier 5 (Cowrie) → implement LAST, only after full pipeline is stable end-to-end
```

Do not skip ahead. Each tier builds on verified working state of the previous.

---

---

# TIER 1 — New rules using existing log sources
**When:** Implement first, before any other tier.  
**Dependency:** None. All log sources already tailed by Triage.  
**What changes:** Add new event_types to Triage normalizer + new rules to Investigator.

---

## Tier 1 — Step 1: Add new event_types to Triage normalizer

Triage's normalizer must classify these new event patterns. Add to the Triage parsing module.

### auth.log additions

File: `triage_agent.py` (or equivalent Triage module)  
Location of change: inside the `parse_auth_log_line(line)` function

```python
# --- ADD THESE TO auth.log PARSER ---

# T1110.003 — Password Spraying
# Pattern: same IP, multiple DIFFERENT usernames, few failures each
# Triage flags at ingest when username is new for this IP
if "Failed password for" in line:
    username = extract_username(line)
    source_ip = extract_ip(line)
    # emit event_type = "auth_fail"
    # also update ip_stats: failed_usernames set for this IP
    # spraying detection happens in Investigator (needs count across events)

# T1078.001 — Default Account Usage
# Pattern: auth success with a default/known-weak username
DEFAULT_USERNAMES = {"root", "admin", "ubuntu", "pi", "oracle",
                     "test", "guest", "user", "postgres", "mysql",
                     "ftpuser", "www-data", "nobody", "daemon"}
if "Accepted" in line and "for" in line:
    username = extract_username(line)
    if username in DEFAULT_USERNAMES:
        emit_event(event_type="default_account_login", username=username, ...)

# T1548.003 — Sudo Abuse
# Pattern: sudo failures OR sudo used by unexpected user
if "sudo:" in line and "authentication failure" in line:
    emit_event(event_type="sudo_fail", ...)
if "sudo:" in line and "command not allowed" in line:
    emit_event(event_type="sudo_denied", ...)

# T1531 — Account Deleted
if "userdel" in line or "deluser" in line:
    emit_event(event_type="account_deleted", ...)
```

### syslog additions

File: `triage_agent.py`  
Location of change: inside `parse_syslog_line(line)` function

```python
# --- ADD THESE TO syslog PARSER ---

# T1543.002 — New Systemd Service Created
# Pattern: systemctl enable for a service not in a known whitelist
KNOWN_SERVICES = {
    "splunk", "suricata", "wazuh-agent", "apache2", "mariadb",
    "nextcloud", "ssh", "ufw", "tailscaled", "lm-studio",
    "homelab-dashboard", "photo-gallery", "hermes"
}
if "systemctl" in line and "enable" in line:
    service_name = extract_service_name(line)
    if service_name not in KNOWN_SERVICES:
        emit_event(event_type="unknown_service_enabled",
                   service=service_name, ...)

# T1037 — Boot/Logon Script Modified
# Pattern: writes to startup script locations
STARTUP_PATHS = [
    "/etc/rc.local", "/etc/profile", "/etc/profile.d/",
    "/etc/bash.bashrc", "/root/.bashrc", "/root/.profile",
    "/etc/environment"
]
if any(path in line for path in STARTUP_PATHS) and (
    "modified" in line or "created" in line or "write" in line
):
    emit_event(event_type="startup_script_modified", ...)

# T1070.003 — Clear Command History
# Pattern: HISTFILE redirected to null or history cleared
if "HISTFILE=/dev/null" in line or "HISTSIZE=0" in line:
    emit_event(event_type="history_cleared", ...)
if "history -c" in line or "history -w /dev/null" in line:
    emit_event(event_type="history_cleared", ...)
```

### Apache/Nextcloud access.log additions

File: `triage_agent.py`  
Location of change: inside `parse_apache_access_line(line)` function

```python
# --- ADD THESE TO Apache access.log PARSER ---

# T1595.002 — Active Scanning / Vulnerability Scanning
# Pattern: same IP hitting many distinct endpoints rapidly
# Triage: track unique_paths_hit per IP in ip_stats
# (scanning detection happens in Investigator using that count)

# Update ip_stats on every web request:
ip_stats[source_ip]["unique_paths_hit"].add(request_path)
ip_stats[source_ip]["last_request_time"] = timestamp

# T1110 — Nextcloud Credential Brute Force via Web
# Pattern: repeated POST to /index.php/login or Nextcloud login endpoint
NEXTCLOUD_LOGIN_PATHS = {
    "/index.php/login", "/login", "/remote.php/dav",
    "/ocs/v1.php", "/ocs/v2.php"
}
if request_method == "POST" and request_path in NEXTCLOUD_LOGIN_PATHS:
    if response_code in {401, 403}:
        emit_event(event_type="web_auth_fail",
                   service="nextcloud", path=request_path, ...)
    elif response_code == 200:
        emit_event(event_type="web_auth_success",
                   service="nextcloud", path=request_path, ...)
```

---

## Tier 1 — Step 2: Update ip_stats schema

Add new fields to Triage's ip_stats object to support new rules.

File: wherever ip_stats is initialized in `triage_agent.py`

```python
# Add these fields to the default ip_stats entry for each new IP:
ip_stats_template = {
    # --- existing fields ---
    "ip_type": "external",
    "first_seen": None,
    "last_seen": None,
    "auth_failures": 0,
    "auth_successes": 0,
    "success_username": None,
    "failed_usernames": [],        # list, for spray detection
    "scan_targets": [],
    "services_hit": [],
    "active_hours_utc": [],
    "known_ip": False,
    "bytes_out": 0,
    "web_posts": 0,
    "web_post_to_unknown_path": False,
    "web_200_response": False,
    "account_events": 0,
    "cron_events": 0,
    "service_stop_events": 0,

    # --- NEW fields for Tier 1 ---
    "default_account_login": False,       # T1078.001
    "sudo_failures": 0,                   # T1548.003
    "sudo_denied": False,                 # T1548.003
    "account_deleted": False,             # T1531
    "unknown_service_enabled": False,     # T1543.002
    "unknown_service_name": None,         # T1543.002
    "startup_script_modified": False,     # T1037
    "history_cleared": False,             # T1070.003
    "unique_paths_hit": set(),            # T1595.002 (convert to list for JSON)
    "web_auth_failures_nextcloud": 0,     # T1110 web
    "web_auth_success_nextcloud": False,  # T1110 web
}
```

Note: `unique_paths_hit` is a Python set in memory. Convert to `len(set)` integer when writing to `ip_stats.json` — sets are not JSON serializable.

---

## Tier 1 — Step 3: Add new Investigator rules

File: `investigator_agent.py`  
Location: inside the main rule-checking loop over `ip_stats`

```python
# R12 — Password Spraying (T1110.003)
# Same IP, 5+ unique usernames attempted, average <3 failures per username
# Indicates spray (many targets, few attempts each) vs brute (one target, many attempts)
unique_usernames = len(set(stats["failed_usernames"]))
if (unique_usernames >= 5
        and stats["auth_failures"] >= 5
        and stats["auth_failures"] / unique_usernames < 3.0):
    open_ticket(ip, "R12", "high", stats,
                technique="T1110.003", tactic="Credential Access")

# R13 — Default Account Login (T1078.001)
if stats["default_account_login"]:
    open_ticket(ip, "R13", "high", stats,
                technique="T1078.001", tactic="Initial Access")

# R14 — Sudo Abuse (T1548.003)
# 3+ sudo failures OR sudo explicitly denied
if stats["sudo_failures"] >= 3 or stats["sudo_denied"]:
    open_ticket(ip, "R14", "medium", stats,
                technique="T1548.003", tactic="Privilege Escalation")

# R15 — Account Deleted (T1531)
# Removing accounts = covering tracks or denying access to legitimate users
if stats["account_deleted"]:
    open_ticket(ip, "R15", "high", stats,
                technique="T1531", tactic="Impact")

# R16 — Unknown Service Enabled (T1543.002)
if stats["unknown_service_enabled"]:
    open_ticket(ip, "R16", "medium", stats,
                technique="T1543.002", tactic="Persistence",
                note=stats["unknown_service_name"])

# R17 — Startup Script Modified (T1037)
if stats["startup_script_modified"]:
    open_ticket(ip, "R17", "high", stats,
                technique="T1037", tactic="Persistence")

# R18 — History Cleared (T1070.003)
if stats["history_cleared"]:
    open_ticket(ip, "R18", "medium", stats,
                technique="T1070.003", tactic="Defense Evasion")

# R19 — Vulnerability Scanning (T1595.002)
# 20+ distinct paths hit by same IP in last 5 min window
if (stats["unique_paths_hit"] >= 20
        and time_delta(stats["first_seen"], stats["last_seen"]) < 300):
    open_ticket(ip, "R19", "medium", stats,
                technique="T1595.002", tactic="Reconnaissance")

# R20 — Nextcloud Web Brute Force (T1110)
if stats["web_auth_failures_nextcloud"] >= 10:
    open_ticket(ip, "R20", "medium", stats,
                technique="T1110", tactic="Credential Access")

# R21 — Nextcloud Web Brute Force Success (T1110, T1078)
if (stats["web_auth_failures_nextcloud"] >= 5
        and stats["web_auth_success_nextcloud"]):
    open_ticket(ip, "R21", "high", stats,
                technique="T1078", tactic="Initial Access")
```

---

## Tier 1 — Step 4: Add Triage pre-flags for single-event signals

R15 (account deleted), R17 (startup script modified), and R18 (history cleared) are high-confidence single-event signals. Add them to Triage pre-flagging alongside R7, R8, R10.

File: `triage_agent.py` — inside the pre-flag check after event parsing

```python
# Existing pre-flags: R7, R8, R10
# Add:

if event_type == "account_deleted":
    # R15 pre-flag
    write_preflag_ticket(source_ip, rule="R15", severity="high",
                         technique="T1531", tactic="Impact",
                         raw=line)

if event_type == "startup_script_modified":
    # R17 pre-flag
    write_preflag_ticket(source_ip, rule="R17", severity="high",
                         technique="T1037", tactic="Persistence",
                         raw=line)

if event_type == "history_cleared":
    # R18 pre-flag
    write_preflag_ticket(source_ip, rule="R18", severity="medium",
                         technique="T1070.003", tactic="Defense Evasion",
                         raw=line)
```

---

## Tier 1 — Verification checklist

After implementing Tier 1, verify before moving on:

```bash
# 1. Confirm ip_stats.json contains new fields
cat ~/.hermes/soc/ip_stats.json | python3 -m json.tool | grep "sudo_failures"

# 2. Simulate a spray attempt in auth.log
# Add test lines with 6 different usernames from same IP — confirm R12 fires

# 3. Check Triage is parsing unknown service names
logger "systemctl enable evilservice"   # writes to syslog
# Confirm ip_stats shows unknown_service_enabled: true

# 4. Confirm Investigator opens tickets for new rules by checking ticket store
ls ~/.hermes/soc/tickets/
```

---

---

# TIER 2 — Fix Suricata flow logging
**When:** After Tier 1 is verified working.  
**Dependency:** Suricata already installed and running on `wlp3s0`.  
**What changes:** Enable flow logging in suricata.yaml. Re-activates R3 and R5.

---

## Tier 2 — Step 1: Check current Suricata eve.json output

```bash
# Check what Suricata is currently logging
sudo tail -5 /var/log/suricata/eve.json | python3 -m json.tool | grep '"type"'

# If you see only "alert" and "stats" — flow is off
# If you see "flow" — it's already on, skip to verification
```

---

## Tier 2 — Step 2: Edit suricata.yaml

```bash
sudo nano /etc/suricata/suricata.yaml
```

Find the `outputs` → `eve-log` → `types` section. It will look like this:

```yaml
# BEFORE (approximate — may vary):
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - stats:
            interval: 10
```

Change to:

```yaml
# AFTER — add flow, http, dns, tls:
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - flow:
            all-versions: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - stats:
            interval: 10
```

Save and exit.

---

## Tier 2 — Step 3: Restart Suricata

```bash
sudo systemctl restart suricata
sleep 5
sudo systemctl status suricata   # confirm active (running)
```

---

## Tier 2 — Step 4: Verify flow events appear

```bash
# Wait 60 seconds then check
sleep 60
sudo grep '"event_type":"flow"' /var/log/suricata/eve.json | head -3 | python3 -m json.tool
```

A flow record looks like:
```json
{
  "timestamp": "2026-07-26T03:14:00.123456+0000",
  "event_type": "flow",
  "src_ip": "45.33.32.156",
  "dest_ip": "10.0.0.108",
  "proto": "TCP",
  "flow": {
    "bytes_toserver": 1024,
    "bytes_toclient": 52428800,
    "pkts_toserver": 10,
    "pkts_toclient": 40000
  }
}
```

`bytes_toclient` = bytes sent FROM your server TO the external IP = outbound data. This is what R5 uses.

---

## Tier 2 — Step 5: Add flow parsing to Triage

File: `triage_agent.py`  
Add a new parser for Suricata flow events alongside the existing alert parser.

```python
def parse_suricata_flow(event: dict) -> dict | None:
    """
    Parse a Suricata flow record from eve.json.
    Returns normalized event or None if not relevant.
    """
    if event.get("event_type") != "flow":
        return None

    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")
    flow = event.get("flow", {})

    bytes_out = flow.get("bytes_toclient", 0)   # outbound from our server
    bytes_in = flow.get("bytes_toserver", 0)    # inbound to our server
    proto = event.get("proto", "")

    # Only care about flows involving our server
    if dest_ip != "10.0.0.108" and src_ip != "10.0.0.108":
        return None

    # Determine direction
    if src_ip == "10.0.0.108":
        external_ip = dest_ip
        direction = "outbound"
    else:
        external_ip = src_ip
        direction = "inbound"

    # Update ip_stats for this IP
    ip_stats[external_ip]["bytes_out"] += bytes_out
    ip_stats[external_ip]["bytes_in"] = (
        ip_stats[external_ip].get("bytes_in", 0) + bytes_in
    )

    return {
        "event_type": "flow",
        "source_ip": external_ip,
        "dest_ip": "10.0.0.108",
        "ip_type": classify_ip(external_ip),
        "direction": direction,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "proto": proto,
        "log_source": "suricata_flow",
        "timestamp": event.get("timestamp"),
        "raw": json.dumps(event)
    }
```

---

## Tier 2 — Step 6: Re-activate R3 and R5 in Investigator

These rules were removed in V2 because Suricata flow was off. Now re-add them.

File: `investigator_agent.py`

```python
# R3 — Login then C2 (T1078, T1071)
# Auth success followed by outbound connection within 2 minutes
# Requires: auth_successes > 0 AND bytes_out > 0 AND
#           time between auth_success and first outbound flow < 120s
if (stats["auth_successes"] >= 1
        and stats.get("bytes_out", 0) > 0
        and stats.get("seconds_to_first_outbound") is not None
        and stats["seconds_to_first_outbound"] < 120):
    open_ticket(ip, "R3", "high", stats,
                technique="T1071", tactic="Command and Control")

# R5 — Exfiltration (T1048)
# New IP auth success + >50MB outbound in <10 min
BYTES_50MB = 52_428_800
if (stats["auth_successes"] >= 1
        and not stats["known_ip"]
        and stats.get("bytes_out", 0) > BYTES_50MB
        and time_delta(stats["first_seen"], stats["last_seen"]) < 600):
    open_ticket(ip, "R5", "high", stats,
                technique="T1048", tactic="Exfiltration")
```

Also add `seconds_to_first_outbound` tracking to Triage — record the timestamp of first auth_success per IP and first outbound flow per IP, then compute the delta.

---

## Tier 2 — Verification checklist

```bash
# 1. Confirm flow records in eve.json
sudo grep '"event_type":"flow"' /var/log/suricata/eve.json | wc -l
# Should be increasing over time

# 2. Confirm ip_stats shows bytes_out values
cat ~/.hermes/soc/ip_stats.json | python3 -m json.tool | grep "bytes_out"

# 3. To test R5: generate a large outbound transfer from a new IP session
#    (do this in a controlled test — e.g. SCP a large file from a new client)
#    Confirm ticket opens with rule R5

# 4. Suricata should still be running
sudo systemctl status suricata
```

---

---

# TIER 3 — Enable auditd
**When:** After Tier 2 is verified working.  
**Dependency:** None — auditd is already in Ubuntu 24.04 base repos.  
**What changes:** Install and configure auditd. Add new Triage log tailer. Add new rules.

---

## Tier 3 — Step 1: Install auditd

```bash
sudo apt update
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd   # confirm active
```

---

## Tier 3 — Step 2: Create audit rules file

```bash
sudo nano /etc/audit/rules.d/soc_v2.rules
```

Paste exactly:

```bash
# SOC V2 audit rules
# Generated for user@10.0.0.108

# Clear existing rules on load
-D

# Buffer size (increase if seeing backlog warnings in /var/log/syslog)
-b 8192

# Failure mode: 1 = log failures, 2 = kernel panic on failure (use 1)
-f 1

# --- Credential Access (T1003.008) ---
# Reading /etc/shadow = credential dump attempt
-w /etc/shadow -p r -k credential_dump
-w /etc/gshadow -p r -k credential_dump
-w /etc/passwd -p wa -k passwd_modification

# --- Privilege Escalation (T1548.001, T1548.003) ---
# Setuid/setgid bit changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat \
   -F auid>=1000 -F auid!=4294967295 -k permission_change
# Sudoers modification
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# --- Persistence (T1098.004) ---
# SSH authorized_keys modification
-w /root/.ssh -p wa -k ssh_key_modification
-w /home/user/.ssh -p wa -k ssh_key_modification

# --- Execution (T1059.004) ---
# Shell execution — log all execve syscalls from non-root users
-a always,exit -F arch=b64 -S execve \
   -F auid>=1000 -F auid!=4294967295 -k shell_execution

# --- Defense Evasion (T1222) ---
# Unusual file permission changes (chmod to 777 or removing execute)
-a always,exit -F arch=b64 -S chmod \
   -F a1=0777 -k world_writable_set

# --- Lateral Movement (T1021.004) ---
# SSH config modification
-w /etc/ssh/sshd_config -p wa -k ssh_config_modification

# --- Persistence — Kernel level (T1547.006) ---
# Kernel module loading
-w /sbin/insmod -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_module

# Make rules immutable until next reboot (comment out during development)
# -e 2
```

Load the rules:
```bash
sudo augenrules --load
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l | head -20
```

---

## Tier 3 — Step 3: Confirm audit log location and format

```bash
# Audit log location
ls -la /var/log/audit/audit.log

# Sample a record
sudo tail -5 /var/log/audit/audit.log
```

A raw auditd record looks like:
```
type=SYSCALL msg=audit(1753500000.123:456): arch=c000003e syscall=2 
success=yes exit=3 a0=7f... a1=0 a2=1b6 a3=0 items=1 ppid=1234 
pid=5678 auid=1001 uid=0 gid=0 euid=0 key="credential_dump"
```

The `key=` field is what your rules tag with — this is how Triage identifies which rule triggered.

---

## Tier 3 — Step 4: Add auditd Triage tailer and parser

File: `triage_agent.py`  
Add alongside existing log tailers.

```python
# New log source: auditd
AUDIT_LOG_PATH = "/var/log/audit/audit.log"

def parse_audit_line(line: str) -> dict | None:
    """
    Parse a raw auditd log line.
    Returns normalized event dict or None if not relevant to our rules.
    """
    # Extract key fields using regex
    import re

    key_match = re.search(r'key="([^"]+)"', line)
    if not key_match:
        return None   # not one of our watched rules

    key = key_match.group(1)
    
    # Extract common fields
    pid_match = re.search(r'\bpid=(\d+)', line)
    uid_match = re.search(r'\bauid=(\d+)', line)
    success_match = re.search(r'\bsuccess=(\w+)', line)
    syscall_match = re.search(r'\bsyscall=(\d+)', line)
    ts_match = re.search(r'audit\((\d+\.\d+)', line)

    timestamp = ts_match.group(1) if ts_match else None
    success = success_match.group(1) if success_match else "unknown"
    auid = uid_match.group(1) if uid_match else "unknown"

    # Map audit key to event_type
    KEY_TO_EVENT_TYPE = {
        "credential_dump":        "credential_access",
        "passwd_modification":    "passwd_modified",
        "permission_change":      "permission_changed",
        "sudoers_modification":   "sudoers_modified",
        "ssh_key_modification":   "ssh_key_modified",
        "shell_execution":        "shell_executed",
        "world_writable_set":     "world_writable_set",
        "ssh_config_modification":"ssh_config_modified",
        "kernel_module":          "kernel_module_event",
    }

    event_type = KEY_TO_EVENT_TYPE.get(key)
    if not event_type:
        return None

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source_ip": "127.0.0.1",   # auditd events are local
        "dest_ip": "10.0.0.108",
        "ip_type": "internal",
        "username": auid,            # numeric UID — look up via /etc/passwd if needed
        "service": "auditd",
        "event_type": event_type,
        "audit_key": key,
        "success": success,
        "log_source": "auditd",
        "raw": line.strip()
    }
```

Note: auditd events are local (no external source_ip). They are indexed by `audit_key` in ip_stats under a special `"local"` IP entry.

---

## Tier 3 — Step 5: Add auditd ip_stats tracking

Since auditd events are local, add a `"local"` key to ip_stats for tracking local activity:

```python
# In ip_stats initialization, always create a "local" entry:
ip_stats["local"] = {
    "ip_type": "internal",
    "credential_dump_attempts": 0,     # T1003.008
    "passwd_modified": False,          # T1003
    "permission_changes": 0,           # T1222
    "sudoers_modified": False,         # T1548.003
    "ssh_key_modified": False,         # T1098.004
    "shell_executions": 0,             # T1059.004
    "world_writable_files_set": 0,     # T1222
    "ssh_config_modified": False,      # T1021.004
    "kernel_module_events": 0,         # T1547.006
}
```

Update these fields as auditd events arrive.

---

## Tier 3 — Step 6: Add auditd Investigator rules

File: `investigator_agent.py`  
Add these rules — they check `ip_stats["local"]` instead of per-IP entries.

```python
local = ip_stats.get("local", {})

# R22 — Credential Dump Attempt (T1003.008)
if local.get("credential_dump_attempts", 0) >= 1:
    open_ticket("local", "R22", "critical", local,
                technique="T1003.008", tactic="Credential Access")

# R23 — Sudoers File Modified (T1548.003)
if local.get("sudoers_modified", False):
    open_ticket("local", "R23", "critical", local,
                technique="T1548.003", tactic="Privilege Escalation")

# R24 — SSH Authorized Keys Modified (T1098.004)
if local.get("ssh_key_modified", False):
    open_ticket("local", "R24", "high", local,
                technique="T1098.004", tactic="Persistence")

# R25 — Kernel Module Loaded (T1547.006)
if local.get("kernel_module_events", 0) >= 1:
    open_ticket("local", "R25", "high", local,
                technique="T1547.006", tactic="Persistence")

# R26 — World-Writable Files Set (T1222)
if local.get("world_writable_files_set", 0) >= 1:
    open_ticket("local", "R26", "medium", local,
                technique="T1222", tactic="Defense Evasion")

# R27 — SSH Config Modified (T1021.004)
if local.get("ssh_config_modified", False):
    open_ticket("local", "R27", "high", local,
                technique="T1021.004", tactic="Lateral Movement")
```

---

## Tier 3 — Verification checklist

```bash
# 1. Confirm auditd is running and logging
sudo systemctl status auditd
sudo wc -l /var/log/audit/audit.log   # should be increasing

# 2. Test credential_dump rule fires
sudo cat /etc/shadow > /dev/null   # this should trigger the rule
sudo grep 'credential_dump' /var/log/audit/audit.log | tail -3

# 3. Confirm Triage parses audit events
# Check ip_stats["local"] in ip_stats.json after restart
cat ~/.hermes/soc/ip_stats.json | python3 -m json.tool | grep -A 10 '"local"'

# 4. Test R22 fires by reading /etc/shadow (as above)
# Wait one Investigator cycle, check ticket store
ls ~/.hermes/soc/tickets/ | grep R22
```

---

---

# TIER 4 — Fix and enable Wazuh
**When:** After Tier 3 is verified.  
**Dependency:** Wazuh already installed on the system (noted as installed but not alerting).  
**What changes:** Diagnose and fix Wazuh. Add Wazuh alert log as new Triage source.

---

## Tier 4 — Step 1: Diagnose current Wazuh state

```bash
# Check Wazuh manager status
sudo systemctl status wazuh-manager 2>/dev/null || \
sudo systemctl status wazuh-agent 2>/dev/null

# Check which Wazuh components are installed
dpkg -l | grep wazuh

# Check if alerts file exists and has content
sudo ls -la /var/ossec/logs/alerts/alerts.json 2>/dev/null || \
echo "alerts.json not found"

# Check Wazuh logs for errors
sudo tail -50 /var/ossec/logs/ossec.log 2>/dev/null | grep -i error
```

---

## Tier 4 — Step 2: Fix Wazuh based on diagnosis

### If Wazuh manager is not running:
```bash
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
sleep 10
sudo systemctl status wazuh-manager
```

### If alerts.json exists but is empty:
The manager may be running but the alert threshold is set too high.

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Find the `<alerts>` section and set minimum level to 3:
```xml
<alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
</alerts>
```

Restart:
```bash
sudo systemctl restart wazuh-manager
```

### If agent is installed but not connected to manager:
```bash
# If running manager+agent on same host (common homelab setup)
sudo /var/ossec/bin/agent-auth -m 127.0.0.1
sudo systemctl restart wazuh-agent
```

### Enable key Wazuh modules (edit ossec.conf):
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Ensure these modules are enabled:
```xml
<!-- File Integrity Monitoring — T1505.003, T1036 -->
<syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <!-- Monitor web directories for web shells -->
    <directories check_all="yes" realtime="yes">/var/www/html</directories>
    <directories check_all="yes" realtime="yes">/var/www/nextcloud</directories>
    <!-- Monitor critical system files -->
    <directories check_all="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>
    <directories check_all="yes">/home/user/.ssh</directories>
</syscheck>

<!-- Rootcheck — T1014 -->
<rootcheck>
    <disabled>no</disabled>
    <frequency>36000</frequency>
</rootcheck>

<!-- Log monitoring — ensure auth.log and syslog are included -->
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
</localfile>
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
</localfile>
<localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
</localfile>
```

Restart after edits:
```bash
sudo systemctl restart wazuh-manager
```

---

## Tier 4 — Step 3: Confirm alerts are flowing

```bash
# Wait 2–3 minutes then check
sudo tail -5 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

A Wazuh alert looks like:
```json
{
    "timestamp": "2026-07-26T03:14:22.123+0000",
    "rule": {
        "id": "5710",
        "description": "sshd: Attempt to login using a denied user",
        "level": 5,
        "groups": ["syslog", "sshd", "authentication_failed"]
    },
    "agent": {"id": "000", "name": "user"},
    "data": {"srcip": "45.33.32.156"},
    "full_log": "..."
}
```

Key fields: `rule.id`, `rule.level`, `rule.groups`, `data.srcip`.

---

## Tier 4 — Step 4: Add Wazuh alert parser to Triage

File: `triage_agent.py`

```python
WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"

# Wazuh rule groups that map to MITRE techniques
WAZUH_GROUP_MAP = {
    "authentication_failed":  ("auth_fail",      "T1110",     "Credential Access"),
    "authentication_success": ("auth_success",   "T1078",     "Initial Access"),
    "rootcheck":              ("rootkit_detect",  "T1014",     "Defense Evasion"),
    "syscheck":               ("file_modified",   "T1565",     "Impact"),
    "web_attack":             ("web_attack",      "T1190",     "Initial Access"),
    "sql_injection":          ("web_attack",      "T1190",     "Initial Access"),
    "php":                    ("web_shell_hint",  "T1505.003", "Persistence"),
}

def parse_wazuh_alert(alert: dict) -> dict | None:
    """
    Parse a Wazuh alert JSON record.
    Only process alerts with level >= 5 to avoid noise.
    """
    level = alert.get("rule", {}).get("level", 0)
    if level < 5:
        return None   # below threshold, ignore

    groups = alert.get("rule", {}).get("groups", [])
    source_ip = alert.get("data", {}).get("srcip", "local")
    rule_id = alert.get("rule", {}).get("id", "unknown")
    description = alert.get("rule", {}).get("description", "")

    # Find first matching group
    event_type = "wazuh_alert"
    technique = None
    tactic = None
    for group in groups:
        if group in WAZUH_GROUP_MAP:
            event_type, technique, tactic = WAZUH_GROUP_MAP[group]
            break

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": alert.get("timestamp"),
        "source_ip": source_ip if source_ip != "local" else "127.0.0.1",
        "dest_ip": "10.0.0.108",
        "ip_type": classify_ip(source_ip),
        "service": "wazuh",
        "event_type": event_type,
        "wazuh_rule_id": rule_id,
        "wazuh_level": level,
        "wazuh_groups": groups,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "description": description,
        "log_source": "wazuh",
        "raw": json.dumps(alert)
    }
```

---

## Tier 4 — Step 5: Add Wazuh-sourced Investigator rules

File: `investigator_agent.py`

```python
# R28 — Rootkit Detected (T1014)
# Wazuh rootcheck fired
wazuh_rootkit = [
    e for e in recent_events(source="wazuh")
    if e.get("event_type") == "rootkit_detect"
]
if wazuh_rootkit:
    open_ticket("local", "R28", "critical", {"events": wazuh_rootkit},
                technique="T1014", tactic="Defense Evasion")

# R29 — Web Shell Hint (T1505.003)
# Wazuh flagged a PHP/web file change in web directory
wazuh_webshell = [
    e for e in recent_events(source="wazuh")
    if e.get("event_type") == "web_shell_hint"
]
if wazuh_webshell:
    open_ticket("local", "R29", "critical", {"events": wazuh_webshell},
                technique="T1505.003", tactic="Persistence")

# R30 — File Integrity Violation (T1565)
# Wazuh syscheck flagged change to monitored file
wazuh_fim = [
    e for e in recent_events(source="wazuh")
    if e.get("event_type") == "file_modified"
    and e.get("wazuh_level", 0) >= 7
]
if wazuh_fim:
    open_ticket("local", "R30", "high", {"events": wazuh_fim},
                technique="T1565", tactic="Impact")
```

---

## Tier 4 — Verification checklist

```bash
# 1. Wazuh generating alerts
sudo wc -l /var/ossec/logs/alerts/alerts.json

# 2. Triage parsing Wazuh events
cat ~/.hermes/soc/ip_stats.json | python3 -m json.tool | grep "wazuh"

# 3. Trigger a test alert — modify a monitored file
sudo touch /var/www/html/test_syscheck.php
# Wait 5 min for syscheck cycle, check for alert
sudo grep "test_syscheck" /var/ossec/logs/alerts/alerts.json
# Delete test file after
sudo rm /var/www/html/test_syscheck.php

# 4. Confirm R29/R30 fires in ticket store
```

---

---

# TIER 5 — Cowrie SSH Honeypot
**When:** LAST. Only after full V2 pipeline is stable end-to-end (all agents running, tickets flowing, Telegram working).  
**Dependency:** Multi-agent pipeline fully operational. Port 22 must be moved off your real SSH.  
**What changes:** Deploy Cowrie on port 22 (WAN). Move real SSH to port 2222 or use Tailscale only. Add Cowrie log as Triage source.

⚠️ **Do not expose Cowrie until the pipeline is stable. Cowrie generates high-volume attacker traffic — if your pipeline isn't ready, it will be overwhelmed.**

---

## Tier 5 — Step 1: Move real SSH off port 22

Before deploying Cowrie, move your real sshd to a non-standard port. You access the server via Tailscale (`ssh user@100.x.x.x`) so port doesn't matter for your access.

```bash
sudo nano /etc/ssh/sshd_config
```

Change:
```
Port 22
```
To:
```
Port 2222
```

Also add:
```
# Only allow Tailscale and LAN connections
ListenAddress 100.x.x.x   # Tailscale IP
ListenAddress 10.0.0.108     # LAN IP
```

Restart sshd:
```bash
sudo systemctl restart sshd

# Verify you can still connect via Tailscale on new port
# Test from ANOTHER terminal before closing current session:
ssh -p 2222 user@100.x.x.x
```

Only close the current session after confirming the new port works.

---

## Tier 5 — Step 2: Install Cowrie

```bash
# Install dependencies
sudo apt install python3-venv libssl-dev libffi-dev -y

# Create dedicated user
sudo adduser --disabled-password cowrie
sudo su - cowrie

# Clone Cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Create venv and install
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Copy config
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

---

## Tier 5 — Step 3: Configure Cowrie

```bash
# Still as cowrie user
nano etc/cowrie.cfg
```

Key settings to change:

```ini
[honeypot]
# Hostname shown to attackers
hostname = ubuntu-server

# Cowrie listens on 2223, authbind forwards 22 → 2223
listen_endpoints = tcp:2223:interface=0.0.0.0

# Logging — enable JSON output for Triage
[output_jsonlog]
enabled = true
logfile = log/cowrie.json

# Disable telnet (SSH only for now)
[output_telnet]
enabled = false
```

---

## Tier 5 — Step 4: Forward port 22 to Cowrie

Cowrie can't bind port 22 as a non-root user. Use authbind or iptables redirect.

```bash
# Exit cowrie user, back to user
exit

# Using iptables redirect (port 22 WAN → 2223 Cowrie):
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2223

# Make it persistent
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

---

## Tier 5 — Step 5: Create systemd service for Cowrie

```bash
sudo nano /etc/systemd/system/cowrie.service
```

```ini
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/python \
    bin/cowrie start -n
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/python \
    bin/cowrie stop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie
sudo systemctl status cowrie
```

---

## Tier 5 — Step 6: Add Cowrie log parser to Triage

Cowrie JSON log location: `/home/cowrie/cowrie/log/cowrie.json`

File: `triage_agent.py`

```python
COWRIE_LOG_PATH = "/home/cowrie/cowrie/log/cowrie.json"

def parse_cowrie_event(event: dict) -> dict | None:
    """
    Parse a Cowrie honeypot JSON event.
    All events from Cowrie are suspicious by definition
    — nothing legitimate connects to a honeypot.
    """
    event_id_cowrie = event.get("eventid", "")
    source_ip = event.get("src_ip", "unknown")
    timestamp = event.get("timestamp")

    # Cowrie event types we care about
    COWRIE_EVENT_MAP = {
        "cowrie.login.failed":   ("honeypot_auth_fail",    "T1110",     "high"),
        "cowrie.login.success":  ("honeypot_auth_success", "T1078",     "critical"),
        "cowrie.command.input":  ("honeypot_command",      "T1059.004", "high"),
        "cowrie.session.file_download": ("honeypot_download", "T1105", "critical"),
        "cowrie.session.connect":("honeypot_connect",      "T1595",     "medium"),
    }

    if event_id_cowrie not in COWRIE_EVENT_MAP:
        return None

    event_type, technique, severity = COWRIE_EVENT_MAP[event_id_cowrie]

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source_ip": source_ip,
        "dest_ip": "10.0.0.108",
        "ip_type": "external",   # all cowrie traffic is external
        "service": "cowrie_honeypot",
        "event_type": event_type,
        "cowrie_event": event_id_cowrie,
        "mitre_technique": technique,
        "honeypot_severity": severity,
        "input": event.get("input", ""),       # command entered by attacker
        "username": event.get("username", ""),
        "password": event.get("password", ""),  # attacker's attempted password
        "log_source": "cowrie",
        "raw": json.dumps(event)
    }
```

---

## Tier 5 — Step 7: Add Cowrie Investigator rule

```python
# R31 — Honeypot Interaction (T1595, T1078, T1059)
# Anything hitting Cowrie is suspicious. Severity escalates with interaction depth.
cowrie_events = [
    e for e in recent_events(source="cowrie")
    if e.get("source_ip") == ip
]
if cowrie_events:
    max_severity = max(
        e.get("honeypot_severity", "medium") for e in cowrie_events
    )
    open_ticket(ip, "R31", max_severity, {"cowrie_events": cowrie_events},
                technique="T1595", tactic="Reconnaissance",
                note=f"{len(cowrie_events)} honeypot interactions")
```

---

## Tier 5 — Verification checklist

```bash
# 1. Cowrie is running
sudo systemctl status cowrie

# 2. Port 22 redirects to Cowrie (not real SSH)
# From external machine: ssh root@YOUR_WAN_IP
# Should see Cowrie fake banner, not real SSH

# 3. Real SSH still works on Tailscale
ssh -p 2222 user@100.x.x.x   # or via Tailscale without port if you set ListenAddress

# 4. Cowrie JSON log filling up (within minutes of going live)
sudo -u cowrie tail -f /home/cowrie/cowrie/log/cowrie.json

# 5. Triage parsing cowrie events
cat ~/.hermes/soc/ip_stats.json | python3 -m json.tool | grep "cowrie"

# 6. R31 tickets appearing in ticket store
ls ~/.hermes/soc/tickets/ | grep R31
```

---

---

# Full V2 ruleset — post all tiers

| Rule | Technique | Tactic | Severity | Handler | Tier |
|------|-----------|--------|----------|---------|------|
| R1 | T1595→T1190 | Recon→Initial Access | Medium | Investigator | V2 |
| R2 | T1110.001, T1078 | Credential Access | High | Investigator | V2 |
| R3 | T1078, T1071 | C2 | High | Investigator | Tier 2 |
| R4 | T1021.004 | Lateral Movement | Medium | Investigator | V2 |
| R5 | T1048 | Exfiltration | High | Investigator | Tier 2 |
| R6 | T1078 | Initial Access | Medium | Investigator | V2 |
| R7 | T1070.002 | Defense Impairment | High | Triage pre-flag | V2 |
| R8 | T1136, T1098 | Persistence | High | Triage pre-flag | V2 |
| R9 | T1053.003 | Persistence | Medium | Investigator | V2 |
| R10 | T1562.001 | Defense Impairment | Critical | Triage pre-flag | V2 |
| R11 | T1190, T1505.003 | Initial Access | High | Investigator | V2 |
| R12 | T1110.003 | Credential Access | High | Investigator | Tier 1 |
| R13 | T1078.001 | Initial Access | High | Investigator | Tier 1 |
| R14 | T1548.003 | Privilege Escalation | Medium | Investigator | Tier 1 |
| R15 | T1531 | Impact | High | Triage pre-flag | Tier 1 |
| R16 | T1543.002 | Persistence | Medium | Investigator | Tier 1 |
| R17 | T1037 | Persistence | High | Triage pre-flag | Tier 1 |
| R18 | T1070.003 | Defense Evasion | Medium | Triage pre-flag | Tier 1 |
| R19 | T1595.002 | Reconnaissance | Medium | Investigator | Tier 1 |
| R20 | T1110 | Credential Access | Medium | Investigator | Tier 1 |
| R21 | T1078 | Initial Access | High | Investigator | Tier 1 |
| R22 | T1003.008 | Credential Access | Critical | Investigator | Tier 3 |
| R23 | T1548.003 | Privilege Escalation | Critical | Investigator | Tier 3 |
| R24 | T1098.004 | Persistence | High | Investigator | Tier 3 |
| R25 | T1547.006 | Persistence | High | Investigator | Tier 3 |
| R26 | T1222 | Defense Evasion | Medium | Investigator | Tier 3 |
| R27 | T1021.004 | Lateral Movement | High | Investigator | Tier 3 |
| R28 | T1014 | Defense Evasion | Critical | Investigator | Tier 4 |
| R29 | T1505.003 | Persistence | Critical | Investigator | Tier 4 |
| R30 | T1565 | Impact | High | Investigator | Tier 4 |
| R31 | T1595 | Reconnaissance | Variable | Investigator | Tier 5 |

**Total: 31 rules across 12 tactics — ~41 techniques, ~18% of ATT&CK Enterprise matrix**

---

*Last updated: 2026-07-26 — coverage expansion guide complete*
