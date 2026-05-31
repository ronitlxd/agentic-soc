# Agentic SOC — Version 2 Redesign Notes
**Status:** In progress — agent-by-agent redesign session  
**Reference project:** github.com/ronitlxd/Home_SOC_Lab  
**Server:** Ubuntu Server 24.04 LTS | `user@10.0.0.108`

---

## Context: Why V2

V1 pipeline is live and partially proven (R2, R7 confirmed firing end-to-end).  
V2 redesign goals:
- Make the Investigator the clear central intelligence — reduce its data-prep burden to zero
- Add LLM as a second-pass detection layer (Stage 2) for novel/unmatched events
- Replace/remove broken or noisy rules (R3, R5 no-op; R6 too broad)
- Add coverage for Persistence, Defense Impairment tactics (currently zero coverage)
- Give LLM structured input it can reason on, not raw log strings
- Improve audit trail integrity (event-ID based state, not timestamp-based)

Detection philosophy:
- Stage 1: deterministic Python rules — fast, free, fully auditable
- Stage 2: LLM on unmatched events only — novel pattern detection
- Triage pre-flags single-event critical signals directly (no Investigator wait)
- Human-in-the-loop before any containment action — unchanged

---

## AGENT 1 — TRIAGE (redesign complete)

### Role (unchanged)
Collect and normalize all log sources concurrently. Feed the Investigator.

### What changes

#### 1. Full event normalization (new)
Every event from every log source must conform to a single schema before entering the buffer. Investigator never touches raw strings.

**Normalized event schema:**
```json
{
  "event_id": "uuid4",
  "timestamp": "2026-07-26T03:14:22Z",
  "source_ip": "45.33.32.156",
  "dest_ip": "10.0.0.108",
  "ip_type": "external",
  "username": "root",
  "service": "ssh",
  "event_type": "auth_fail",
  "port": 22,
  "log_source": "auth.log",
  "raw": "original log line"
}
```

**event_type fixed vocabulary:**
```
auth_fail / auth_success / account_created / account_modified
port_scan / firewall_block
web_get / web_post / web_error
cron_modified / service_stopped / log_modified
```

- `ip_type` classified at ingest: internal (RFC1918) vs external
- `event_id` (uuid4) added at ingest — fixes Investigator restart skip/duplicate bug (replaces timestamp-based state)
- Unknown/unmappable lines logged to a `triage_unparsed.log` — not silently dropped

#### 2. sshd log collapse expansion (new)
sshd collapses repeated failures into `message repeated N times`. Currently counts as 1 failure, breaking R2 threshold.

Fix in Triage parser — emit N synthetic failure events for that IP:
```python
if "message repeated" in line:
    count = int(re.search(r'repeated (\d+) times', line).group(1))
    for _ in range(count):
        emit_event(last_event_template_for_ip)
```
This fix belongs in Triage, not Investigator.

#### 3. Per-IP statistics store (new — main change)
Triage maintains a live running stats object per IP, updated in real time as events arrive. Persisted to `~/.hermes/soc/ip_stats.json` — survives restarts.

**Stats object per IP:**
```json
{
  "45.33.32.156": {
    "ip_type": "external",
    "first_seen": "2026-07-26T02:58:01Z",
    "last_seen": "2026-07-26T03:14:22Z",
    "auth_failures": 23,
    "auth_successes": 1,
    "success_username": "root",
    "failed_usernames": ["root", "admin", "ubuntu"],
    "scan_targets": [],
    "services_hit": ["ssh"],
    "active_hours_utc": [2, 3],
    "known_ip": false,
    "bytes_out": 0,
    "web_posts": 0,
    "account_events": 0,
    "cron_events": 0,
    "service_stop_events": 0
  }
}
```

`known_ip`: true if IP seen in auth.log in past 7 days (rolling window maintained by Triage).

**Why this matters for Investigator:**  
Every detection rule becomes a 3–5 line dict lookup instead of a multi-pass buffer scan. Investigator can run every 60–90s instead of every 5 min.

**Why this matters for LLM Stage 2:**  
LLM receives structured per-IP summaries — not raw log lines. Reliable reasoning, no hallucinated field extraction.

#### 4. Single-event pre-flagging (extended)
Some signals don't need multi-event correlation. Triage writes tickets directly for these — Investigator skips if ticket already exists.

| Trigger | Technique | Severity |
|---------|-----------|----------|
| Log file shrinks (existing R7) | T1070.002 | High |
| `useradd` / `adduser` / `new user` in auth.log (new) | T1136 | High |
| `usermod` / `passwd` modification (new) | T1098 | High |
| `systemctl stop/disable suricata\|wazuh\|splunk\|ufw` in syslog (new) | T1562.001 | Critical |
| `ufw disable` / `iptables -F` in syslog (new) | T1562.001 | Critical |

Critical-severity tickets bypass the standard 5-minute Investigator cycle entirely and go direct to Orchestrator.

#### 5. Output to Investigator (changed)
V1: raw 24h event buffer  
V2: two outputs
- `ip_stats.json` — live stats store (primary Investigator input)
- `event_buffer` — normalized event stream with `event_id` (secondary, for sequence correlation)

---

## Triage — MITRE coverage added

| New coverage | Technique |
|---|---|
| Account creation detection | T1136 |
| Account modification detection | T1098 |
| Defense tool disabling | T1562.001 |

---

## AGENT 2 — INVESTIGATOR (redesign complete)

### Role (unchanged)
Correlate events into attack patterns. Open tickets. Central intelligence of the pipeline.

### What changes

#### 1. Input (biggest change)
V1: scans raw 24h event buffer — does its own extraction, grouping, parsing  
V2: reads `ip_stats.json` from Triage — opens file, iterates dict, applies rules  
Every rule drops from 50+ lines of iteration to 3–5 lines of logic.

#### 2. Run cycle
V1: every 5 minutes (limited by buffer scan cost)  
V2: every 60–90 seconds (dict lookup is near-instant)  
Brute force detected in <90s instead of up to 5 min.

#### 3. State management
V1: timestamp-based — restarts cause skip or duplicate  
V2: tracks last processed `event_id` (uuid4 from Triage) per log source

State file: `~/.hermes/soc/investigator_state.json`
```json
{
  "last_event_id": "a3f2c1d4-...",
  "last_run": "2026-07-26T03:14:00Z",
  "open_ip_set": ["45.33.32.156"]
}
```

#### 4. Ticket deduplication (new)
Before opening a ticket, check store for open ticket matching `source_ip + rule_id`.  
If found → append finding update. If not → open new ticket.
```python
existing = find_open_ticket(ip=source_ip, rule=rule_id)
if existing:
    append_finding(existing["ticket_id"], updated_stats)
else:
    open_ticket(source_ip, rule_id, stats)
```

#### 5. Severity scoring (new)
V1: no severity — everything equally weighted  
V2: assigned at ticket creation

| Severity | Rules | Rationale |
|---|---|---|
| Critical | R10 (Triage pre-flag) | Attacker disabling defenses |
| High | R2, R8, R11 | Confirmed access or persistence |
| Medium | R1, R4, R6, R9 | Multi-stage signal, unconfirmed |
| Low | LLM Stage 2 | Model-detected, unconfirmed |

Critical tickets bypass Intel and go direct to Orchestrator.

#### 6. Rule engine (V2 — dict lookups on ip_stats)

```python
# R1 — Recon→Exploit (T1595→T1190)
if (stats["port_scan_count"] > 0
    and (stats["auth_failures"] > 0 or stats["web_posts"] > 0)
    and time_delta(stats["first_seen"], stats["last_seen"]) < 600):
    open_ticket(ip, "R1", "medium", stats)

# R2 — Brute Force Success (T1110.001, T1078)
if stats["auth_failures"] >= 5 and stats["auth_successes"] >= 1:
    open_ticket(ip, "R2", "high", stats)

# R4 — Lateral Movement (T1021.004)
if stats["ip_type"] == "internal" and len(stats["scan_targets"]) >= 5:
    open_ticket(ip, "R4", "medium", stats)

# R6 — Off-Hours Auth from Unknown IP (T1078 replacement)
if (stats["auth_successes"] >= 1
    and current_utc_hour in [2, 3, 4, 5]
    and not stats["known_ip"]):
    open_ticket(ip, "R6", "medium", stats)

# R9 — Cron Persistence (T1053.003)
if stats["cron_events"] >= 1:
    open_ticket(ip, "R9", "medium", stats)

# R11 — Suspicious Web POST (T1190, T1505.003)
if (stats["web_posts"] >= 1
    and stats["web_post_to_unknown_path"]
    and stats["web_200_response"]
    and not stats["known_ip"]):
    open_ticket(ip, "R11", "high", stats)
```

R7, R8, R10 handled by Triage pre-flag — Investigator skips IPs already ticketed.

#### 7. LLM Stage 2 integration (new)

After Stage 1, collect unmatched IPs with non-trivial activity:
```python
candidates = [
    ip for ip, stats in ip_stats.items()
    if not triggered_any_rule(ip)
    and stats["auth_failures"] + stats["web_posts"] + stats["cron_events"] > 0
]
```

Memory gate — check ticket store before calling LLM:
```python
for ip in candidates:
    recent = find_recent_ticket(ip=ip, hours=24)
    if recent:
        tag_as_variant(ip, recent["ticket_id"])
        candidates.remove(ip)
# remaining → LLM
```

LLM prompt (structured summaries, JSON-only output):
```
You are a SOC analyst. Review these IP activity summaries.
None matched a known detection rule. Identify credible threats only.

For each suspicious IP respond ONLY in this JSON format:
{
  "ip": "...",
  "finding": "threat" or "none",
  "confidence": "low/medium/high",
  "mitre_technique": "T1234" or null,
  "reasoning": "one sentence max"
}

Summaries:
{candidates_stats_json}
```

LLM response validated against schema before use. JSON parse failure → log and discard, do not crash pipeline.

#### 8. Ticket schema V2 (enriched)

```json
{
  "ticket_id": "SOC-0142",
  "created": "2026-07-26T03:15:30Z",
  "source_ip": "45.33.32.156",
  "ip_type": "external",
  "rule": "R2",
  "detection_method": "rule",
  "mitre_technique": "T1110.001",
  "mitre_tactic": "Credential Access",
  "severity": "high",
  "evidence": {
    "auth_failures": 23,
    "auth_successes": 1,
    "success_username": "root",
    "failed_usernames": ["root", "admin", "ubuntu"],
    "active_hours_utc": [3],
    "known_ip": false
  },
  "findings": [],
  "status": "open",
  "agent_trail": ["triage", "investigator"]
}
```

`detection_method`: `"rule"` / `"llm"` / `"triage_preflag"` — always distinguishable  
`agent_trail`: append-only, every agent stamps itself  
`findings`: append-only array — Intel, Responder, Auditor all write here

---

### Investigator V2 — summary table

| Dimension | V1 | V2 |
|---|---|---|
| Input | Raw 24h event buffer | ip_stats.json dict |
| Rule code | 50+ lines per rule | 3–5 lines per rule |
| Run cycle | 5 minutes | 60–90 seconds |
| State tracking | Timestamp-based | event_id-based |
| Ticket dedup | None | Yes — append to existing |
| Severity | None | 4-level scoring |
| LLM integration | None | Stage 2 on unmatched IPs |
| Memory gate | None | Ticket store check before LLM |
| Ticket schema | Minimal | Fully enriched with evidence |
| Pre-flagged events | Passed through | Skipped (Triage handled) |

---

## AGENT 3 — INTEL (redesign complete)

### Role (unchanged)
Enrich suspicious external IPs with threat intelligence before the Orchestrator briefs the operator.

### What changes

#### 1. Priority-aware routing (new)
Not every ticket needs full enrichment.

| Severity | Mode | What runs |
|---|---|---|
| Critical | Skip entirely | Goes direct to Orchestrator — speed over enrichment |
| High | Full enrichment | All feeds + API keys if available |
| Medium | Free feeds only | No API calls, no rate limit risk |
| Low (LLM) | Lightweight | IP classification only |

#### 2. IP result cache (new)
24h TTL cache at `~/.hermes/soc/intel_cache.json`.  
Same IP generating 10 tickets = 1 API call, not 10.  
Cache lookup happens before any feed or API call.

#### 3. Feed stack (extended)

Free feeds — downloaded daily, stored locally, lookup is in-memory set check:
- Tor exit list (torproject.org)
- Feodo C2 tracker (abuse.ch)
- Emerging Threats compromised IPs (emergingthreats.net) ← new
- Spamhaus DROP list (spamhaus.org) ← new

API feeds — optional, degrade gracefully if no key:
- AbuseIPDB: confidence score, report count
- IPinfo: country, ASN, org, hosting boolean
- GreyNoise: internet scanner classification ← new
- Shodan: open ports on the IP ← new

#### 4. MITRE ATT&CK group correlation (new)
Local lookup only — zero API calls.  
Source: STIX JSON downloaded once to `~/.hermes/soc/attack_stix.json`  
Given technique ID on ticket → returns list of known threat actor groups using it.  
Orchestrator brief: "T1110.001 — groups known to use this: APT28, FIN7"

#### 5. Cross-ticket correlation (new)
Before passing ticket on, check ticket store for prior tickets from same source IP.  
Appends: prior ticket count, IDs, and techniques seen previously.  
Repeat offender vs first-time visitor changes the Orchestrator brief significantly.

#### 6. Structured intel_summary output (new)
V1: raw feed results appended to ticket  
V2: clean `intel_summary` block the Orchestrator reads directly

```json
"intel_summary": {
  "ip_reputation": "malicious",
  "reputation_score": 87,
  "known_threat": true,
  "threat_labels": ["Tor exit node", "AbuseIPDB score 87/100"],
  "geolocation": "Netherlands (NL)",
  "org": "DigitalOcean LLC",
  "hosting_provider": true,
  "internet_scanner": true,
  "scanner_name": "SSH Scanner",
  "associated_groups": ["APT28", "FIN7"],
  "prior_tickets": 3,
  "prior_ticket_ids": ["SOC-0138", "SOC-0141"],
  "feed_hits": ["feodo_c2", "tor_exit"],
  "enrichment_mode": "full",
  "enriched_at": "2026-07-26T03:15:45Z"
}
```

### Intel V2 — internal flow
```
Ticket arrives
    ↓ severity == critical → skip → Orchestrator directly
    ↓ ip_type == internal → skip enrichment
    ↓
Cache check → fresh? → use cache
    ↓ stale/missing
Run enrichment (mode based on severity)
    → free feeds (always)
    → API feeds (high only)
    → MITRE group lookup (local, always)
    → cross-ticket correlation (local, always)
    ↓
Build intel_summary
Append to ticket findings array
Save to cache
    ↓
Pass enriched ticket to Orchestrator
```

### Intel V2 — summary table

| Dimension | V1 | V2 |
|---|---|---|
| Priority routing | None | 4-mode: skip/full/free-only/lightweight |
| IP caching | None | 24h TTL, one API call per IP per day |
| Free feeds | Tor + Feodo | + Emerging Threats + Spamhaus DROP |
| API feeds | AbuseIPDB + IPinfo | + GreyNoise + Shodan |
| Feed loading | Per-ticket network call | Daily local download, in-memory set lookup |
| MITRE group lookup | None | Local STIX lookup by technique ID |
| Cross-ticket correlation | None | Prior ticket count + IDs + techniques |
| Output format | Raw feed results | Structured intel_summary block |
| Internal IP protection | Hard block | Hard block (unchanged) |
| Degradation | Graceful | Graceful (unchanged) |

---

## AGENT 5 — RESPONDER (redesign complete)

### Role (unchanged)
Execute operator-approved containment actions only. Evidence before action. Never lock out the operator.

### What changes

#### 1. Pre-flight validation gate (extended — 5 checks)
Any failure aborts with reason logged to ticket:
1. Ticket still open (not already resolved)
2. Option valid for this rule type
3. Ticket not stale (>120 min old → refuse, re-investigate)
4. Lockout prevention (option 2: block IP check against protected ranges)
5. No duplicate action (same action already executed for this ticket)

Protected IPs — never block:
- `100.x.x.x` (Tailscale server IP)
- `100.64.0.0/10` (entire Tailscale range)
- `10.0.0.0/8` (LAN range)
- `127.0.0.1` / `::1` (loopback)

#### 2. System state snapshot (extended)
Saves to `~/.hermes/soc/snapshots/{ticket_id}_{timestamp}.json`  
Captures: active sessions, active connections, firewall state, top processes, logged-in users, listening ports.  
Snapshot path stored in ticket — Auditor references it in case file.

#### 3. Action library (V2 — extended for new rules)

**Option 1 — Monitor:** No system changes. Tag ticket as "monitoring".

**Option 2 — Block IP (all rules):**
- Execute: `sudo ufw deny from {ip} to any comment 'SOC-{id}'`
- Verify: `sudo ufw status | grep {ip}` shows DENY
- Rollback: `sudo ufw delete deny from {ip} to any`

**Option 3 — Dynamic by rule type (new):**
- Auth rules (R2, R13, R21): Kill active session
  - `sudo pkill -KILL -u {username}` + `sudo ss -K dst {ip}`
  - Verify: `who | grep {ip}` empty
- Cron persistence (R9): Remove crontab
  - Backup first, then `sudo crontab -r -u {username}`
  - Rollback: restore from backup file
- Unknown service (R16): Disable service
  - `sudo systemctl stop {service}` + `sudo systemctl disable {service}`
  - Rollback: `sudo systemctl enable {service} && start`
- Defense tool stopped (R10): Restore security tool
  - Whitelist: suricata, wazuh, ufw, fail2ban, splunk only
  - `sudo systemctl start {tool}` + `sudo systemctl enable {tool}`
- SSH key modified (R24): Backup + manual review alert
  - Cannot safely auto-identify malicious key — backs up authorized_keys
  - Sends additional Telegram requesting manual review

**New Option — Disable account (R8, R12, R13):**
- Lock (not delete — preserves forensic evidence): `sudo usermod -L {username}`
- Protected users list: root, user, splunk, www-data, nobody, daemon, sys
- Rollback: `sudo usermod -U {username}`

**Option 4 — Escalate:** Mark ticket escalated, send full case dump to Telegram.

#### 4. Action log format (enriched)
Every action writes to ticket findings array:
```json
{
  "agent": "responder",
  "timestamp": "...",
  "action": "block_ip",
  "target": "45.33.32.156",
  "pre_snapshot": "~/.hermes/soc/snapshots/SOC-0142_...",
  "command_run": "sudo ufw deny from 45.33.32.156 to any",
  "verified": true,
  "rollback_command": "sudo ufw delete deny from 45.33.32.156 to any",
  "operator_option": 2,
  "execution_ms": 340
}
```
`rollback_command` stored as executable string — operator can run directly if needed.

#### 5. Dry run mode (new — for safe testing)
`RESPONDER_DRY_RUN=true` env var — logs what would execute without running it.  
Use during testing and portfolio demonstration.

### Action matrix

| Trigger rule | Option 3 action | Reversible |
|---|---|---|
| R2, R13, R21 (auth) | Kill active session | No (account preserved) |
| R8 (account created) | Disable account | Yes — usermod -U |
| R9 (cron) | Remove crontab | Yes — restore from backup |
| R10 (tool stopped) | Restore security tool | Yes |
| R16 (unknown service) | Disable service | Yes |
| R17 (startup script) | Manual review alert | N/A |
| R24 (SSH key) | Backup + manual review | N/A |
| All rules | Block IP (option 2) | Yes — ufw delete |
| All rules | Monitor (option 1) | N/A |
| All rules | Escalate (option 4) | N/A |

### Summary table

| Dimension | V1 | V2 |
|---|---|---|
| Pre-flight checks | Basic lockout check | 5-check gate |
| Snapshot scope | Sessions, connections, firewall | + processes, ports, login history |
| Action library | Block IP, kill session | + remove cron, disable service, restore tool, disable account, SSH key backup |
| Option 3 | Fixed (kill session) | Dynamic — varies by rule type |
| Rollback storage | Logged as text | Stored as executable string in ticket |
| Dry run mode | None | RESPONDER_DRY_RUN=true |
| Protected accounts | None | PROTECTED_USERS list |
| Stale ticket guard | None | Refuse if ticket >120 min old |
| Audit output | Log entry | Structured JSON finding in ticket |

---

## AGENT 6 — AUDITOR (redesign complete)

### Role (unchanged)
Write forensic case file after containment. Close ticket. Produce portfolio-ready artefact.

### What changes

#### 1. Two-part case file (main change)
V1: single Python template, all deterministic, reads like a form.  
V2: two distinct sections with different authors.

**Part 1 — Structured data (Python-generated)**  
Exact field values, MITRE tags, timestamps, IOCs, action logs. Never LLM — must be precise.

**Part 2 — Narrative (LLM-written)**  
Executive summary, attack narrative, analyst notes.  
LLM receives structured data, writes readable prose.  
Local qwen3-4b-2507 on port 1234.  
If LLM fails → Python template fallback. Case file always completes.

#### 2. Full case file sections
- Executive Summary (LLM)
- Attack Narrative (LLM)
- Analyst Notes (LLM)
- Timeline — reconstructed from event_ids + timestamps (Python)
- Indicators of Compromise — IP, usernames, ASN (Python)
- MITRE ATT&CK mapping table — full technique chain (Python)
- Threat Intelligence — from intel_summary (Python)
- Containment Actions — from Responder action log (Python)
- NIST IR Lifecycle — phase table with status (Python)
- Remediation Checklist — rule-specific (Python)
- Agent Trail — from ticket agent_trail array (Python)
- System Snapshot reference path (Python)
- Rollback Procedure — executable command string (Python)

#### 3. Rule-specific remediation checklists
Each rule has a predefined checklist. Multiple rules fired → checklists merged and deduplicated.

Examples:
- R2 fired → rotate credentials, disable root SSH, audit session window files
- R9 fired → review all cron entries, check /etc/cron.d/, audit /tmp
- R10 fired → confirm tool restored, review gap-period logs, audit who stopped it
- R22 fired → assume shadow compromised, rotate all passwords, check exfiltration

#### 4. OCSF export (new — roadmap item)
Machine-readable OCSF-compliant JSON alongside markdown.  
Class UID 2001 (Security Finding).  
Includes: technique, actor IP, geolocation, observables list.  
Saved as `SOC-0142_2026-07-26.ocsf.json`

#### 5. File storage
```
~/.hermes/soc/cases/
    SOC-0142_2026-07-26.md           # human-readable
    SOC-0142_2026-07-26.ocsf.json    # OCSF machine-readable
    SOC-0142_2026-07-26.json         # raw ticket JSON
```

GitHub: `docs/incidents/` — each case file is a direct portfolio artefact.

#### 6. Ticket closure
```python
update_ticket(ticket_id, {
    "status": "closed",
    "closed_at": now_iso(),
    "case_file": case_file_path,
    "ocsf_export": ocsf_path
})
append_agent_trail(ticket_id, "auditor")
```

### Auditor V2 — summary table

| Dimension | V1 | V2 |
|---|---|---|
| Case file format | Single Python template | Two-part: Python structured + LLM narrative |
| Narrative | Template strings | LLM executive summary + attack prose |
| Timeline | Basic | Reconstructed from event_ids with exact timestamps |
| IOC extraction | Manual template | Structured from evidence + intel_summary |
| MITRE mapping | Single technique tag | Full technique chain if multiple rules fired |
| Threat intel section | None | intel_summary — groups, reputation, geolocation |
| Remediation | Generic | Rule-specific checklist per rule fired |
| NIST mapping | Basic mention | Full phase table with status per phase |
| OCSF export | None | Yes — machine-readable alongside markdown |
| Rollback procedure | Text mention | Executable command string from Responder log |
| GitHub ready | No | Yes — docs/incidents/ structure |
| LLM fallback | N/A | Template fallback if LLM unavailable |

---

## AGENT 4 — ORCHESTRATOR + VEGA (redesign complete)

### Role (unchanged)
Orchestrator: conductor — starts agents, schedules cycles, routes tickets, sends Telegram briefs.  
Vega: operator interface — receives inbound Telegram messages, interprets natural language queries.

### The main bug fix: operator response via web interface

**Root cause of V1 bug:** LLM deciding whether "SOC-0138 3" is a ticket command or chat. Non-deterministic decision on deterministic data. Any phrasing variation breaks it.

**Fix:** Remove operator response from Telegram entirely. Telegram is now read-only push notification. All decisions happen in the web interface. operator_response.json is written by a plain Flask POST handler — no LLM, no skill, no Hermes.

### Telegram — read-only notification only (V2)

Plain text + URL. No buttons. No inline keyboard. No callback handling.

```
🚨 SOC-0142 | HIGH | Brute Force → Root Login

45.33.32.156 (Netherlands / DigitalOcean)
AbuseIPDB: 87/100 · Known SSH scanner
23 SSH failures → root login at 03:14 UTC

→ http://100.x.x.x:5000/brief/SOC-0142
```

### Web interface — where decisions happen (new)

Three new routes added to existing Flask dashboard (port 5000, `homelab-dashboard.service`):

**`/briefs`** — active briefs list, sorted by severity. Auto-refreshes every 10 seconds.

**`/brief/<ticket_id>`** — full brief view:
- Header: ticket ID, severity badge, rule, timestamp
- IP block: geolocation, ASN, hosting flag
- Reputation: AbuseIPDB score, feed hits, known scanner flag
- Threat context: MITRE technique + tactic, associated ATT&CK groups
- Evidence: event counts from ip_stats
- Prior tickets: list of previous tickets from same IP
- Action buttons: Monitor / Block IP / [Rule-specific] / Escalate

**`/respond`** — POST endpoint. Receives `{ticket_id, option}` from button click. Writes `operator_response.json`. Returns JSON confirmation.

```python
@app.route("/respond", methods=["POST"])
def respond():
    data = request.json
    ticket_id = data.get("ticket_id")
    option = data.get("option")
    if not ticket_id or option not in [1, 2, 3, 4]:
        return jsonify({"error": "invalid"}), 400
    payload = {
        "ticket_id": ticket_id,
        "option": option,
        "received_at": now_iso(),
        "source": "web_interface"
    }
    write_json(payload, OPERATOR_RESPONSE_PATH)
    return jsonify({"status": "ok", "ticket_id": ticket_id, "option": option})
```

### Orchestrator V2 changes

#### 1. Severity-based routing
- Critical → skip Intel, brief immediately
- High/Medium → normal Intel flow, then brief
- Low → 30-min digest, not per-ticket brief

#### 2. Rich brief generator
Structure built by Python from intel_summary.  
One-sentence narrative written by local LLM (qwen3-4b-2507) from structured evidence.  
Telegram gets plain text + URL. Web interface gets full structured layout.

#### 3. Multi-ticket priority queue
PriorityQueue ordered by severity then timestamp.  
Critical interrupts queue — sent immediately.

#### 4. Response timeout
15 min → resend Telegram reminder with URL  
30 min → log non-response, default to Monitor (no action, never auto-contain)

#### 5. Brief deduplication
Same source IP with open ticket awaiting response → append finding update, no new brief.

### Vega V2 changes

#### 1. Narrowed scope — natural language only
No ticket command handling at all. operator_response.json written by Flask, not Vega.

Vega handles:
- "What's happening right now?" → reads ticket store, summarises
- "Tell me about SOC-0142" → reads ticket + intel_summary
- "Is the server under attack?" → reads ip_stats, gives assessment

Vega does NOT handle:
- Ticket response commands — web interface only
- Inline keyboard callbacks — removed entirely

#### 2. Context injection
Active ticket store + top-5 IP activity summary injected into every LLM call.  
Answers grounded in current system state.

#### 3. SOUL.md update required
Remove: instruction to parse ticket commands from text  
Add: "You handle natural language queries only. Decisions happen via the web interface. Inject current ticket store before answering."

### Updated flow

```
Investigator → Intel → Orchestrator
                            ↓
                Sends Telegram (plain text + URL)
                            ↓
                Operator opens URL in browser
                            ↓
                Web interface — full brief + action buttons
                            ↓
                Operator clicks action button
                            ↓
                Flask POST → operator_response.json
                            ↓
                Orchestrator polls → calls Responder
                            ↓
                Responder executes approved action
```

### Summary tables

**Orchestrator:**
| Dimension | V1 | V2 |
|---|---|---|
| Brief format | Plain Python template | intel_summary + LLM narrative sentence |
| Telegram | Text + buttons | Text + URL (read-only) |
| Operator response | Vega/Hermes/LLM | Flask POST endpoint |
| Severity routing | None | 4-path: critical/high/medium/low |
| Multi-ticket handling | None | Priority queue |
| Low-severity alerts | Per-ticket brief | 30-min digest |
| Response timeout | None | 15-min reminder, 30-min default |
| Brief deduplication | None | Append to existing open case |

**Vega:**
| Dimension | V1 | V2 |
|---|---|---|
| Scope | All inbound including commands | Natural language only |
| Ticket command parsing | LLM (unreliable) | Removed — web interface handles it |
| Context available | None | Active tickets + ip_stats injected |
| Handoff mechanism | Skill trigger (broken) | Flask writes operator_response.json |
| LLM usage | All inbound | Natural language queries only |

**Web interface (new):**
| Route | Purpose |
|---|---|
| `/briefs` | Active briefs list, severity sorted, auto-refresh 10s |
| `/brief/<ticket_id>` | Full brief view with action buttons |
| `/respond` (POST) | Writes operator_response.json, returns confirmation |

---

## Revised detection ruleset (V2)

| Rule | Technique | Status | Notes |
|------|-----------|--------|-------|
| R1 | T1595→T1190 | Keep, tighten | Tighten to SSH/Apache/Nextcloud login specifically |
| R2 | T1110.001, T1078 | Keep, fix | sshd collapse fix now in Triage |
| R3 | T1078, T1071 | **Removed** | No-op — Suricata flow off. Re-add in V2.1 when flow confirmed |
| R4 | T1021.004 | Keep | No change |
| R5 | T1048 | **Removed** | No-op — Suricata flow off. Re-add in V2.1 when flow confirmed |
| R6 | T1078 | **Replaced** | New: off-hours AND auth_success AND unknown IP (3 conditions) |
| R7 | T1070.002 | Keep | Moved to Triage pre-flag |
| R8 | T1136, T1098 | **New** | Account creation/modification — Triage pre-flag |
| R9 | T1053.003 | **New** | Cron persistence — Investigator rule |
| R10 | T1562.001 | **New** | Defense tool disabling — Triage pre-flag, Critical severity |
| R11 | T1190, T1505.003 | **New** | Suspicious POST to non-standard path, status 200, new IP |

Active rules: 9  
Deferred (documented): R3, R5  
Triage pre-flags (bypass Investigator): R7, R8, R10  
Investigator correlation rules: R1, R2, R4, R6, R9, R11  
LLM Stage 2: novel patterns not matching any rule above

---

## Two-stage detection pipeline (V2)

```
Log sources → Triage
                ↓
    [normalize → ip_stats.json → pre-flag critical events]
                ↓
         Investigator (Stage 1)
    [dict lookups on ip_stats, 60-90s cycle]
                ↓ match
         Ticket opened, MITRE tagged, queued
                ↓ no match
    [Memory gate: similar ticket in last 24h?]
                ↓ no
         LLM Investigator (Stage 2)
    [structured ip_stats summaries, JSON-only output]
                ↓ finding
         Ticket opened, tagged "llm-detected", confidence score
                ↓
    Intel → Orchestrator → Telegram brief → Human decision
                ↓ approved
         Responder → Auditor → case file closed
```

---

## Known deferred issues (carry forward from V1)

- Vega inbound reply parsing unreliable (main open bug — Hermes skill not triggering consistently)
- LM Studio server stability on port 1234 unresolved — must be fixed before Stage 2 wiring
- Suricata flow logging unconfirmed — blocks R3, R5 re-introduction
- Wazuh disabled — intended log source, not yet generating alerts
- Investigator state resets on restart (fix: event_id tracking, implemented in V2 Triage)
- Triage stale alerts spam every ~30 min on idle logs (fix: quiet-hours suppression, add to Triage)

---

*Last updated: 2026-07-26 — Triage redesign complete, Investigator next*
