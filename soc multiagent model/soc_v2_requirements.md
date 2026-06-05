# SOC V2 — Requirements & Dependencies
**Target system:** Ubuntu Server 24.04 LTS | user: `user` | IP: `10.0.0.108`  
**Purpose:** All external libraries, services, APIs, system tools, and config required to run the V2 pipeline. Does not include agent code being built.

---

## 1. Python runtime

**Required version:** Python 3.10+  
**Check:** `python3 --version`  
**Install if missing:** `sudo apt install python3 python3-pip python3-venv -y`

### Python stdlib used (no install needed)
```
threading       — concurrent log tailing
queue           — priority ticket queue
subprocess      — system command execution (Responder)
ipaddress       — internal/external IP classification
uuid            — event_id generation
json            — all data serialization
re              — log line parsing, regex
os              — file paths, environment variables
signal          — graceful shutdown handling
time            — sleep cycles, timestamps
datetime        — timestamp formatting, TTL calculations
pathlib         — file path management
hashlib         — cache key generation
socket          — hostname resolution
logging         — agent logging
```

### Python third-party libraries (pip install required)

```bash
pip install flask==3.1.0
pip install requests==2.32.0
pip install python-dotenv==1.0.1
```

| Library | Version | Purpose |
|---|---|---|
| flask | 3.1.0 | Web interface — /briefs, /brief/<id>, /respond routes |
| requests | 2.32.0 | HTTP calls — Telegram API, threat feed downloads, AbuseIPDB, IPinfo, GreyNoise |
| python-dotenv | 1.0.1 | Load API keys from .env file |

**Install all:**
```bash
pip install flask==3.1.0 requests==2.32.0 python-dotenv==1.0.1 --break-system-packages
```

**No other third-party Python dependencies.** Detection pipeline (Triage, Investigator) is stdlib only. LLM calls use requests against local LM Studio endpoint.

---

## 2. Local LLM inference

### LM Studio headless
**Already installed.** Binary path: `/home/user/.lmstudio/bin/lms`  
Must be on PATH — add to `~/.bashrc`:
```bash
export PATH="$PATH:/home/user/.lmstudio/bin"
```

**Model:** `qwen/qwen3-4b-2507`  
**VRAM requirement:** ~2.33 GiB (fits GTX 1650 Ti Mobile 4GB)  
**Endpoint:** `http://127.0.0.1:1234/v1` (OpenAI-compatible)  
**Start command:** `lms server start --port 1234`  
**Health check:** `curl http://127.0.0.1:1234/v1/models`

**Used by:**
- Investigator Stage 2 — novel event analysis
- Orchestrator — one-sentence brief narrative
- Auditor — executive summary + attack narrative
- Vega — natural language query responses

**Known issue:** Server stability on port 1234 was unresolved at V1. Must be fixed before wiring any LLM agent. Verify with 24h uptime test before proceeding.

### OpenRouter (cloud LLM — Vega only)
**Model:** DeepSeek (via OpenRouter)  
**Used by:** Vega — natural language query responses (fallback if local LLM down)  
**API endpoint:** `https://openrouter.ai/api/v1/chat/completions`  
**Key:** Set in .env as `OPENROUTER_API_KEY`  
**Cost:** Pay per token — only fires on natural language Telegram messages to Vega  
**Frequency:** Low — only when operator asks questions

---

## 3. Telegram Bot API

**Purpose:** Outbound brief notifications (read-only in V2 — no inline keyboards)  
**Provider:** Telegram (free)  
**Endpoint:** `https://api.telegram.org/bot<TOKEN>/sendMessage`  
**No polling needed from Orchestrator** — Vega handles inbound via Hermes  

**Required values (set in .env):**
```
TELEGRAM_BOT_TOKEN=<your bot token>
TELEGRAM_CHAT_ID=<your personal chat ID>
```

**How to get:**
- Bot token: message @BotFather on Telegram → /newbot
- Chat ID: message @userinfobot on Telegram

**Used by:**
- Orchestrator — sends brief notification with URL
- Responder — sends abort notifications and manual review alerts
- Vega — sends natural language query responses

---

## 4. Threat intelligence — free feeds (no API key)

Downloaded once daily, stored locally. Intel agent reads from local files — no network call per ticket.

| Feed | URL | Local path | Format |
|---|---|---|---|
| Tor exit nodes | `https://check.torproject.org/torbulkexitlist` | `~/.hermes/soc/feeds/tor_exits.txt` | Plain text, one IP per line |
| Feodo C2 tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | `~/.hermes/soc/feeds/feodo_c2.txt` | Plain text, one IP per line |
| Emerging Threats | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | `~/.hermes/soc/feeds/et_compromised.txt` | Plain text, one IP per line |
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | `~/.hermes/soc/feeds/spamhaus_drop.txt` | CIDR ranges with comments |

**Daily refresh:** cron job or Triage startup routine:
```bash
# Add to crontab -e:
0 6 * * * /home/user/.hermes/soc/scripts/refresh_feeds.sh
```

**Refresh script skeleton:**
```bash
#!/bin/bash
FEEDS_DIR="/home/user/.hermes/soc/feeds"
curl -s https://check.torproject.org/torbulkexitlist > $FEEDS_DIR/tor_exits.txt
curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.txt > $FEEDS_DIR/feodo_c2.txt
curl -s https://rules.emergingthreats.net/blockrules/compromised-ips.txt > $FEEDS_DIR/et_compromised.txt
curl -s https://www.spamhaus.org/drop/drop.txt > $FEEDS_DIR/spamhaus_drop.txt
```

---

## 5. Threat intelligence — API feeds (optional, key required)

Each degrades gracefully if key is missing. Set keys in .env — Intel agent checks for presence before calling.

### AbuseIPDB
**Purpose:** IP reputation score (0-100), report count, abuse categories  
**Free tier:** 1000 requests/day  
**Signup:** https://www.abuseipdb.com/register  
**Endpoint:** `https://api.abuseipdb.com/api/v2/check`  
**Key:** `ABUSEIPDB_API_KEY` in .env  
**Rate limit protection:** 24h cache per IP in `intel_cache.json` — same IP uses cache

### IPinfo
**Purpose:** Geolocation, ASN, org name, hosting provider boolean  
**Free tier:** 50,000 requests/month  
**Signup:** https://ipinfo.io/signup  
**Endpoint:** `https://ipinfo.io/<IP>/json`  
**Key:** `IPINFO_API_KEY` in .env  
**Rate limit protection:** 24h cache per IP

### GreyNoise (optional — lower priority)
**Purpose:** Internet scanner classification, known scanner name  
**Free community tier:** Limited lookups  
**Signup:** https://viz.greynoise.io/signup  
**Endpoint:** `https://api.greynoise.io/v3/community/<IP>`  
**Key:** `GREYNOISE_API_KEY` in .env  
**Rate limit protection:** 24h cache per IP

### Shodan (optional — lowest priority)
**Purpose:** Open ports and services on the IP  
**Cost:** Paid (membership ~$49/year for full access)  
**Signup:** https://account.shodan.io/register  
**Endpoint:** `https://api.shodan.io/shodan/host/<IP>`  
**Key:** `SHODAN_API_KEY` in .env  
**Note:** Lower priority — only add after other feeds are working

---

## 6. MITRE ATT&CK STIX data

**Purpose:** Local lookup — technique ID → threat actor groups (no API call per ticket)  
**Source:** https://github.com/mitre-attack/attack-stix-data  
**File:** Enterprise ATT&CK STIX 2.1 JSON bundle  
**Local path:** `~/.hermes/soc/attack_stix.json`  
**Size:** ~30MB  
**Update frequency:** When MITRE releases a new version (roughly quarterly)

**One-time download:**
```bash
curl -L "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" \
  -o ~/.hermes/soc/attack_stix.json
```

**Used by:** Intel agent — MITRE group correlation

---

## 7. System services (must be installed and running)

### Already installed — verify status
```bash
sudo systemctl status suricata
sudo systemctl status wazuh-manager   # or wazuh-agent
sudo systemctl status apache2
sudo systemctl status ufw
sudo systemctl status tailscaled
sudo systemctl status splunk          # runs as splunk user
```

| Service | Port | Purpose | V2 action needed |
|---|---|---|---|
| Suricata | — | Network IDS, eve.json log source | Fix flow logging (Tier 2) |
| Wazuh | — | EDR, alerts log source | Fix and enable (Tier 4) |
| Apache2 | 80, 443 | Web server, access log source | None — already tailed |
| UFW | — | Firewall, Responder uses for block | None |
| Tailscale | — | Remote access | None |
| Splunk | 8000, 8088, 8089 | SIEM (separate from V2 pipeline) | None |
| LM Studio | 1234 | Local LLM inference | Stability fix required |
| homelab-dashboard | 5000 | Flask app — extend with /briefs, /brief, /respond | Add 3 new routes |
| photo-gallery | 5001 | Separate Flask app | None |

### Needs installing — before implementation

**auditd (Tier 3):**
```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Cowrie (Tier 5 — install last):**
```bash
sudo apt install python3-venv libssl-dev libffi-dev -y
sudo adduser --disabled-password cowrie
# Full install steps in soc_v2_coverage_expansion.md Tier 5
```

**iptables-persistent (needed for Tier 5 port redirect):**
```bash
sudo apt install iptables-persistent -y
```

---

## 8. Port registry (full V2)

| Port | Service | Notes |
|---|---|---|
| 22 | Cowrie honeypot (Tier 5) | Redirected from real SSH via iptables |
| 80 | Apache2 / Nextcloud HTTP | Existing |
| 443 | Nextcloud HTTPS | Existing |
| 1234 | LM Studio inference | Local only |
| 2222 | Real SSH (Tier 5) | Moved off 22 when Cowrie deployed |
| 2223 | Cowrie internal listen (Tier 5) | iptables routes 22 → 2223 |
| 5000 | Flask SOC dashboard | Add /briefs, /brief/<id>, /respond |
| 5001 | Photo gallery Flask app | Existing, no change |
| 8000 | Splunk Web UI | Existing |
| 8088 | Splunk HEC | Existing |
| 8089 | Splunk REST API | Existing |

---

## 9. File paths — V2 working directory

All SOC V2 state lives under `~/.hermes/soc/`. Create subdirectories on setup:

```bash
mkdir -p ~/.hermes/soc/{tickets,cases,snapshots,feeds,scripts}
```

| Path | Contents | Written by |
|---|---|---|
| `~/.hermes/soc/ip_stats.json` | Live per-IP statistics | Triage |
| `~/.hermes/soc/investigator_state.json` | Last processed event_id | Investigator |
| `~/.hermes/soc/intel_cache.json` | IP enrichment cache (24h TTL) | Intel |
| `~/.hermes/soc/attack_stix.json` | MITRE ATT&CK STIX data | One-time download |
| `~/.hermes/soc/operator_response.json` | Operator decision handoff | Flask /respond |
| `~/.hermes/soc/tickets/SOC-XXXX.json` | Individual ticket files | Investigator, Intel, Responder |
| `~/.hermes/soc/cases/SOC-XXXX_DATE.md` | Forensic case files | Auditor |
| `~/.hermes/soc/cases/SOC-XXXX_DATE.ocsf.json` | OCSF exports | Auditor |
| `~/.hermes/soc/snapshots/SOC-XXXX_TIME.json` | Pre-action system snapshots | Responder |
| `~/.hermes/soc/feeds/tor_exits.txt` | Tor exit node list | Daily cron |
| `~/.hermes/soc/feeds/feodo_c2.txt` | Feodo C2 IPs | Daily cron |
| `~/.hermes/soc/feeds/et_compromised.txt` | ET compromised IPs | Daily cron |
| `~/.hermes/soc/feeds/spamhaus_drop.txt` | Spamhaus DROP CIDRs | Daily cron |

### Log sources tailed by Triage

| Log path | Source | Tier |
|---|---|---|
| `/var/log/suricata/eve.json` | Suricata IDS | V2 base |
| `/var/log/auth.log` | SSH, sudo, account events | V2 base |
| `/var/log/syslog` | System events, cron, services | V2 base |
| `/var/log/apache2/access.log` | Web requests | V2 base |
| `/var/log/apache2/error.log` | Web errors | V2 base |
| `/var/log/ufw.log` | Firewall blocks | V2 base |
| `/var/log/audit/audit.log` | Kernel-level events | Tier 3 (auditd) |
| `/var/ossec/logs/alerts/alerts.json` | Wazuh EDR alerts | Tier 4 (Wazuh) |
| `/home/cowrie/cowrie/log/cowrie.json` | Honeypot interactions | Tier 5 (Cowrie) |

---

## 10. Environment variables (.env file)

Create at `/home/user/.hermes/soc/.env`  
Load with python-dotenv in all agents.  
Never commit to GitHub.

```env
# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# LLM — local
LM_STUDIO_BASE_URL=http://127.0.0.1:1234/v1
LM_STUDIO_MODEL=qwen/qwen3-4b-2507

# LLM — cloud (Vega fallback)
OPENROUTER_API_KEY=your_openrouter_key_here
OPENROUTER_MODEL=deepseek/deepseek-chat

# Threat intel APIs (all optional — degrade gracefully if missing)
ABUSEIPDB_API_KEY=
IPINFO_API_KEY=
GREYNOISE_API_KEY=
SHODAN_API_KEY=

# Responder safety
RESPONDER_DRY_RUN=true
# Set to false only when fully tested

# Server identity
SERVER_LAN_IP=10.0.0.108
SERVER_TAILSCALE_IP=100.x.x.x
SERVER_USER=user

# Paths
SOC_BASE_DIR=/home/user/.hermes/soc
HERMES_DIR=/home/user/.hermes
```

---

## 11. Sudoers rules (Responder)

Responder needs passwordless sudo for specific containment commands only.  
Never give blanket sudo — scope each command exactly.

Create file: `/etc/sudoers.d/soc_responder`

```
# SOC V2 Responder — scoped passwordless sudo
# Firewall
user ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from * to any *
user ALL=(ALL) NOPASSWD: /usr/sbin/ufw delete deny from * to any
user ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose

# Session termination
user ALL=(ALL) NOPASSWD: /usr/bin/pkill -KILL -u *
user ALL=(ALL) NOPASSWD: /usr/sbin/ss -K dst *

# Account management
user ALL=(ALL) NOPASSWD: /usr/sbin/usermod -L *
user ALL=(ALL) NOPASSWD: /usr/sbin/usermod -U *

# Cron management
user ALL=(ALL) NOPASSWD: /usr/bin/crontab -r -u *
user ALL=(ALL) NOPASSWD: /usr/bin/crontab -l -u *

# Service management (security tools only)
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl start suricata
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop suricata
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl start wazuh-manager
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop wazuh-manager
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl start ufw
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl enable *
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl disable *

# Null routing
user ALL=(ALL) NOPASSWD: /usr/sbin/ip route add blackhole *
user ALL=(ALL) NOPASSWD: /usr/sbin/ip route del blackhole *

# Snapshot commands
user ALL=(ALL) NOPASSWD: /usr/bin/ss -tnp
user ALL=(ALL) NOPASSWD: /usr/bin/ps aux
user ALL=(ALL) NOPASSWD: /usr/bin/last -n 10
user ALL=(ALL) NOPASSWD: /usr/bin/who
```

Validate after creating:
```bash
sudo visudo -c -f /etc/sudoers.d/soc_responder
```

---

## 12. systemd services

### Existing services (no change)
- `homelab-dashboard.service` — Flask on port 5000 (add new routes, don't recreate)
- `photo-gallery.service` — Flask on port 5001
- `Splunkd.service` — Splunk
- `suricata.service` — Suricata

### New service — SOC V2 Orchestrator
Create: `/etc/systemd/system/soc-v2.service`

```ini
[Unit]
Description=SOC V2 Multi-Agent Pipeline
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/.hermes/soc
EnvironmentFile=/home/user/.hermes/soc/.env
ExecStart=/usr/bin/python3 /home/user/.hermes/soc/orchestrator.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable soc-v2
sudo systemctl start soc-v2
```

### Hermes (existing — Vega)
Already running as a service. Check:
```bash
sudo systemctl status hermes
```

---

## 13. Network requirements

All external calls made by SOC V2:

| Destination | Purpose | Frequency | Agent |
|---|---|---|---|
| `api.telegram.org` | Send brief notifications | Per ticket | Orchestrator |
| `api.telegram.org` | Vega inbound polling | Continuous | Vega/Hermes |
| `check.torproject.org` | Tor feed refresh | Once daily | Cron |
| `feodotracker.abuse.ch` | Feodo feed refresh | Once daily | Cron |
| `rules.emergingthreats.net` | ET feed refresh | Once daily | Cron |
| `www.spamhaus.org` | Spamhaus feed refresh | Once daily | Cron |
| `api.abuseipdb.com` | IP reputation (optional) | Per unique IP per 24h | Intel |
| `ipinfo.io` | Geolocation (optional) | Per unique IP per 24h | Intel |
| `api.greynoise.io` | Scanner detection (optional) | Per unique IP per 24h | Intel |
| `api.shodan.io` | Open ports (optional) | Per unique IP per 24h | Intel |
| `openrouter.ai` | Vega cloud LLM (optional) | Per natural language query | Vega |
| `127.0.0.1:1234` | Local LLM inference | Per Investigator cycle | Investigator, Orchestrator, Auditor |

No other outbound connections. All detection is local. Internal IPs are never sent to external APIs.

---

## 14. Hardware constraints

| Resource | Available | Constraint |
|---|---|---|
| RAM | 16GB | Sufficient for all agents + LM Studio + Splunk simultaneously |
| VRAM | 4GB (GTX 1650 Ti Mobile) | Limits local model to ≤4B parameters. qwen3-4b-2507 uses ~2.33 GiB — fits |
| Storage | 1TB+ | Log rotation needed — eve.json can grow large with flow logging enabled |
| CPU | — | LM Studio inference CPU-heavy when VRAM full — monitor during load |

**Log rotation — add before enabling Suricata flow logging:**
```bash
sudo nano /etc/logrotate.d/suricata
```
```
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP suricata.service
    endscript
}
```

---

## 15. Quick verification checklist

Run before starting implementation:

```bash
# Python version
python3 --version                          # must be 3.10+

# pip packages
pip show flask requests python-dotenv      # must all be installed

# LM Studio
lms server status                          # must be running on 1234
curl http://127.0.0.1:1234/v1/models       # must return model list

# Log sources accessible
tail -1 /var/log/auth.log                  # must return a line
tail -1 /var/log/suricata/eve.json         # must return JSON
tail -1 /var/log/syslog                    # must return a line
tail -1 /var/log/apache2/access.log        # must return a line

# Services running
sudo systemctl is-active suricata          # active
sudo systemctl is-active apache2           # active
sudo systemctl is-active homelab-dashboard # active (Flask port 5000)

# Telegram (replace TOKEN and CHAT_ID with real values)
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
  -d "chat_id=$TELEGRAM_CHAT_ID&text=SOC V2 test"

# SOC directories
ls ~/.hermes/soc/                          # must show tickets/ cases/ etc

# Sudoers valid
sudo visudo -c -f /etc/sudoers.d/soc_responder
```

---

*Last updated: 2026-07-26 — requirements complete for all V2 tiers*
