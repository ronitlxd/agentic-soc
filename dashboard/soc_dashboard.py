#!/usr/bin/env python3
"""
VEGA SOC DASHBOARD
Stdlib-only web dashboard. Serves live agent activity from the JSON files
Triage / Investigator / Intel / Responder / Auditor already write.

No external dependencies. Run:
    python3 soc_dashboard.py
Then open http://<server-ip>:9200 from any device on the LAN.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── paths ─────────────────────────────────────────────────────────────────────
SOC_DIR    = os.path.expanduser("~/.hermes/soc")
BUFFER     = os.path.join(SOC_DIR, "findings_buffer.json")
TICKETS    = os.path.join(SOC_DIR, "tickets.json")
STATE      = os.path.join(SOC_DIR, "investigator_state.json")
SIZES      = os.path.join(SOC_DIR, "log_sizes.json")
CASES_DIR  = os.path.join(SOC_DIR, "cases")

PORT       = int(os.environ.get("SOC_DASHBOARD_PORT", "9200"))
SERVICE    = "soc-orchestrator.service"

# Rule → MITRE ATT&CK tactic (for the coverage heatmap)
RULE_MITRE = {
    "R1_RECON_TO_EXPLOIT":    ("T1595 / T1190", "Recon → Initial Access"),
    "R2_BRUTE_FORCE_SUCCESS": ("T1110.001 / T1078", "Credential Access"),
    "R3_LOGIN_TO_C2":         ("T1078 / T1071", "Command & Control"),
    "R4_LATERAL_MOVEMENT":    ("T1021.004", "Lateral Movement"),
    "R5_EXFILTRATION":        ("T1048", "Exfiltration"),
    "R6_OFFHOURS":            ("T1078", "Initial Access"),
    "R7_LOG_TAMPER":          ("T1070.002", "Defense Evasion"),
}


# ── data helpers ──────────────────────────────────────────────────────────────

def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def entry_ts(e):
    try:
        return datetime.fromisoformat(e["timestamp"]).timestamp()
    except (KeyError, ValueError, TypeError):
        return 0


def get_events():
    data = read_json(BUFFER, {"entries": []})
    entries = data.get("entries", [])
    entries.sort(key=entry_ts, reverse=True)
    return entries[:300]  # newest 300


def get_tickets():
    data = read_json(TICKETS, [])
    if isinstance(data, dict):          # tolerate {"tickets": [...]}
        data = data.get("tickets", [])
    return data


def extract_rule(ticket):
    for f in ticket.get("findings", []):
        note = f.get("note", "")
        if "Rule: R" in note:
            import re
            m = re.search(r"Rule: (R\d+_\w+)", note)
            if m:
                return m.group(1)
    return None


def service_status():
    try:
        r = subprocess.run(
            ["systemctl", "--user", "is-active", SERVICE],
            capture_output=True, text=True, timeout=5,
        )
        active = r.stdout.strip()
        u = subprocess.run(
            ["systemctl", "--user", "show", SERVICE,
             "--property=ActiveEnterTimestamp", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        return active, u.stdout.strip()
    except Exception:
        return "unknown", ""


# ── API payloads ──────────────────────────────────────────────────────────────

def api_events():
    return get_events()


def api_tickets():
    tickets = get_tickets()
    for t in tickets:
        t["_rule"] = extract_rule(t)
    return tickets


def api_health():
    events   = read_json(BUFFER, {"entries": []}).get("entries", [])
    state    = read_json(STATE, {"last_processed": 0})
    sizes    = read_json(SIZES, {})
    active, since = service_status()

    latest = max((entry_ts(e) for e in events), default=0)
    stale  = (now_ts() - latest) > 600 if latest else True

    # Event counts by source (proxy for which watchers are alive)
    by_source = Counter(e.get("source", "?") for e in events)

    last_proc = state.get("last_processed", 0)
    return {
        "service_active":   active,
        "service_since":    since,
        "buffer_size":      len(events),
        "latest_event_age": round(now_ts() - latest) if latest else None,
        "stale":            stale,
        "investigator_last": round(now_ts() - last_proc) if last_proc else None,
        "sources":          dict(by_source),
        "monitored_logs":   list(sizes.keys()),
        "server_time":      datetime.now(timezone.utc).isoformat(),
    }


def api_metrics():
    tickets  = get_tickets()
    by_rule  = Counter()
    by_sev   = Counter()
    by_status = Counter()

    for t in tickets:
        rule = extract_rule(t) or "unmatched"
        by_rule[rule]   += 1
        by_sev[t.get("severity", "unknown").lower()] += 1
        by_status[t.get("status", "open").lower()]   += 1

    # MITRE coverage: which rules have actually fired
    fired = set(by_rule.keys())
    mitre = []
    for rule, (tech, tactic) in RULE_MITRE.items():
        mitre.append({
            "rule":   rule,
            "tech":   tech,
            "tactic": tactic,
            "count":  by_rule.get(rule, 0),
            "fired":  rule in fired,
        })

    # cases written
    try:
        cases = len([f for f in os.listdir(CASES_DIR) if f.endswith(".txt")])
    except FileNotFoundError:
        cases = 0

    return {
        "total_tickets": len(tickets),
        "by_rule":       dict(by_rule),
        "by_severity":   dict(by_sev),
        "by_status":     dict(by_status),
        "mitre":         mitre,
        "cases_written": cases,
    }


ROUTES = {
    "/api/events":  api_events,
    "/api/tickets": api_tickets,
    "/api/health":  api_health,
    "/api/metrics": api_metrics,
}


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # silence per-request logging

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            self._send(200, HTML, "text/html")
            return
        fn = ROUTES.get(path)
        if fn:
            try:
                self._send(200, json.dumps(fn()))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
            return
        self._send(404, json.dumps({"error": "not found"}))


# ── frontend (single embedded page) ───────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vega SOC</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root{
    --bg:#0a0e14; --panel:#111722; --panel2:#161d2b; --line:#232c3d;
    --txt:#c7d1e0; --dim:#7c899e; --accent:#4da3ff;
    --crit:#ff4d5e; --high:#ff9640; --med:#ffd23f; --low:#3ecf8e; --info:#4da3ff;
    --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--txt);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
  header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
  header h1{font-size:17px;font-weight:600;letter-spacing:.3px;display:flex;align-items:center;gap:10px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--low);box-shadow:0 0 8px var(--low)}
  .dot.stale{background:var(--high);box-shadow:0 0 8px var(--high)}
  .dot.down{background:var(--crit);box-shadow:0 0 8px var(--crit)}
  header .meta{font-size:12px;color:var(--dim);font-family:var(--mono)}
  .wrap{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:14px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;display:flex;flex-direction:column;min-height:0}
  .panel h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);padding:11px 15px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
  .panel h2 .badge{background:var(--panel2);color:var(--accent);padding:2px 8px;border-radius:20px;font-size:11px;letter-spacing:0}
  .body{padding:12px 15px;overflow-y:auto;max-height:44vh}
  .full{grid-column:1/3}
  /* event feed */
  .ev{display:grid;grid-template-columns:64px 78px 1fr;gap:8px;padding:5px 0;border-bottom:1px solid var(--panel2);font-family:var(--mono);font-size:12px;align-items:baseline}
  .ev .t{color:var(--dim)}
  .ev .s{color:var(--accent);text-transform:uppercase;font-size:10.5px}
  .ev .d{color:var(--txt);word-break:break-word}
  .tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:10px;background:var(--panel2);color:var(--dim);margin-right:5px}
  /* tickets */
  .tk{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:9px;background:var(--panel2)}
  .tk .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
  .tk .id{font-family:var(--mono);font-size:12px;color:var(--accent)}
  .tk .ti{font-size:13px;margin:3px 0;color:#e6ecf5}
  .tk .rule{font-family:var(--mono);font-size:11px;color:var(--dim)}
  .pill{font-size:10px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:20px;letter-spacing:.5px}
  .pill.critical{background:rgba(255,77,94,.15);color:var(--crit)}
  .pill.high{background:rgba(255,150,64,.15);color:var(--high)}
  .pill.medium{background:rgba(255,210,63,.15);color:var(--med)}
  .pill.low{background:rgba(62,207,142,.15);color:var(--low)}
  .pill.unknown{background:var(--panel);color:var(--dim)}
  .st{font-size:10px;color:var(--dim);font-family:var(--mono);text-transform:uppercase}
  /* health */
  .hgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .stat{background:var(--panel2);border-radius:8px;padding:11px 13px}
  .stat .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
  .stat .v{font-size:22px;font-weight:600;margin-top:3px;font-family:var(--mono)}
  .src{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .src span{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:3px 8px;font-size:11px;font-family:var(--mono)}
  .src b{color:var(--accent)}
  /* metrics */
  .charts{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .chartbox{background:var(--panel2);border-radius:8px;padding:12px;height:220px;position:relative}
  .chartbox h3{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
  /* mitre */
  .mitre{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-top:12px}
  .mcell{border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:var(--panel2);opacity:.45}
  .mcell.fired{opacity:1;border-color:var(--accent);box-shadow:0 0 0 1px rgba(77,163,255,.25)}
  .mcell .r{font-family:var(--mono);font-size:11px;color:var(--accent)}
  .mcell .tc{font-size:12px;margin:3px 0;color:#e6ecf5}
  .mcell .tech{font-family:var(--mono);font-size:10px;color:var(--dim)}
  .mcell .c{float:right;font-family:var(--mono);font-size:12px;font-weight:700}
  .empty{color:var(--dim);font-style:italic;padding:18px;text-align:center}
  @media(max-width:900px){.wrap{grid-template-columns:1fr}.full{grid-column:1}.charts{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <h1><span id="hdot" class="dot"></span> VEGA&nbsp;SOC <span style="color:var(--dim);font-weight:400;font-size:13px">· Multi-Agent Monitor</span></h1>
  <div class="meta" id="hmeta">connecting…</div>
</header>

<div class="wrap">
  <!-- AGENT HEALTH -->
  <div class="panel">
    <h2>Agent Health <span class="badge" id="svc">—</span></h2>
    <div class="body" id="health"></div>
  </div>

  <!-- TICKET BOARD -->
  <div class="panel">
    <h2>Ticket Board <span class="badge" id="tkn">0</span></h2>
    <div class="body" id="tickets"></div>
  </div>

  <!-- METRICS -->
  <div class="panel full">
    <h2>Metrics &amp; MITRE ATT&amp;CK Coverage</h2>
    <div class="body" style="max-height:none">
      <div class="charts">
        <div class="chartbox"><h3>Tickets by Rule</h3><canvas id="cRule"></canvas></div>
        <div class="chartbox"><h3>Severity Breakdown</h3><canvas id="cSev"></canvas></div>
      </div>
      <div class="mitre" id="mitre"></div>
    </div>
  </div>

  <!-- LIVE EVENT FEED -->
  <div class="panel full">
    <h2>Live Event Feed <span class="badge" id="evn">0</span></h2>
    <div class="body" id="events" style="max-height:40vh"></div>
  </div>
</div>

<script>
const SEV=["critical","high","medium","low"];
let ruleChart, sevChart;

function ago(s){ if(s==null)return "—"; if(s<60)return s+"s"; if(s<3600)return Math.floor(s/60)+"m"; return Math.floor(s/3600)+"h";}
function esc(x){return (x==null?"":String(x)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function hhmmss(iso){try{return new Date(iso).toLocaleTimeString('en-GB');}catch(e){return "";}}

async function j(u){const r=await fetch(u);return r.json();}

async function refresh(){
  try{
    const [health,tickets,events,metrics]=await Promise.all([
      j('/api/health'),j('/api/tickets'),j('/api/events'),j('/api/metrics')]);
    renderHealth(health);
    renderTickets(tickets);
    renderEvents(events);
    renderMetrics(metrics);
    document.getElementById('hmeta').textContent =
      'updated '+new Date().toLocaleTimeString('en-GB')+' · buffer '+health.buffer_size;
  }catch(e){
    document.getElementById('hmeta').textContent='connection lost — retrying…';
  }
}

function renderHealth(h){
  const dot=document.getElementById('hdot');
  dot.className='dot'+(h.service_active!=='active'?' down':(h.stale?' stale':''));
  document.getElementById('svc').textContent=h.service_active;
  const srcs=Object.entries(h.sources).sort((a,b)=>b[1]-a[1])
    .map(([k,v])=>`<span>${esc(k)} <b>${v}</b></span>`).join('');
  document.getElementById('health').innerHTML=`
    <div class="hgrid">
      <div class="stat"><div class="k">Service</div><div class="v" style="color:${h.service_active==='active'?'var(--low)':'var(--crit)'}">${esc(h.service_active)}</div></div>
      <div class="stat"><div class="k">Buffer Events</div><div class="v">${h.buffer_size}</div></div>
      <div class="stat"><div class="k">Last Event</div><div class="v" style="color:${h.stale?'var(--high)':'var(--low)'}">${ago(h.latest_event_age)}</div></div>
      <div class="stat"><div class="k">Investigator Ran</div><div class="v">${ago(h.investigator_last)} ago</div></div>
    </div>
    <div style="margin-top:11px"><div class="k" style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px">Events by Source</div>
    <div class="src">${srcs||'<span>no events</span>'}</div></div>
    <div style="margin-top:11px"><div class="k" style="font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px">Monitored Logs (${h.monitored_logs.length})</div>
    <div class="src">${h.monitored_logs.map(l=>`<span>${esc(l.split('/').pop())}</span>`).join('')||'<span>—</span>'}</div></div>`;
}

function renderTickets(ts){
  document.getElementById('tkn').textContent=ts.length;
  if(!ts.length){document.getElementById('tickets').innerHTML='<div class="empty">No tickets — system quiet</div>';return;}
  const order={critical:0,high:1,medium:2,low:3};
  ts.sort((a,b)=>(order[(a.severity||'').toLowerCase()]??9)-(order[(b.severity||'').toLowerCase()]??9));
  document.getElementById('tickets').innerHTML=ts.slice(0,40).map(t=>{
    const sev=(t.severity||'unknown').toLowerCase();
    return `<div class="tk">
      <div class="top"><span class="id">${esc(t.id||'—')}</span>
        <span><span class="pill ${sev}">${esc(sev)}</span> <span class="st">${esc(t.status||'open')}</span></span></div>
      <div class="ti">${esc(t.title||'(no title)')}</div>
      <div class="rule">${esc(t._rule||t.source||'')}</div>
    </div>`;}).join('');
}

function renderEvents(evs){
  document.getElementById('evn').textContent=evs.length;
  if(!evs.length){document.getElementById('events').innerHTML='<div class="empty">Buffer empty</div>';return;}
  document.getElementById('events').innerHTML=evs.map(e=>{
    const d=e.signature||e.detail||e.message||e.path||e.username||e.raw||'';
    const extra=(e.src_ip&&e.src_ip!=='local'&&e.src_ip!=='unknown')?`<span class="tag">${esc(e.src_ip)}</span>`:'';
    return `<div class="ev"><span class="t">${hhmmss(e.timestamp)}</span>
      <span class="s">${esc(e.source||'')}</span>
      <span class="d">${extra}<span class="tag">${esc(e.event_type||'')}</span>${esc(String(d).slice(0,120))}</span></div>`;
  }).join('');
}

function renderMetrics(m){
  // rule chart
  const rl=Object.entries(m.by_rule);
  const rlLabels=rl.map(x=>x[0].replace(/^R\d+_/,''));
  const rlData=rl.map(x=>x[1]);
  if(!ruleChart){
    ruleChart=new Chart(document.getElementById('cRule'),{type:'bar',
      data:{labels:rlLabels,datasets:[{data:rlData,backgroundColor:'#4da3ff'}]},
      options:baseOpts()});
  }else{ruleChart.data.labels=rlLabels;ruleChart.data.datasets[0].data=rlData;ruleChart.update();}

  // severity donut
  const sv=SEV.map(s=>m.by_severity[s]||0);
  const cols=['#ff4d5e','#ff9640','#ffd23f','#3ecf8e'];
  if(!sevChart){
    sevChart=new Chart(document.getElementById('cSev'),{type:'doughnut',
      data:{labels:SEV,datasets:[{data:sv,backgroundColor:cols,borderColor:'#161d2b',borderWidth:2}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#7c899e',boxWidth:12,font:{size:11}}}}}});
  }else{sevChart.data.datasets[0].data=sv;sevChart.update();}

  // mitre heatmap
  document.getElementById('mitre').innerHTML=m.mitre.map(x=>`
    <div class="mcell ${x.fired?'fired':''}">
      <span class="c" style="color:${x.count?'var(--accent)':'var(--dim)'}">${x.count}</span>
      <div class="r">${esc(x.rule.replace(/^R\d+_/,''))}</div>
      <div class="tc">${esc(x.tactic)}</div>
      <div class="tech">${esc(x.tech)}</div>
    </div>`).join('');
}

function baseOpts(){return{responsive:true,maintainAspectRatio:false,
  plugins:{legend:{display:false}},
  scales:{x:{ticks:{color:'#7c899e',font:{size:10}},grid:{display:false}},
          y:{ticks:{color:'#7c899e',stepSize:1},grid:{color:'#232c3d'},beginAtZero:true}}};}

refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(SOC_DIR, exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("[DASHBOARD] Vega SOC dashboard on http://0.0.0.0:{}".format(PORT))
    print("[DASHBOARD] Reading from {}".format(SOC_DIR))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
