#!/usr/bin/env python3
"""
AGENTIC SOC — DASHBOARD
Stdlib-only web dashboard that shows HOW the multi-agent system works.

Three views:
  • Agents   — a grid of the six agents, what each is doing, and their live logs
  • Cases    — pick a ticket and watch it hand off from agent to agent
  • Activity — live event feed + system health

Everything is reconstructed from the `agent` field stamped on every ticket
finding, plus the Triage event buffer. No external dependencies.

    python3 soc_dashboard.py    →    http://<host>:9200
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── paths ─────────────────────────────────────────────────────────────────────
SOC_DIR   = os.path.expanduser("~/.hermes/soc")
BUFFER    = os.path.join(SOC_DIR, "findings_buffer.json")
TICKETS   = os.path.join(SOC_DIR, "tickets.json")
STATE     = os.path.join(SOC_DIR, "investigator_state.json")
CASES_DIR = os.path.join(SOC_DIR, "cases")

PORT    = int(os.environ.get("SOC_DASHBOARD_PORT", "9200"))
SERVICE = "soc-orchestrator.service"
ACTIVE_WINDOW = 900   # an agent is "active" if it acted in the last 15 min

# The six agents, in pipeline order. `key` matches the --agent field in findings.
AGENTS = [
    {"key": "triage",       "name": "Triage",       "role": "The Watcher",
     "desc": "Collects and parses every log line", "count_label": "events collected", "icon": "\U0001F441"},
    {"key": "investigator", "name": "Investigator", "role": "The Analyst",
     "desc": "Correlates events into attacks",      "count_label": "attacks detected", "icon": "\U0001F9E0"},
    {"key": "intel",        "name": "Intel",        "role": "The Researcher",
     "desc": "Enriches suspicious indicators",      "count_label": "indicators enriched", "icon": "\U0001F50E"},
    {"key": "coordinator",  "name": "Coordinator (Vega)", "role": "The Shift Lead",
     "desc": "Briefs the operator, routes each case", "count_label": "cases coordinated", "icon": "\U0001F399"},
    {"key": "responder",    "name": "Responder",    "role": "The Operator",
     "desc": "Executes approved containment",       "count_label": "actions taken", "icon": "\U0001F6E1"},
    {"key": "auditor",      "name": "Auditor",      "role": "The Scribe",
     "desc": "Writes the forensic case file",       "count_label": "cases documented", "icon": "\U0001F4DD"},
]
AGENT_BY_KEY = {a["key"]: a for a in AGENTS}


# ── data helpers ──────────────────────────────────────────────────────────────

def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def to_ts(iso):
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0


def get_tickets():
    data = read_json(TICKETS, [])
    if isinstance(data, dict):
        data = data.get("tickets", [])
    return data if isinstance(data, list) else []


def get_events():
    data = read_json(BUFFER, {"entries": []})
    entries = data.get("entries", [])
    entries.sort(key=lambda e: to_ts(e.get("timestamp", "")), reverse=True)
    return entries


def all_findings():
    """Flatten every finding across every ticket, tagged with its ticket id."""
    out = []
    for t in get_tickets():
        tid = t.get("id", "?")
        for f in t.get("findings", []):
            out.append({
                "ticket": tid,
                "agent":  f.get("agent", "?"),
                "note":   f.get("note", ""),
                "ts":     f.get("timestamp", ""),
            })
    return out


def service_status():
    try:
        r = subprocess.run(["systemctl", "--user", "is-active", SERVICE],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception:
        return "unknown"


# ── API payloads ──────────────────────────────────────────────────────────────

def api_agents():
    """Summary card data for each of the six agents."""
    findings = all_findings()
    by_agent = {}
    for f in findings:
        by_agent.setdefault(f["agent"], []).append(f)

    events   = get_events()
    buf_latest = to_ts(events[0]["timestamp"]) if events else 0

    cards = []
    for a in AGENTS:
        key = a["key"]

        if key == "triage":
            count      = len(events)
            last_ts    = buf_latest
            e          = events[0] if events else {}
            last_note  = "{} · {}".format(
                e.get("source", ""),
                e.get("signature") or e.get("event_type") or "")
        else:
            items   = sorted(by_agent.get(key, []), key=lambda x: to_ts(x["ts"]), reverse=True)
            count   = len(items)
            last_ts = to_ts(items[0]["ts"]) if items else 0
            last_note = (items[0]["note"][:110] if items else "")

        # investigator "attacks detected" = distinct tickets it opened
        if key == "investigator":
            count = len({f["ticket"] for f in by_agent.get(key, [])})

        cards.append({
            "key":         key,
            "name":        a["name"],
            "role":        a["role"],
            "desc":        a["desc"],
            "icon":        a["icon"],
            "count":       count,
            "count_label": a["count_label"],
            "last_note":   last_note,
            "last_age":    round(now_ts() - last_ts) if last_ts else None,
            "active":      bool(last_ts and (now_ts() - last_ts) < ACTIVE_WINDOW),
        })
    return {"agents": cards, "service": service_status()}


def api_agent_log(key):
    """Full activity stream for one agent."""
    if key == "triage":
        rows = []
        for e in get_events()[:200]:
            rows.append({
                "ticket": "",
                "ts":     e.get("timestamp", ""),
                "note":   "[{}] {} {}".format(
                    e.get("source", ""),
                    e.get("event_type", ""),
                    e.get("signature") or e.get("detail") or e.get("message") or ""),
            })
        return {"agent": key, "rows": rows}

    rows = [f for f in all_findings() if f["agent"] == key]
    rows.sort(key=lambda x: to_ts(x["ts"]), reverse=True)
    return {"agent": key, "rows": rows[:200]}


def api_cases():
    """Ticket list for the case-picker."""
    out = []
    for t in get_tickets():
        agents_touched = []
        for f in t.get("findings", []):
            ag = f.get("agent")
            if ag and ag not in agents_touched:
                agents_touched.append(ag)
        out.append({
            "id":       t.get("id", "?"),
            "title":    t.get("title", ""),
            "severity": (t.get("severity") or "unknown").lower(),
            "status":   (t.get("status") or "open").lower(),
            "agents":   agents_touched,
            "ts":       t.get("created") or (t.get("findings") or [{}])[0].get("timestamp", ""),
        })
    out.sort(key=lambda x: to_ts(x["ts"]), reverse=True)
    return {"cases": out}


def api_journey(ticket_id):
    """Ordered handoff timeline for one ticket."""
    for t in get_tickets():
        if t.get("id") == ticket_id:
            steps = sorted(t.get("findings", []), key=lambda f: to_ts(f.get("timestamp", "")))
            return {
                "id":       t.get("id"),
                "title":    t.get("title", ""),
                "severity": (t.get("severity") or "unknown").lower(),
                "status":   (t.get("status") or "open").lower(),
                "steps":    [{"agent": s.get("agent", "?"),
                              "note":  s.get("note", ""),
                              "ts":    s.get("timestamp", "")} for s in steps],
            }
    return {"error": "not found"}


def api_activity():
    events = get_events()
    state  = read_json(STATE, {"last_processed": 0})
    latest = to_ts(events[0]["timestamp"]) if events else 0
    return {
        "service":          service_status(),
        "buffer_size":      len(events),
        "latest_event_age": round(now_ts() - latest) if latest else None,
        "stale":            (now_ts() - latest) > 600 if latest else True,
        "investigator_last": round(now_ts() - state.get("last_processed", 0))
                             if state.get("last_processed") else None,
        "by_source":        dict(Counter(e.get("source", "?") for e in events)),
        "events":           events[:200],
    }


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def do_GET(self):
        path = self.path.split("?")[0]
        parts = [p for p in path.split("/") if p]

        if path in ("/", "/index.html"):
            return self._send(200, HTML, "text/html")

        try:
            if path == "/api/agents":
                return self._send(200, json.dumps(api_agents()))
            if path == "/api/cases":
                return self._send(200, json.dumps(api_cases()))
            if path == "/api/activity":
                return self._send(200, json.dumps(api_activity()))
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "agent":
                return self._send(200, json.dumps(api_agent_log(parts[2])))
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "journey":
                return self._send(200, json.dumps(api_journey(parts[2])))
        except Exception as e:
            return self._send(500, json.dumps({"error": str(e)}))

        self._send(404, json.dumps({"error": "not found"}))


# ── frontend ──────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agentic SOC</title>
<style>
  :root{
    --bg:#0a0e14; --panel:#111722; --panel2:#161d2b; --line:#232c3d;
    --txt:#c7d1e0; --dim:#7c899e; --accent:#4da3ff;
    --crit:#ff4d5e; --high:#ff9640; --med:#ffd23f; --low:#3ecf8e;
    --mono:"SFMono-Regular",Consolas,Menlo,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--txt);font-family:system-ui,Segoe UI,Roboto,sans-serif;font-size:14px}
  header{display:flex;align-items:center;justify-content:space-between;padding:13px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
  header h1{font-size:16px;font-weight:600;display:flex;align-items:center;gap:9px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--low);box-shadow:0 0 8px var(--low)}
  .dot.down{background:var(--crit);box-shadow:0 0 8px var(--crit)}
  .tabs{display:flex;gap:4px}
  .tab{padding:6px 15px;border-radius:7px;cursor:pointer;color:var(--dim);font-size:13px;font-weight:500}
  .tab.on{background:var(--panel2);color:var(--accent)}
  .meta{font-size:11.5px;color:var(--dim);font-family:var(--mono)}
  main{padding:16px 22px;max-width:1400px;margin:0 auto}
  .view{display:none}.view.on{display:block}

  /* agent grid */
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;cursor:pointer;transition:border-color .15s,transform .1s;position:relative}
  .card:hover{border-color:var(--accent);transform:translateY(-2px)}
  .card .flow{position:absolute;top:14px;right:14px;font-family:var(--mono);font-size:11px;color:var(--dim)}
  .card .head{display:flex;align-items:center;gap:11px;margin-bottom:11px}
  .card .ico{font-size:22px;line-height:1}
  .card .nm{font-size:15px;font-weight:600;color:#e6ecf5}
  .card .rl{font-size:11.5px;color:var(--accent);font-weight:500}
  .card .st{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;margin-left:6px}
  .card .st .d{width:7px;height:7px;border-radius:50%}
  .st.active .d{background:var(--low);box-shadow:0 0 6px var(--low)} .st.active{color:var(--low)}
  .st.idle .d{background:var(--dim)} .st.idle{color:var(--dim)}
  .card .desc{font-size:12.5px;color:var(--dim);margin-bottom:13px;min-height:34px}
  .card .num{font-size:30px;font-weight:700;font-family:var(--mono);color:#e6ecf5;line-height:1}
  .card .numlbl{font-size:11.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
  .card .last{margin-top:13px;padding-top:11px;border-top:1px solid var(--line);font-size:11.5px;color:var(--dim);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .card .last b{color:var(--txt);font-weight:400}

  /* cases */
  .caserow{display:grid;grid-template-columns:340px 1fr;gap:16px}
  .list{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;max-height:72vh;overflow-y:auto}
  .li{padding:11px 14px;border-bottom:1px solid var(--panel2);cursor:pointer}
  .li:hover{background:var(--panel2)} .li.on{background:var(--panel2);border-left:3px solid var(--accent)}
  .li .id{font-family:var(--mono);font-size:12px;color:var(--accent)}
  .li .ti{font-size:12.5px;color:#e6ecf5;margin:3px 0;line-height:1.3}
  .li .ags{display:flex;gap:3px;margin-top:5px;flex-wrap:wrap}
  .li .ag{font-size:9px;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:1px 5px;color:var(--dim);text-transform:capitalize}
  .pill{font-size:9.5px;font-weight:700;text-transform:uppercase;padding:2px 7px;border-radius:20px}
  .pill.critical{background:rgba(255,77,94,.15);color:var(--crit)}
  .pill.high{background:rgba(255,150,64,.15);color:var(--high)}
  .pill.medium{background:rgba(255,210,63,.15);color:var(--med)}
  .pill.low{background:rgba(62,207,142,.15);color:var(--low)}
  .pill.unknown{background:var(--panel2);color:var(--dim)}

  /* journey timeline */
  .journey{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;max-height:72vh;overflow-y:auto}
  .jhead{display:flex;align-items:center;gap:10px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--line)}
  .jhead .id{font-family:var(--mono);color:var(--accent);font-size:14px}
  .step{display:grid;grid-template-columns:130px 1fr;gap:14px;position:relative;padding-bottom:18px}
  .step:before{content:"";position:absolute;left:130px;top:6px;bottom:-6px;width:2px;background:var(--line)}
  .step:last-child:before{display:none}
  .step .who{text-align:right;padding-right:16px;position:relative}
  .step .who:after{content:"";position:absolute;right:-6px;top:5px;width:11px;height:11px;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}
  .step .agn{font-size:12.5px;font-weight:600;color:#e6ecf5;text-transform:capitalize}
  .step .tm{font-size:10.5px;color:var(--dim);font-family:var(--mono)}
  .step .note{font-size:12.5px;color:var(--txt);padding-left:16px;line-height:1.45;word-break:break-word}

  /* agent log modal */
  .modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:50;align-items:center;justify-content:center;padding:24px}
  .modal.on{display:flex}
  .sheet{background:var(--panel);border:1px solid var(--line);border-radius:14px;width:100%;max-width:820px;max-height:82vh;display:flex;flex-direction:column;overflow:hidden}
  .sheet .top{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--line)}
  .sheet .top h3{font-size:15px;display:flex;align-items:center;gap:10px}
  .sheet .x{cursor:pointer;color:var(--dim);font-size:22px;line-height:1}
  .sheet .logs{overflow-y:auto;padding:8px 0}
  .logrow{display:grid;grid-template-columns:70px 74px 1fr;gap:10px;padding:7px 20px;border-bottom:1px solid var(--panel2);font-family:var(--mono);font-size:12px;align-items:baseline}
  .logrow .tm{color:var(--dim)} .logrow .tk{color:var(--accent)} .logrow .nt{color:var(--txt);word-break:break-word}

  /* activity */
  .aGrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 15px}
  .stat .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
  .stat .v{font-size:22px;font-weight:700;font-family:var(--mono);margin-top:3px}
  .feed{background:var(--panel);border:1px solid var(--line);border-radius:10px;max-height:60vh;overflow-y:auto}
  .ev{display:grid;grid-template-columns:64px 76px 1fr;gap:8px;padding:6px 15px;border-bottom:1px solid var(--panel2);font-family:var(--mono);font-size:12px}
  .ev .t{color:var(--dim)} .ev .s{color:var(--accent);text-transform:uppercase;font-size:10.5px} .ev .d{color:var(--txt)}
  .empty{color:var(--dim);font-style:italic;padding:26px;text-align:center}
  @media(max-width:820px){.caserow{grid-template-columns:1fr}.aGrid{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<header>
  <h1><span id="hdot" class="dot"></span> AGENTIC&nbsp;SOC</h1>
  <div class="tabs">
    <div class="tab on" data-v="agents">Agents</div>
    <div class="tab" data-v="cases">Cases</div>
    <div class="tab" data-v="activity">Activity</div>
  </div>
  <div class="meta" id="meta">loading…</div>
</header>

<main>
  <section class="view on" id="v-agents"><div class="grid" id="grid"></div></section>

  <section class="view" id="v-cases">
    <div class="caserow">
      <div class="list" id="caseList"></div>
      <div class="journey" id="journey"><div class="empty">Select a case to see how it moved through the agents.</div></div>
    </div>
  </section>

  <section class="view" id="v-activity">
    <div class="aGrid" id="stats"></div>
    <div class="feed" id="feed"></div>
  </section>
</main>

<div class="modal" id="modal">
  <div class="sheet">
    <div class="top"><h3 id="mTitle"></h3><span class="x" onclick="closeModal()">&times;</span></div>
    <div class="logs" id="mLogs"></div>
  </div>
</div>

<script>
const FLOW=["triage","investigator","intel","coordinator","responder","auditor"];
let curView="agents", curCase=null;

function esc(x){return (x==null?"":String(x)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function ago(s){if(s==null)return "—";if(s<60)return s+"s";if(s<3600)return Math.floor(s/60)+"m";if(s<86400)return Math.floor(s/3600)+"h";return Math.floor(s/86400)+"d";}
function hhmm(iso){try{return new Date(iso).toLocaleTimeString('en-GB');}catch(e){return "";}}
async function j(u){const r=await fetch(u);return r.json();}

document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  curView=t.dataset.v;
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===t));
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('on',v.id==='v-'+curView));
  refresh();
});

async function refresh(){
  try{
    if(curView==='agents') await loadAgents();
    else if(curView==='cases') await loadCases();
    else await loadActivity();
    document.getElementById('meta').textContent='updated '+new Date().toLocaleTimeString('en-GB');
  }catch(e){document.getElementById('meta').textContent='connection lost…';}
}

async function loadAgents(){
  const d=await j('/api/agents');
  document.getElementById('hdot').className='dot'+(d.service!=='active'?' down':'');
  document.getElementById('grid').innerHTML=d.agents.map((a,i)=>`
    <div class="card" onclick="openAgent('${a.key}','${esc(a.name)}','${a.icon}')">
      <div class="flow">${i+1}/6</div>
      <div class="head">
        <span class="ico">${a.icon}</span>
        <div><div class="nm">${esc(a.name)}
          <span class="st ${a.active?'active':'idle'}"><span class="d"></span>${a.active?'active':'idle'}</span></div>
          <div class="rl">${esc(a.role)}</div></div>
      </div>
      <div class="desc">${esc(a.desc)}</div>
      <div class="num">${a.count}</div>
      <div class="numlbl">${esc(a.count_label)}</div>
      <div class="last">${a.last_note?('<b>'+esc(a.last_note)+'</b> · '+ago(a.last_age)+' ago'):'no activity yet'}</div>
    </div>`).join('');
}

async function openAgent(key,name,icon){
  const d=await j('/api/agent/'+key);
  document.getElementById('mTitle').innerHTML=icon+' '+esc(name)+' — activity log';
  document.getElementById('mLogs').innerHTML = d.rows.length?d.rows.map(r=>`
    <div class="logrow"><span class="tm">${hhmm(r.ts)}</span>
      <span class="tk">${esc(r.ticket||'')}</span>
      <span class="nt">${esc(r.note)}</span></div>`).join(''):'<div class="empty">No activity recorded yet.</div>';
  document.getElementById('modal').classList.add('on');
}
function closeModal(){document.getElementById('modal').classList.remove('on');}
document.getElementById('modal').onclick=e=>{if(e.target.id==='modal')closeModal();};

async function loadCases(){
  const d=await j('/api/cases');
  document.getElementById('caseList').innerHTML = d.cases.length?d.cases.map(c=>`
    <div class="li ${c.id===curCase?'on':''}" onclick="openCase('${c.id}')">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span class="id">${esc(c.id)}</span><span class="pill ${c.severity}">${esc(c.severity)}</span></div>
      <div class="ti">${esc(c.title)}</div>
      <div class="ags">${c.agents.map(a=>`<span class="ag">${esc(a)}</span>`).join('')}</div>
    </div>`).join(''):'<div class="empty">No cases yet.</div>';
  if(curCase) openCase(curCase,true);
}

async function openCase(id,keep){
  curCase=id;
  document.querySelectorAll('.li').forEach(l=>l.classList.toggle('on',l.querySelector('.id')&&l.querySelector('.id').textContent===id));
  const d=await j('/api/journey/'+id);
  if(d.error){document.getElementById('journey').innerHTML='<div class="empty">Case not found.</div>';return;}
  document.getElementById('journey').innerHTML=`
    <div class="jhead"><span class="id">${esc(d.id)}</span>
      <span class="pill ${d.severity}">${esc(d.severity)}</span>
      <span style="color:var(--dim);font-size:12px">${esc(d.status)}</span>
      <span style="color:#e6ecf5;font-size:13px">${esc(d.title)}</span></div>
    ${d.steps.map(s=>`<div class="step">
        <div class="who"><div class="agn">${esc(s.agent)}</div><div class="tm">${hhmm(s.ts)}</div></div>
        <div class="note">${esc(s.note)}</div></div>`).join('')||'<div class="empty">No steps recorded.</div>'}`;
}

async function loadActivity(){
  const d=await j('/api/activity');
  document.getElementById('hdot').className='dot'+(d.service!=='active'?' down':'');
  document.getElementById('stats').innerHTML=`
    <div class="stat"><div class="k">Service</div><div class="v" style="color:${d.service==='active'?'var(--low)':'var(--crit)'}">${esc(d.service)}</div></div>
    <div class="stat"><div class="k">Buffer Events</div><div class="v">${d.buffer_size}</div></div>
    <div class="stat"><div class="k">Last Event</div><div class="v" style="color:${d.stale?'var(--high)':'var(--low)'}">${ago(d.latest_event_age)}</div></div>
    <div class="stat"><div class="k">Investigator Ran</div><div class="v">${ago(d.investigator_last)} ago</div></div>`;
  document.getElementById('feed').innerHTML = d.events.length?d.events.map(e=>{
    const dd=e.signature||e.detail||e.message||e.username||e.event_type||'';
    return `<div class="ev"><span class="t">${hhmm(e.timestamp)}</span>
      <span class="s">${esc(e.source||'')}</span>
      <span class="d">${esc(String(dd).slice(0,130))}</span></div>`;}).join(''):'<div class="empty">Buffer empty.</div>';
}

refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(SOC_DIR, exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("[DASHBOARD] Agentic SOC dashboard on http://0.0.0.0:{}".format(PORT))
    print("[DASHBOARD] Reading from {}".format(SOC_DIR))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
