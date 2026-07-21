#!/usr/bin/env python3
"""
SOC SIMULATOR — SOC V2 (portfolio demo)
=======================================

A single-page web app that runs the REAL V2 agents against an uploaded (or
built-in) attack log, in an ISOLATED demo sandbox that never touches the live
SOC. Minimal black-and-white UI centered on the seven agents — each agent block
shows its own activity, output, and the data it hands to the next stage.

Run:  python3 soc_demo.py   ->   http://<host>:5010
"""

import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone

# ── isolate the pipeline in a demo namespace BEFORE importing the agents ──────
LIVE_DIR = os.path.expanduser("~/.hermes/soc")
DEMO_DIR = os.path.join(LIVE_DIR, "demo")


def _setup_demo_dir():
    for sub in ("tickets", "cases", "snapshots", "feeds"):
        os.makedirs(os.path.join(DEMO_DIR, sub), exist_ok=True)
    for name in ("attack_stix.json",):
        link, src = os.path.join(DEMO_DIR, name), os.path.join(LIVE_DIR, name)
        if os.path.exists(src) and not os.path.exists(link):
            try:
                os.symlink(src, link)
            except OSError:
                pass
    for name in ("tor_exits.txt", "feodo_c2.txt", "et_compromised.txt", "spamhaus_drop.txt"):
        link = os.path.join(DEMO_DIR, "feeds", name)
        src = os.path.join(LIVE_DIR, "feeds", name)
        if os.path.exists(src) and not os.path.exists(link):
            try:
                os.symlink(src, link)
            except OSError:
                pass


_setup_demo_dir()
os.environ["SOC_BASE_DIR"] = DEMO_DIR
os.environ["RESPONDER_DRY_RUN"] = "true"
os.environ["INVESTIGATOR_STAGE2"] = "false"

import sys
sys.path.insert(0, LIVE_DIR)
import triage_agent
import investigator_agent
import intel_agent
import responder_agent
import auditor_agent

from flask import Flask, jsonify, request

app = Flask(__name__)
DEMO_PORT = int(os.environ.get("SOC_DEMO_PORT", "5010"))

# ── built-in attack scenarios ─────────────────────────────────────────────────
EXT_IP = "203.0.113.45"
EXT_IP2 = "198.51.100.23"


def _sur(sig, sip, dip="10.0.0.10", dport=22):
    return json.dumps({"event_type": "alert", "src_ip": sip, "dest_ip": dip,
                       "dest_port": dport, "alert": {"signature": sig, "severity": 2}})


SCENARIOS = {
    "ssh_bruteforce": {
        "title": "SSH brute-force -> successful login (R2)",
        "lines": ["2026-07-30T02:14:0{}Z server sshd[4410]: Failed password for admin from {} port 552{} ssh2".format(i, EXT_IP, i)
                  for i in range(1, 8)]
                 + ["2026-07-30T02:14:12Z server sshd[4411]: Accepted password for admin from {} port 55230 ssh2".format(EXT_IP)],
    },
    "password_spray": {
        "title": "Password spraying across accounts (R12)",
        "lines": ["2026-07-30T03:01:0{}Z server sshd[52{}]: Failed password for {} from {} port 61000 ssh2".format(i, i, u, EXT_IP2)
                  for i, u in enumerate(["admin", "root", "oracle", "test", "ubuntu", "postgres"], 1)],
    },
    "recon_exploit": {
        "title": "Port scan -> exploit attempt (R1)",
        "lines": [_sur("ET SCAN Potential SSH Scan", EXT_IP), _sur("ET SCAN Nmap Scripting Engine", EXT_IP),
                  "2026-07-30T04:20:01Z server sshd[7001]: Failed password for root from {} port 44001 ssh2".format(EXT_IP),
                  "2026-07-30T04:20:05Z server sshd[7002]: Failed password for admin from {} port 44002 ssh2".format(EXT_IP)],
    },
    "defense_disable": {
        "title": "Attacker disables Suricata (R10 - critical)",
        "lines": ["2026-07-30T05:00:01Z server sudo[9100]: admin : COMMAND=/usr/bin/systemctl stop suricata",
                  "2026-07-30T05:00:01Z server systemd[1]: systemctl stop suricata"],
    },
    "nextcloud_brute": {
        "title": "Nextcloud web login brute-force + success (R20/R21)",
        "lines": ['{} - - [30/Jul/2026:06:10:0{} +0000] "POST /index.php/login HTTP/1.1" 401 1200'.format(EXT_IP2, i)
                  for i in range(1, 9)]
                 + ['{} - - [30/Jul/2026:06:10:12 +0000] "POST /index.php/login HTTP/1.1" 200 3400'.format(EXT_IP2)],
    },
}

# ── live demo state ───────────────────────────────────────────────────────────
_state_lock = threading.Lock()


def _fresh_state():
    return {"stage": "idle", "running": False, "scenario": None,
            "events": [], "agent_log": [], "tickets": [], "responder_output": [], "cases": []}


_state = _fresh_state()


def now_hms():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(agent, msg):
    with _state_lock:
        _state["agent_log"].append({"t": now_hms(), "agent": agent, "msg": msg})
        _state["agent_log"] = _state["agent_log"][-300:]


def set_stage(stage):
    with _state_lock:
        _state["stage"] = stage


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def reset_demo():
    for sub in ("tickets", "cases", "snapshots"):
        d = os.path.join(DEMO_DIR, sub)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    for f in ("ip_stats.json", "event_buffer.json", "investigator_state_v2.json",
              "intel_cache.json", "v2_log_sizes.json", "v2_known_ips.json"):
        try:
            os.remove(os.path.join(DEMO_DIR, f))
        except OSError:
            pass
    with _state_lock:
        _state.update(_fresh_state())


def route_and_emit(line):
    line = line.strip()
    if not line:
        return []
    if line.startswith("{"):
        evts = triage_agent.parse_suricata(line)
    elif '"GET ' in line or '"POST ' in line or '"HEAD ' in line:
        evts = triage_agent.parse_apache(line)
    elif "UFW BLOCK" in line:
        evts = triage_agent.parse_ufw(line)
    elif any(k in line for k in ("Failed password", "Accepted ", "Invalid user",
                                 "sudo:", "useradd", "usermod", "userdel", "new user")):
        evts = triage_agent.parse_auth(line)
    else:
        evts = triage_agent.parse_syslog(line)
    for e in (evts or []):
        triage_agent.emit(e)
        triage_agent.dispatch_preflags(e)
        with _state_lock:
            _state["events"].append({"t": now_hms(), "type": e.get("event_type"),
                                     "ip": e.get("source_ip"), "raw": (e.get("raw") or "")[:130]})
            _state["events"] = _state["events"][-200:]
    return evts or []


def load_demo_tickets():
    tdir = os.path.join(DEMO_DIR, "tickets")
    out = []
    if os.path.isdir(tdir):
        for fn in sorted(os.listdir(tdir)):
            if fn.endswith(".json"):
                t = _read_json(os.path.join(tdir, fn), None)
                if t:
                    isum = t.get("intel_summary") or {}
                    out.append({"id": t.get("ticket_id"), "rule": t.get("rule"),
                                "severity": (t.get("severity") or "").lower(),
                                "technique": t.get("mitre_technique"), "tactic": t.get("mitre_tactic"),
                                "ip": t.get("source_ip"), "status": t.get("status"),
                                "groups": isum.get("associated_groups", []),
                                "reputation": isum.get("ip_reputation"), "response": t.get("response")})
    return out


def refresh_tickets():
    with _state_lock:
        _state["tickets"] = load_demo_tickets()


def process_run(lines):
    set_stage("triage")
    log("triage", "Ingesting {} log lines".format(len(lines)))
    for ln in lines:
        route_and_emit(ln)
        time.sleep(0.12)
    ips = _read_json(os.path.join(DEMO_DIR, "ip_stats.json"), {})
    log("triage", "Normalized {} events; built ip_stats for {} IP(s)".format(len(_state["events"]), len(ips)))

    set_stage("investigator")
    log("investigator", "Correlating ip_stats against detection rules")
    time.sleep(0.5)
    investigator_agent.run_cycle()
    refresh_tickets()
    log("investigator", "Opened {} ticket(s)".format(len([t for t in _state["tickets"] if t["status"] == "open"])))
    for t in _state["tickets"]:
        log("investigator", "{}: {} ({}) severity={}".format(t["id"], t["rule"], t["technique"], t["severity"]))

    set_stage("intel")
    log("intel", "Enriching tickets: threat feeds + MITRE ATT&CK group lookup")
    time.sleep(0.5)
    intel_agent.run_cycle()
    refresh_tickets()
    for t in _state["tickets"]:
        if t.get("groups"):
            log("intel", "{}: {} used by {}".format(t["id"], t["technique"], ", ".join(t["groups"][:3])))

    set_stage("orchestrator")
    log("orchestrator", "Briefs assembled. Awaiting operator decision.")
    time.sleep(0.3)
    set_stage("ready")
    with _state_lock:
        _state["running"] = False


def start_run(lines, scenario=None):
    if _state.get("running"):
        return False
    reset_demo()
    with _state_lock:
        _state.update(_fresh_state())
        _state["running"] = True
        _state["scenario"] = scenario
    threading.Thread(target=process_run, args=(lines,), daemon=True).start()
    return True


def term(line):
    with _state_lock:
        _state["responder_output"].append({"t": now_hms(), "line": line})
        _state["responder_output"] = _state["responder_output"][-200:]


def run_response(ticket_id, option):
    set_stage("responder")
    log("responder", "Executing option {} for {} (DRY-RUN)".format(option, ticket_id))
    term("$ responder --ticket {} --option {}".format(ticket_id, option))
    result = responder_agent.execute(ticket_id, option)
    t = _read_json(os.path.join(DEMO_DIR, "tickets", ticket_id + ".json"), {})
    for f in t.get("findings", []):
        if f.get("agent") == "responder" and f.get("command_run"):
            term("  " + f["command_run"] + "   # dry-run")
            if f.get("rollback_command") and f["rollback_command"] not in ("n/a", "n/a (irreversible)"):
                term("  rollback: " + f["rollback_command"])
    term("> " + result)
    log("responder", result)

    set_stage("auditor")
    log("auditor", "Writing case file and closing ticket")
    time.sleep(0.4)
    case = auditor_agent.audit(ticket_id)
    if case:
        with _state_lock:
            _state["cases"].append({"id": ticket_id, "path": os.path.basename(case)})
        log("auditor", "{} closed - case file {}".format(ticket_id, os.path.basename(case)))
    refresh_tickets()
    set_stage("ready")


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return HTML


@app.route("/demo/scenarios")
def scenarios():
    return jsonify([{"id": k, "title": v["title"]} for k, v in SCENARIOS.items()])


@app.route("/demo/run", methods=["POST"])
def run():
    data = request.get_json(silent=True) or {}
    name = data.get("scenario")
    if name not in SCENARIOS:
        return jsonify({"error": "unknown scenario"}), 400
    return jsonify({"status": "started" if start_run(list(SCENARIOS[name]["lines"]), name) else "busy"})


@app.route("/demo/upload", methods=["POST"])
def upload():
    f = request.files.get("logfile")
    if not f:
        return jsonify({"error": "no file"}), 400
    lines = [l for l in f.read().decode("utf-8", errors="ignore").splitlines() if l.strip()]
    if not lines:
        return jsonify({"error": "empty file"}), 400
    return jsonify({"status": "started" if start_run(lines, "upload:" + f.filename) else "busy", "lines": len(lines)})


@app.route("/demo/respond", methods=["POST"])
def respond():
    data = request.get_json(silent=True) or {}
    tid, opt = data.get("ticket_id"), data.get("option")
    if not tid or opt not in (1, 2, 3, 4):
        return jsonify({"error": "invalid"}), 400
    threading.Thread(target=run_response, args=(tid, opt), daemon=True).start()
    return jsonify({"status": "ok"})


@app.route("/demo/reset", methods=["POST"])
def reset():
    reset_demo()
    return jsonify({"status": "reset"})


@app.route("/demo/state")
def state():
    with _state_lock:
        return jsonify(dict(_state))


@app.route("/demo/flow")
def flow():
    ip_stats = _read_json(os.path.join(DEMO_DIR, "ip_stats.json"), {})
    events = _read_json(os.path.join(DEMO_DIR, "event_buffer.json"), {"events": []}).get("events", [])
    tdir = os.path.join(DEMO_DIR, "tickets")
    tickets = []
    if os.path.isdir(tdir):
        for fn in sorted(os.listdir(tdir)):
            if fn.endswith(".json"):
                t = _read_json(os.path.join(tdir, fn), None)
                if t:
                    tickets.append(t)

    def slim(t, keys):
        return {k: t.get(k) for k in keys}

    return jsonify({
        "ingest": {"label": "raw log lines -> normalized events", "data": events[-12:]},
        "triage": {"label": "ip_stats.json (per-IP running statistics)", "data": ip_stats},
        "investigator": {"label": "ticket (rule + severity + evidence)",
                         "data": [slim(t, ["ticket_id", "rule", "severity", "mitre_technique",
                                           "mitre_tactic", "detection_method", "evidence"]) for t in tickets]},
        "intel": {"label": "intel_summary (reputation + MITRE groups + correlation)",
                  "data": [{"ticket_id": t.get("ticket_id"), "intel_summary": t.get("intel_summary")} for t in tickets]},
        "orchestrator": {"label": "operator brief (ticket + intel_summary)",
                         "data": [slim(t, ["ticket_id", "severity", "rule", "mitre_technique", "source_ip"]) for t in tickets]},
        "responder": {"label": "containment actions (command + rollback, dry-run)",
                      "data": [{"ticket_id": t.get("ticket_id"),
                                "actions": [f for f in t.get("findings", []) if f.get("agent") == "responder"]} for t in tickets]},
        "auditor": {"label": "case file + closure",
                    "data": [slim(t, ["ticket_id", "status", "closed_at", "case_file", "agent_trail"]) for t in tickets]},
    })


# ── frontend (minimal black & white, agent-centric) ───────────────────────────
HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>SOC Simulator</title>
<style>
:root{--ink:#111111;--mut:#6b6b6b;--line:#e2e2e2;--soft:#f6f6f6;--mono:"SFMono-Regular",Consolas,Menlo,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#fff;color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:13px;line-height:1.5}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 26px;border-bottom:1px solid var(--line)}
header h1{font-size:16px;font-weight:700;letter-spacing:.2px}
header h1 span{font-weight:400;color:var(--mut)}
.ctl{display:flex;gap:8px;align-items:center}
select,button,label.up{font-size:12px;padding:8px 13px;border-radius:6px;border:1px solid var(--ink);background:#fff;color:var(--ink);cursor:pointer;font-family:inherit}
button.run{background:var(--ink);color:#fff}
button.reset,label.up{border-color:#bbb;color:var(--mut)}
main{max-width:880px;margin:0 auto;padding:22px 26px 60px}
.arrow{text-align:center;color:#bbb;font-family:var(--mono);font-size:11px;padding:5px 0}
.arrow b{color:var(--ink)}
/* agent block */
.agent{border:1px solid var(--line);border-radius:12px;padding:15px 18px;background:#fff;transition:border-color .25s,box-shadow .25s}
.agent.active{border-color:var(--ink);box-shadow:0 0 0 1px var(--ink)}
.agent.done{border-color:#cfcfcf}
.ahead{display:flex;align-items:center;gap:11px}
.num{width:24px;height:24px;border-radius:50%;border:1.5px solid var(--ink);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex:0 0 auto}
.agent.done .num{background:var(--ink);color:#fff}
.agent.idle .num{border-color:#cfcfcf;color:#cfcfcf}
.aname{font-size:14px;font-weight:700}
.arole{font-size:11.5px;color:var(--mut)}
.status{margin-left:auto;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut)}
.agent.active .status{color:var(--ink);font-weight:700}
.inspect{margin-left:10px;font-size:11px;color:var(--ink);text-decoration:underline;cursor:pointer;background:none;border:none;padding:0}
.abody{margin-top:10px;padding-left:35px}
.act{font-family:var(--mono);font-size:11.5px;color:var(--mut);padding:1px 0}
.act .t{color:#bbb}
.empty{color:#bbb;font-style:italic;font-size:12px}
/* incidents (in orchestrator block) */
.tk{border:1px solid var(--line);border-radius:9px;padding:11px 13px;margin-top:9px}
.tk .top{display:flex;justify-content:space-between;align-items:center}
.tk .id{font-family:var(--mono);font-weight:700}
.tk .ti{font-size:12.5px;margin:4px 0}
.tk .grp{font-size:11px;color:var(--mut)}.tk .grp b{color:var(--ink)}
.sev{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;padding:2px 8px;border-radius:20px}
.sev.critical{background:var(--ink);color:#fff}.sev.high{background:#555;color:#fff}
.sev.medium{background:#fff;color:var(--ink);border:1px solid var(--ink)}
.sev.low{background:#fff;color:#888;border:1px solid #ccc}.sev.closed{background:var(--soft);color:#888}
.acts{display:flex;gap:7px;margin-top:9px;flex-wrap:wrap}
.acts button{font-size:11px;font-weight:600;padding:6px 11px;border-radius:6px;border:1px solid var(--ink);background:#fff;color:var(--ink)}
.acts .a2{background:var(--ink);color:#fff}.acts .a3{background:#555;color:#fff;border-color:#555}
.acts .a4{border-color:#bbb;color:var(--mut)}
.closedmsg{font-size:11.5px;color:var(--ink);margin-top:8px}
/* terminal (responder) */
.term{background:var(--soft);border-radius:8px;padding:11px 13px;font-family:var(--mono);font-size:11.5px;max-height:220px;overflow:auto}
.term .l{white-space:pre-wrap;color:#333}.term .l.cmd{color:var(--ink);font-weight:700}.term .l.res{color:var(--ink)}
.scroll{max-height:150px;overflow:auto}
/* modal */
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:60;align-items:center;justify-content:center;padding:26px}
.modal.on{display:flex}
.sheet{background:#fff;border:1px solid var(--ink);border-radius:12px;width:100%;max-width:800px;max-height:84vh;display:flex;flex-direction:column;overflow:hidden}
.sheet .top{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
.sheet .top h3{font-size:14px}.sheet .x{cursor:pointer;color:var(--mut);font-size:22px}
.sheet .note{font-size:11.5px;color:var(--mut);padding:9px 18px;border-bottom:1px solid var(--line)}
.sheet pre{overflow:auto;padding:14px 18px;margin:0;font-family:var(--mono);font-size:11.5px;color:#222}
</style></head><body>
<header>
  <h1>SOC Simulator <span>· multi-agent pipeline</span></h1>
  <div class="ctl">
    <select id="scenario"></select>
    <button class="run" onclick="runScenario()">Run</button>
    <label class="up">Upload log<input type="file" id="file" style="display:none" onchange="uploadFile()"></label>
    <button class="reset" onclick="resetDemo()">Reset</button>
  </div>
</header>
<main id="agents"></main>
<div class="modal" id="flowModal" onclick="if(event.target.id==='flowModal')closeFlow()">
  <div class="sheet"><div class="top"><h3 id="flowTitle"></h3><span class="x" onclick="closeFlow()">&times;</span></div>
  <div class="note" id="flowNote"></div><pre id="flowJson"></pre></div>
</div>
<script>
const AGENTS=[
 {key:'ingest',n:'Ingest',role:'raw logs -> normalized events',hand:'ip_stats',next:'Triage'},
 {key:'triage',n:'Triage',role:'collect & normalize logs',hand:'ip_stats',next:'Investigator'},
 {key:'investigator',n:'Investigator',role:'correlate events into attacks',hand:'ticket',next:'Intel'},
 {key:'intel',n:'Intel',role:'enrich with threat intelligence',hand:'intel_summary',next:'Orchestrator'},
 {key:'orchestrator',n:'Orchestrator (Vega)',role:'brief the operator & await decision',hand:'decision',next:'Responder'},
 {key:'responder',n:'Responder',role:'execute containment (dry-run)',hand:'case',next:'Auditor'},
 {key:'auditor',n:'Auditor',role:'write case file & close',hand:'',next:''},
];
const ORDER=['ingest','triage','investigator','intel','orchestrator','responder','auditor'];
const STAGE_ACTIVE={idle:-1,triage:1,investigator:2,intel:3,orchestrator:4,ready:4,responder:5,auditor:6};
const OPT3={R2:"Kill Session",R13:"Kill Session",R21:"Kill Session",R6:"Kill Session",R8:"Disable Account",
R12:"Disable Account",R9:"Remove Cron",R10:"Restore Tool",R16:"Disable Service",R15:"Manual Review",R17:"Manual Review",R18:"Manual Review"};
function esc(x){return (x==null?"":String(x)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function load(){
  const s=await (await fetch('/demo/scenarios')).json();
  document.getElementById('scenario').innerHTML=s.map(x=>`<option value="${x.id}">${esc(x.title)}</option>`).join('');
}
async function runScenario(){const n=document.getElementById('scenario').value;
  await fetch('/demo/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scenario:n})});}
async function uploadFile(){const f=document.getElementById('file').files[0];if(!f)return;
  const fd=new FormData();fd.append('logfile',f);await fetch('/demo/upload',{method:'POST',body:fd});}
async function resetDemo(){await fetch('/demo/reset',{method:'POST'});}
async function respond(id,opt){await fetch('/demo/respond',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket_id:id,option:opt})});}

async function openFlow(key,name,nextn){let f;try{f=await (await fetch('/demo/flow')).json();}catch(e){return;}
  const sec=f[key]||{};
  document.getElementById('flowTitle').innerHTML=esc(name)+(nextn?' <span style="color:#888;font-family:monospace">-> '+esc(nextn)+'</span>':'');
  document.getElementById('flowNote').textContent='Payload: '+(sec.label||'');
  document.getElementById('flowJson').textContent=JSON.stringify(sec.data,null,2);
  document.getElementById('flowModal').classList.add('on');}
function closeFlow(){document.getElementById('flowModal').classList.remove('on');}

function acts(a,st){
  const lines=st.agent_log.filter(x=>x.agent===a.key).slice(-6)
    .map(x=>`<div class="act"><span class="t">${x.t}</span> ${esc(x.msg)}</div>`).join('');
  if(a.key==='ingest'){
    const ev=st.events.slice(-6).map(e=>`<div class="act"><span class="t">${e.t}</span> ${esc(e.type)} · ${esc(e.ip)}</div>`).join('');
    return (ev||'<div class="empty">Run a scenario or upload a log to begin.</div>')+
      (st.events.length?`<div class="act" style="color:#111;margin-top:4px">${st.events.length} events normalized</div>`:'');
  }
  if(a.key==='orchestrator'){
    const cards=st.tickets.map(t=>{
      const closed=t.status==='closed';
      const grp=t.groups&&t.groups.length?`<div class="grp">MITRE groups: <b>${t.groups.map(esc).join(', ')}</b></div>`:'';
      const body=closed?`<div class="closedmsg">closed · ${esc(t.response||'')} · case file written</div>`:
        `<div class="acts"><button onclick="respond('${t.id}',1)">Monitor</button>
         <button class="a2" onclick="respond('${t.id}',2)">Block IP</button>
         <button class="a3" onclick="respond('${t.id}',3)">${esc(OPT3[t.rule]||'Contain')}</button>
         <button class="a4" onclick="respond('${t.id}',4)">Escalate</button></div>`;
      return `<div class="tk"><div class="top"><span class="id">${esc(t.id)}</span>
        <span class="sev ${closed?'closed':t.severity}">${esc(closed?'closed':t.severity)}</span></div>
        <div class="ti">${esc(t.rule)} · ${esc(t.technique)} (${esc(t.tactic)}) — ${esc(t.ip)}</div>${grp}${body}</div>`;
    }).join('');
    return lines + (cards||'<div class="empty">No briefs yet.</div>');
  }
  if(a.key==='responder'){
    const t=st.responder_output.slice(-40).map(o=>{
      const c=o.line.startsWith('$')?'cmd':(o.line.startsWith('>')?'res':'');
      return `<div class="l ${c}">${esc(o.line)}</div>`;}).join('');
    return lines + (t?`<div class="term">${t}</div>`:'<div class="empty">Awaiting an operator decision above.</div>');
  }
  if(a.key==='auditor'){
    const c=st.cases.map(x=>`<div class="act">✓ ${esc(x.id)} — ${esc(x.path)}</div>`).join('');
    return lines + (c||'<div class="empty">No case files yet.</div>');
  }
  return lines || '<div class="empty">idle</div>';
}

async function tick(){
  let st;try{st=await (await fetch('/demo/state')).json();}catch(e){return;}
  const active=STAGE_ACTIVE[st.stage]??-1;
  let html='';
  AGENTS.forEach((a,i)=>{
    let cls='agent'; const oi=ORDER.indexOf(a.key);
    if(st.stage!=='idle'){ if(oi<active)cls+=' done'; else if(oi===active)cls+=' active'; }
    if(st.stage==='idle')cls+=' idle';
    if(st.stage==='ready'&&oi<4)cls+=' done';
    const status=oi===active?(st.stage==='ready'?'awaiting':'working'):(oi<active||(st.stage==='ready'&&oi<4)?'done':'idle');
    const insp=a.key!=='orchestrator'?`<button class="inspect" onclick="openFlow('${a.key}','${esc(a.n)}','${esc(a.next)}')">inspect data →</button>`:'';
    html+=`<div class="${cls}"><div class="ahead"><div class="num">${i+1}</div>
      <div><div class="aname">${esc(a.n)}</div><div class="arole">${esc(a.role)}</div></div>
      <span class="status">${status}</span>${insp}</div>
      <div class="abody">${acts(a,st)}</div></div>`;
    if(a.hand){html+=`<div class="arrow">↓ <b>${esc(a.hand)}</b></div>`;}
  });
  document.getElementById('agents').innerHTML=html;
}
load(); setInterval(tick,600); tick();
</script></body></html>"""


if __name__ == "__main__":
    print("[DEMO] SOC Simulator on http://0.0.0.0:{}  (sandbox: {})".format(DEMO_PORT, DEMO_DIR))
    app.run(host="0.0.0.0", port=DEMO_PORT, debug=False, threaded=True)
