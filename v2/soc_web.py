#!/usr/bin/env python3
"""
SOC WEB INTERFACE — SOC V2
==========================

ROLE
    The operator's decision surface. In V2 all containment decisions happen here
    (not over Telegram). Telegram only pushes a read-only notification with a URL
    that opens this interface.

ROUTES
    GET  /                 -> redirect to /briefs
    GET  /briefs           -> active briefs, severity-sorted, auto-refresh 10s
    GET  /brief/<id>       -> full brief for one ticket, with action buttons
    POST /respond          -> {ticket_id, option} -> writes operator_response.json

INPUTS
    tickets/*.json         -> open tickets enriched by Intel (intel_summary)

OUTPUT
    operator_response.json -> {ticket_id, option, received_at, source:"web_interface"}
    The Orchestrator polls this file and dispatches the Responder.

SECURITY
    No ticket/log content is executed — only rendered as escaped text. The only
    write is the small operator_response.json handoff, validated to option 1-4.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, redirect, abort
from markupsafe import escape

BASE_DIR       = os.environ.get("SOC_BASE_DIR", os.path.expanduser("~/.hermes/soc"))
TICKETS_DIR    = os.path.join(BASE_DIR, "tickets")
RESPONSE_PATH  = os.path.join(BASE_DIR, "operator_response_v2.json")
WEB_PORT       = int(os.environ.get("SOC_WEB_PORT", "5005"))

app = Flask(__name__)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "#ff4d5e", "high": "#ff9640", "medium": "#ffd23f", "low": "#3ecf8e"}

# Rule -> label for the dynamic Option 3 (per the design action matrix)
OPTION3_LABEL = {
    "R2": "Kill Session", "R13": "Kill Session", "R21": "Kill Session", "R6": "Kill Session",
    "R8": "Disable Account", "R12": "Disable Account",
    "R9": "Remove Crontab",
    "R10": "Restore Tool",
    "R16": "Disable Service",
    "R17": "Manual Review", "R24": "Manual Review",
    "R15": "Manual Review", "R18": "Manual Review",
}


# ── data ──────────────────────────────────────────────────────────────────────

def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_tickets(open_only=True):
    out = []
    if not os.path.isdir(TICKETS_DIR):
        return out
    for fn in os.listdir(TICKETS_DIR):
        if fn.endswith(".json"):
            t = _read_json(os.path.join(TICKETS_DIR, fn), None)
            if t and (not open_only or t.get("status") == "open"):
                out.append(t)
    out.sort(key=lambda t: (SEV_ORDER.get((t.get("severity") or "").lower(), 9),
                            t.get("created", "")))
    return out


def get_ticket(tid):
    p = os.path.join(TICKETS_DIR, tid + ".json")
    return _read_json(p, None)


# ── HTML rendering (server-side, escaped) ─────────────────────────────────────

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">{refresh}
<title>{title}</title><style>
:root{{--bg:#0a0e14;--panel:#111722;--panel2:#161d2b;--line:#232c3d;--txt:#c7d1e0;--dim:#7c899e;--accent:#4da3ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--txt);font-family:system-ui,Segoe UI,Roboto,sans-serif;font-size:14px;padding:22px;max-width:900px;margin:0 auto}}
h1{{font-size:18px;margin-bottom:4px}}.sub{{color:var(--dim);font-size:12px;margin-bottom:18px}}
a{{color:var(--accent);text-decoration:none}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.row{{display:flex;justify-content:space-between;align-items:center;gap:10px}}
.pill{{font-size:10px;font-weight:700;text-transform:uppercase;padding:2px 9px;border-radius:20px}}
.id{{font-family:monospace;color:var(--accent);font-size:13px}}
.ti{{font-size:14px;color:#e6ecf5;margin:5px 0}}
.meta{{font-size:11px;color:var(--dim);font-family:monospace}}
.sec{{margin:16px 0;padding-top:14px;border-top:1px solid var(--line)}}
.sec h3{{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:8px}}
.kv{{display:grid;grid-template-columns:170px 1fr;gap:4px 12px;font-size:13px}}
.kv b{{color:var(--dim);font-weight:400}}
.btns{{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}}
.btn{{padding:10px 16px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;color:#fff}}
.b1{{background:#3a4a63}}.b2{{background:#c0392b}}.b3{{background:#b9770e}}.b4{{background:#6c3fb5}}
.empty{{color:var(--dim);font-style:italic;padding:30px;text-align:center}}
#msg{{margin-top:12px;font-size:13px;color:var(--accent)}}
.tag{{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:1px 7px;margin:2px;font-size:11px;font-family:monospace}}
</style></head><body>{body}</body></html>"""


def sev_pill(sev):
    sev = (sev or "unknown").lower()
    c = SEV_COLOR.get(sev, "#7c899e")
    return '<span class="pill" style="background:{}22;color:{}">{}</span>'.format(c, c, escape(sev))


@app.route("/")
def home():
    return redirect("/briefs")


@app.route("/briefs")
def briefs():
    tickets = load_tickets(open_only=True)
    if tickets:
        rows = "".join(
            '<a href="/brief/{id}"><div class="card"><div class="row">'
            '<span class="id">{id}</span>{pill}</div>'
            '<div class="ti">{rule} · {tech} — {ip}</div>'
            '<div class="meta">{created}</div></div></a>'.format(
                id=escape(t.get("ticket_id", "?")), pill=sev_pill(t.get("severity")),
                rule=escape(t.get("rule", "?")), tech=escape(t.get("mitre_technique") or ""),
                ip=escape(t.get("source_ip", "?")), created=escape(t.get("created", "")))
            for t in tickets)
    else:
        rows = '<div class="empty">No open briefs — all clear.</div>'
    body = ('<h1>Active Briefs</h1><div class="sub">{} open · auto-refresh 10s</div>{}'
            ).format(len(tickets), rows)
    return PAGE.format(refresh='<meta http-equiv="refresh" content="10">',
                       title="SOC Briefs", body=body)


@app.route("/brief/<ticket_id>")
def brief(ticket_id):
    t = get_ticket(ticket_id)
    if not t:
        abort(404)
    isum = t.get("intel_summary") or {}
    ev = t.get("evidence") or {}
    rule = t.get("rule", "?")
    opt3 = OPTION3_LABEL.get(rule, "Contain")

    groups = "".join('<span class="tag">{}</span>'.format(escape(g))
                     for g in isum.get("associated_groups", [])) or '<span class="meta">none</span>'
    feeds = "".join('<span class="tag">{}</span>'.format(escape(f))
                    for f in isum.get("feed_hits", [])) or '<span class="meta">none</span>'
    labels = "".join('<span class="tag">{}</span>'.format(escape(l))
                     for l in isum.get("threat_labels", [])) or '<span class="meta">none</span>'
    priors = ", ".join(escape(x) for x in isum.get("prior_ticket_ids", [])) or "none"

    body = """
    <div class="row"><h1>{id}</h1>{pill}</div>
    <div class="sub">{rule} · {tech} ({tactic}) · {created}</div>

    <div class="card">
      <div class="sec" style="border:0;padding:0">
        <h3>Source</h3>
        <div class="kv">
          <b>IP</b><span>{ip} ({iptype})</span>
          <b>Geolocation</b><span>{geo}</span>
          <b>Org / ASN</b><span>{org}</span>
          <b>Hosting provider</b><span>{hosting}</span>
        </div>
      </div>
      <div class="sec">
        <h3>Reputation</h3>
        <div class="kv">
          <b>Verdict</b><span>{rep}</span>
          <b>AbuseIPDB score</b><span>{score}</span>
          <b>Internet scanner</b><span>{scanner}</span>
          <b>Feed hits</b><span>{feeds}</span>
          <b>Labels</b><span>{labels}</span>
        </div>
      </div>
      <div class="sec">
        <h3>Threat context</h3>
        <div class="kv">
          <b>MITRE technique</b><span>{tech} — {tactic}</span>
          <b>Associated groups</b><span>{groups}</span>
          <b>Prior tickets</b><span>{prior_n} ({priors})</span>
          <b>Enrichment mode</b><span>{mode}</span>
        </div>
      </div>
      <div class="sec">
        <h3>Evidence</h3>
        <div class="kv">
          <b>Auth failures</b><span>{af}</span>
          <b>Auth successes</b><span>{as_}</span>
          <b>Failed usernames</b><span>{fu}</span>
          <b>Web posts</b><span>{wp}</span>
          <b>Active hours (UTC)</b><span>{ah}</span>
          <b>Known IP</b><span>{known}</span>
        </div>
      </div>
      <div class="sec">
        <h3>Response</h3>
        <div class="btns">
          <button class="btn b1" onclick="respond(1)">Monitor</button>
          <button class="btn b2" onclick="respond(2)">Block IP</button>
          <button class="btn b3" onclick="respond(3)">{opt3}</button>
          <button class="btn b4" onclick="respond(4)">Escalate</button>
        </div>
        <div id="msg"></div>
      </div>
    </div>
    <div class="sub"><a href="/briefs">&larr; back to briefs</a></div>

    <script>
    async function respond(option){{
      const r = await fetch('/respond', {{method:'POST',headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{ticket_id:'{id}', option: option}})}});
      const d = await r.json();
      document.getElementById('msg').textContent = d.status === 'ok'
        ? ('✔ Option ' + option + ' submitted for {id}. Responder will act.')
        : ('Error: ' + (d.error || 'unknown'));
    }}
    </script>
    """.format(
        id=escape(ticket_id), pill=sev_pill(t.get("severity")),
        rule=escape(rule), tech=escape(t.get("mitre_technique") or ""),
        tactic=escape(t.get("mitre_tactic") or ""), created=escape(t.get("created", "")),
        ip=escape(t.get("source_ip", "?")), iptype=escape(t.get("ip_type", "?")),
        geo=escape(isum.get("geolocation") or "—"), org=escape(isum.get("org") or "—"),
        hosting=escape(str(isum.get("hosting_provider"))),
        rep=escape(isum.get("ip_reputation") or "unknown"),
        score=escape(str(isum.get("reputation_score"))),
        scanner=escape(str(isum.get("scanner_name") or isum.get("internet_scanner"))),
        feeds=feeds, labels=labels, groups=groups,
        prior_n=isum.get("prior_tickets", 0), priors=priors,
        mode=escape(isum.get("enrichment_mode") or "—"),
        af=ev.get("auth_failures", 0), as_=ev.get("auth_successes", 0),
        fu=escape(str(ev.get("failed_usernames", []))), wp=ev.get("web_posts", 0),
        ah=escape(str(ev.get("active_hours_utc", []))), known=escape(str(ev.get("known_ip"))),
        opt3=escape(opt3))
    return PAGE.format(refresh="", title="Brief " + ticket_id, body=body)


@app.route("/respond", methods=["POST"])
def respond():
    data = request.get_json(silent=True) or {}
    ticket_id = data.get("ticket_id")
    option = data.get("option")
    if not ticket_id or option not in (1, 2, 3, 4):
        return jsonify({"error": "invalid ticket_id or option"}), 400
    if not get_ticket(ticket_id):
        return jsonify({"error": "unknown ticket"}), 404
    payload = {
        "ticket_id": ticket_id,
        "option": option,
        "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "web_interface",
    }
    tmp = RESPONSE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(payload, f)
    os.replace(tmp, RESPONSE_PATH)
    return jsonify({"status": "ok", "ticket_id": ticket_id, "option": option})


if __name__ == "__main__":
    print("[WEB] SOC V2 web interface on http://0.0.0.0:{}  (/briefs)".format(WEB_PORT))
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
