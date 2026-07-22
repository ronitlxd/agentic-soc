# Design Decisions & Tradeoffs

This document explains *why* Vega SOC is built the way it is. Each decision below
was a real fork in the road during development, with a cost on each side.

## 1. Rules engine instead of per-event LLM analysis

**Decision:** The Investigator is pure Python. No language model sees individual
log lines.

**Why:** A SOC ingests thousands of events per hour. Sending each to an LLM would
cost money and add latency measured in seconds per event — unworkable at volume.
Deterministic correlation rules run in milliseconds at zero token cost. The LLM is
reserved for the one place natural language actually helps: the operator brief.

**Tradeoff:** Rules only catch what they're written to catch. Novel attacks that
don't match a signature slip through — which is why behavioral baselining is on the
roadmap. Rules are a floor, not a ceiling.

## 2. Correlating sequences, not single events

**Decision:** Every rule looks for a multi-stage pattern (scan → exploit, fails →
success, login → exfil), not an isolated alert.

**Why:** Single-event alerting is the primary cause of alert fatigue. One failed
login is noise; five failures followed by a success is an incident. Correlating
sequences is what turns raw telemetry into an attack narrative a human can act on.

**Tradeoff:** Requires holding a time window of state (the 24h rolling buffer) and
indexing by source IP each cycle. More moving parts than a stateless "grep for bad
string" — but that complexity is the whole value.

## 3. One orchestrator, agents as modules

**Decision:** All agents are importable Python modules coordinated by a single
`orchestrator.py` running as one systemd service — not separate processes talking
over a message bus.

**Why:** For a single-host SOC, inter-process messaging (Redis, queues, sockets)
adds operational surface area with no benefit. In-process function calls are simpler
to reason about, debug, and deploy. One service to start, one log to tail.

**Tradeoff:** Doesn't scale horizontally across machines. Acceptable — this is a
host-level SOC, not a distributed platform. If it ever needed to scale, the agent
boundaries are already clean enough to split out.

## 4. Telegram: orchestrator sends, Hermes receives

**Decision:** The orchestrator only *sends* outbound alerts (direct API call). A
separate component (Hermes/Vega) *receives* operator replies and writes the choice
to a handoff file the orchestrator polls.

**Why:** Telegram delivers each update to only one long-polling consumer. If two
processes poll the same bot token, one silently loses messages. Splitting send vs.
receive avoids the conflict cleanly.

**Tradeoff:** Introduces a file-based handoff (`operator_response.json`) and a
dependency on the reply-parsing being reliable — an area that needed iteration.

## 5. Evidence before action, always

**Decision:** The Responder's first step for any containment option is a full
system snapshot (sessions, connections, processes, firewall state), saved to disk
before anything is touched.

**Why:** The moment you block an IP or kill a session, you destroy the live state a
forensic investigation needs. Capturing it first is non-negotiable in real incident
response. Every action also logs a documented rollback.

**Tradeoff:** A few seconds of delay before containment. Worth it — the evidence is
irreplaceable, the delay is not.

## 6. Human in the loop

**Decision:** No containment action ever executes automatically. Vega presents
options; the operator chooses.

**Why:** Automated response that gets it wrong can take down a production service or
lock out the legitimate admin. For a portfolio targeting finance/defence, "the human
decides, the machine executes and documents" is the defensible posture.

**Tradeoff:** Response is only as fast as the operator. Mitigated by pushing a
decision-ready card (with enrichment already done) straight to their phone.

## 7. Graceful degradation everywhere

**Decision:** Missing Suricata flow data, absent API keys, unreachable log files —
each is handled by skipping that capability, not crashing.

**Why:** A SOC that dies because one optional feed is down is worse than useless.
Rules R3/R5 return no-match without flow data; Intel appends an "unavailable" note
without a key; Triage logs a missing source and moves on.

**Tradeoff:** Silent degradation can hide a genuinely broken feed. The dashboard's
Agent Health panel exists partly to surface this — you can see which sources are
actually producing events.

## 8. Prompt-injection boundary

**Decision:** Log content is only ever quoted into briefs — never executed,
evaluated, or fed back as an instruction.

**Why:** Logs contain attacker-controlled strings. If any component treated log text
as a command, an attacker could inject instructions by crafting a log entry. Keeping
a hard boundary between "data we display" and "code we run" closes that class of
attack entirely.
