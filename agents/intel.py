#!/usr/bin/env python3
"""
INTEL — IOC enrichment.
Receives IP list, queries free threat intel sources.
Adds context to ticket findings. Makes no decisions.
API keys optional — degrades gracefully without them.
"""

import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

TICKET_CLI      = os.path.expanduser("~/.hermes/skills/soc/ticket-manager/ticket_cli.py")
ENV_FILE        = os.path.expanduser("~/.hermes/.env")
TOR_CACHE       = os.path.expanduser("~/.hermes/soc/tor_exit_nodes.txt")
FEODO_CACHE     = os.path.expanduser("~/.hermes/soc/feodo_c2.txt")
LIST_MAX_AGE    = 3600  # refresh threat lists every hour

_tor_nodes      = set()
_feodo_ips      = set()
_lists_loaded   = 0

INTERNAL_PREFIXES = ("10.", "192.168.", "172.", "127.", "::1", "local")


# ── helpers ───────────────────────────────────────────────────────────────────

def load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


def fetch(url, headers=None, timeout=10):
    try:
        req = urllib.request.Request(
            url,
            headers={**(headers or {}), "User-Agent": "SOC-Intel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def append_finding(ticket_id, note):
    subprocess.run(
        [sys.executable, TICKET_CLI, "append",
         "--id", ticket_id, "--agent", "intel", "--note", note[:500]],
        capture_output=True, text=True,
    )


def is_internal(ip):
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


# ── threat list management ────────────────────────────────────────────────────

def refresh_lists():
    global _tor_nodes, _feodo_ips, _lists_loaded
    now = datetime.now(timezone.utc).timestamp()
    if now - _lists_loaded < LIST_MAX_AGE:
        return

    # Tor exit nodes (no key required)
    tor_data = fetch("https://check.torproject.org/torbulkexitlist")
    if tor_data:
        _tor_nodes = {
            line.strip() for line in tor_data.splitlines()
            if line.strip() and not line.startswith("#")
        }
        with open(TOR_CACHE, "w") as f:
            f.write(tor_data)
    elif os.path.exists(TOR_CACHE):
        with open(TOR_CACHE) as f:
            _tor_nodes = {
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            }

    # Feodo C2 tracker (no key required)
    feodo_data = fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
    if feodo_data:
        _feodo_ips = {
            line.strip() for line in feodo_data.splitlines()
            if line.strip() and not line.startswith("#")
        }
        with open(FEODO_CACHE, "w") as f:
            f.write(feodo_data)
    elif os.path.exists(FEODO_CACHE):
        with open(FEODO_CACHE) as f:
            _feodo_ips = {
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            }

    _lists_loaded = now


# ── enrichment sources ────────────────────────────────────────────────────────

def lookup_abuseipdb(ip, api_key):
    if not api_key:
        return None
    data = fetch(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90".format(ip),
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if not data:
        return None
    try:
        d = json.loads(data).get("data", {})
        return {
            "score":    d.get("abuseConfidenceScore", 0),
            "reports":  d.get("totalReports", 0),
            "country":  d.get("countryCode", "?"),
            "isp":      d.get("isp", "?"),
            "usage":    d.get("usageType", "?"),
            "domain":   d.get("domain", ""),
        }
    except (json.JSONDecodeError, KeyError):
        return None


def lookup_ipinfo(ip, token):
    if not token:
        return None
    data = fetch("https://ipinfo.io/{}?token={}".format(ip, token))
    if not data:
        return None
    try:
        d = json.loads(data)
        return {
            "country":  d.get("country", "?"),
            "org":      d.get("org", "?"),
            "hostname": d.get("hostname", ""),
            "city":     d.get("city", "?"),
            "region":   d.get("region", "?"),
        }
    except (json.JSONDecodeError, KeyError):
        return None


# ── main enrichment ───────────────────────────────────────────────────────────

def enrich(ticket_id, ioc_list):
    """
    Enrich a list of IOCs and append findings to the ticket.
    Returns list of summary strings for the Vega brief.
    """
    env            = load_env()
    abuseipdb_key  = env.get("ABUSEIPDB_API_KEY")
    ipinfo_token   = env.get("IPINFO_TOKEN")

    refresh_lists()

    summaries = []

    for ip in ioc_list:
        if is_internal(ip):
            continue  # never send internal IPs to external APIs

        tags  = []
        parts = []

        # Free sources (always run)
        if ip in _tor_nodes:
            tags.append("TOR-EXIT")
        if ip in _feodo_ips:
            tags.append("KNOWN-C2")

        # AbuseIPDB (optional)
        abuse = lookup_abuseipdb(ip, abuseipdb_key)
        if abuse:
            parts.append("AbuseIPDB score={}/100 reports={} country={} isp={}".format(
                abuse["score"], abuse["reports"], abuse["country"], abuse["isp"]))
            if abuse["score"] >= 75:
                tags.append("HIGH-ABUSE")
        elif abuseipdb_key:
            parts.append("AbuseIPDB: unavailable")

        # IPinfo (optional)
        info = lookup_ipinfo(ip, ipinfo_token)
        if info:
            parts.append("IPinfo: {} | {} | {} | {}".format(
                info["country"], info["city"], info["org"], info["hostname"]))
        elif ipinfo_token:
            parts.append("IPinfo: unavailable")

        # Build finding
        if not parts and not tags:
            finding = "{}: no enrichment sources configured — add API keys to .env".format(ip)
        else:
            tag_str  = "[{}] ".format(", ".join(tags)) if tags else ""
            finding  = "{}: {}{}".format(ip, tag_str, " | ".join(parts))

        append_finding(ticket_id, finding)
        summaries.append(finding)

    return summaries
