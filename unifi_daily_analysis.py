#!/usr/bin/env python3
"""
unifi_daily_analysis.py

Pulls 24hr UniFi events via REST API, summarizes them,
sends to a local LLM for security analysis, and saves a daily report.

Usage:
    python unifi_daily_analysis.py              # full run
    python unifi_daily_analysis.py --dry-run    # fetch + summarize only, skip LLM
    python unifi_daily_analysis.py --discover   # print site/API info and exit

Setup:
    1. pip install requests python-dotenv
    2. Copy .env.example to .env and fill in your values
    3. Run with --discover first to validate connectivity and find your site ID
"""

import argparse
import datetime
import json
import os
import sys
import urllib3
from pathlib import Path

import requests
from dotenv import load_dotenv

# ── Suppress SSL warnings for self-signed UniFi certs ────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Load config from .env ─────────────────────────────────────────────────────
load_dotenv()

CONSOLE_IP   = os.getenv("UNIFI_CONSOLE_IP")
API_KEY      = os.getenv("UNIFI_API_KEY")
SITE_ID      = os.getenv("UNIFI_SITE_ID")       # from --discover step
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://localhost:1234/v1/chat/completions")
LLM_MODEL    = os.getenv("LLM_MODEL")
REPORT_DIR   = Path(os.getenv("REPORT_DIR", "reports"))
BASELINE_FILE = REPORT_DIR / "baseline.json"

SITE_NAME = os.getenv("UNIFI_SITE_NAME", "default")

# ── Validate required config ──────────────────────────────────────────────────
def validate_config(require_site_id=True):
    required = {
        "UNIFI_CONSOLE_IP": CONSOLE_IP,
        "UNIFI_API_KEY":    API_KEY,
        "LLM_MODEL":        LLM_MODEL,
    }
    if require_site_id:
        required["UNIFI_SITE_ID"] = SITE_ID

    missing = [k for k, v in required.items() if not v]
    if missing:
        print(f"\n[ERROR] Missing required .env variables: {', '.join(missing)}")
        print("Copy .env.example to .env and fill in the missing values.\n")
        sys.exit(1)


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def make_headers():
    return {
        "X-API-KEY": API_KEY,
        "Accept":    "application/json",
    }

def api_get(path):
    """GET from UniFi console; returns the inner data list/dict."""
    url = f"https://{CONSOLE_IP}/proxy/network{path}"
    try:
        r = requests.get(url, headers=make_headers(), verify=False, timeout=15)
        r.raise_for_status()
        body = r.json()
        # Integration API: {"data": [...]}
        # Internal API:    {"data": [...], "meta": {...}}
        return body.get("data", body)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot reach {url} — is the console IP correct?")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code
        # Don't let one bad endpoint kill the whole run. Some UniFi-OS controllers
        # 404 on specific internal-API paths (e.g. stat/event). Warn and continue so
        # the other sections (clients / alarms / rogue APs) still report. 401 is fatal.
        print(f"[WARN] HTTP {code} from {url}")
        if code == 401:
            print("        API key rejected — check UNIFI_API_KEY in .env")
            sys.exit(1)
        return []


# ── Discovery mode ────────────────────────────────────────────────────────────
def discover():
    """Print sites and validate both API paths. Use this to find your SITE_ID."""
    validate_config(require_site_id=False)
    print("\n=== UniFi API Discovery ===\n")

    print("[ Integration API — sites ]")
    sites = api_get("/integration/v1/sites")
    if not sites:
        print("  No sites returned — check API key permissions.")
    else:
        for s in sites:
            print(f"  id: {s.get('id')}  name: {s.get('name')}  desc: {s.get('description','')}")
        first_id = sites[0].get("id") if sites else None
        print(f"\n  → Set UNIFI_SITE_ID={first_id} in your .env (if that's your main site)\n")

    print("[ Integration API — clients (using first site) ]")
    if sites:
        sid = sites[0].get("id")
        clients = api_get(f"/integration/v1/sites/{sid}/clients")
        print(f"  {len(clients) if isinstance(clients, list) else '?'} clients connected\n")

    print("[ Internal API — alarms ]")
    site_path = SITE_ID or "default"
    alarms = api_get(f"/api/s/{site_path}/stat/alarm")
    count = len(alarms) if isinstance(alarms, list) else "?"
    print(f"  {count} unarchived alarms\n")

    print("[ Internal API — recent events (first 2) ]")
    events = api_get(f"/api/s/{site_path}/stat/event?within=1")
    if isinstance(events, list) and events:
        for e in events[:2]:
            print(f"  {json.dumps(e, indent=4)}")
    else:
        print("  No events or unexpected format.")

    print("\n=== Discovery complete ===\n")


# ── Data fetchers ─────────────────────────────────────────────────────────────
def fetch_events_24h():
    data = api_get(f"/api/s/{SITE_NAME}/stat/event?within=24")
    return data if isinstance(data, list) else []

def fetch_clients():
    # Internal API first: stat/sta returns ALL active stations in one call (no paging),
    # which is what the Flask dashboard uses and why it correctly reports ~70.
    data = api_get(f"/api/s/{SITE_NAME}/stat/sta")
    if isinstance(data, list):
        return data
    # Integration API fallback — it PAGINATES with a default page size of 25, so a bare
    # call silently returns only the first 25. Walk pages with an explicit large pageSize.
    all_clients = []
    page = 1
    while True:
        d = api_get(f"/integration/v1/sites/{SITE_ID}/clients?pageSize=200&page={page}")
        if not isinstance(d, list) or not d:
            break
        all_clients.extend(d)
        if len(d) < 200:
            break
        page += 1
    return all_clients

def fetch_alarms():
    data = api_get(f"/api/s/{SITE_NAME}/stat/alarm?archived=false")
    return data if isinstance(data, list) else []

def fetch_rogue_aps():
    data = api_get(f"/api/s/{SITE_NAME}/stat/rogueap")
    return data if isinstance(data, list) else []

# ── Baseline helpers ──────────────────────────────────────────────────────────
def load_baseline():
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except json.JSONDecodeError:
            print("[WARN] baseline.json is corrupt — starting fresh.")
    return {"known_macs": [], "seen_new": {}}

def update_baseline(current_macs: set, baseline: dict) -> dict:
    """
    Gradually absorbs new MACs into the known baseline.
    A MAC seen on 3+ separate days is considered established.
    """
    seen    = baseline.get("seen_new", {})
    known   = set(baseline.get("known_macs", []))
    today   = str(datetime.date.today())
    promote = []

    for mac in current_macs:
        if mac not in known:
            days = seen.get(mac, [])
            if today not in days:
                days.append(today)
            seen[mac] = days
            if len(days) >= 3:
                promote.append(mac)

    for mac in promote:
        known.add(mac)
        seen.pop(mac, None)

    baseline["known_macs"] = sorted(known)
    baseline["seen_new"]   = seen
    return baseline


# ── Summarizer ────────────────────────────────────────────────────────────────
def build_summary(events, clients, alarms, rogue_aps, baseline):
    today       = datetime.date.today()
    known_macs  = set(baseline.get("known_macs", []))
    current_macs = {c.get("mac") for c in clients if c.get("mac")}
    new_macs    = current_macs - known_macs

    # Tally event types
    event_counts = {}
    for e in events:
        key = e.get("key") or e.get("msg", "unknown")
        key = str(key)[:80]
        event_counts[key] = event_counts.get(key, 0) + 1
    top_events = dict(sorted(event_counts.items(), key=lambda x: -x[1])[:20])

    # Firewall / block events
    blocks = [
        e for e in events
        if "block" in str(e.get("key", "")).lower()
        or "firewall" in str(e.get("msg", "")).lower()
        or "block" in str(e.get("msg", "")).lower()
    ]
    block_msgs = [str(b.get("msg", b.get("key", "")))[:120] for b in blocks[:20]]

    # Alarm messages
    alarm_msgs = [str(a.get("msg", ""))[:120] for a in alarms[:15]]

    # Rogue AP SSIDs
    rogue_ssids = [r.get("ssid", r.get("bssid", "unknown")) for r in rogue_aps[:10]]

    summary = f"""=== UniFi 24-Hour Security Summary — {today} ===

CLIENTS
  Total connected : {len(clients)}
  New vs baseline : {len(new_macs)}
  New MAC addresses: {sorted(new_macs) if new_macs else 'None'}

ALARMS ({len(alarms)} unarchived)
{json.dumps(alarm_msgs, indent=2)}

ROGUE ACCESS POINTS DETECTED: {len(rogue_aps)}
  SSIDs: {rogue_ssids if rogue_ssids else 'None'}

FIREWALL BLOCK EVENTS ({len(blocks)} in last 24h)
{json.dumps(block_msgs, indent=2)}

TOP EVENT TYPES (by frequency)
{json.dumps(top_events, indent=2)}

TOTAL RAW EVENTS PROCESSED: {len(events)}
"""
    return summary, current_macs


# ── LLM analysis ─────────────────────────────────────────────────────────────
def analyze_with_llm(summary: str) -> str:
    prompt = f"""You are a network security analyst reviewing a home network (not enterprise).
Analyze the 24-hour UniFi activity summary below for genuine security concerns.

Look specifically for:
- Port scanning or host enumeration
- New or unrecognized devices (flagged as new MACs)
- Unusual outbound connection patterns or destinations
- Slow beaconing behavior (periodic connections at regular intervals)
- Repeated firewall blocks from the same source
- Rogue access points impersonating known SSIDs
- Brute force attempts on any service
- Any multi-event pattern that individually looks innocent but together suggests compromise

Instructions:
- Rate each finding: HIGH / MED / LOW
- If nothing is genuinely suspicious, say so clearly — do not invent concerns
- Be concise; bullet points preferred
- End with a one-line overall verdict

{summary}"""

    try:
        r = requests.post(
            LLM_ENDPOINT,
            json={
                "model":       LLM_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  1500,
                "temperature": 0.2,   # low temp for analytical consistency
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError:
        return f"[ERROR] Could not reach LLM at {LLM_ENDPOINT} — is LM Studio running?"
    except (KeyError, IndexError) as e:
        return f"[ERROR] Unexpected LLM response format: {e}"


# ── Report writer ─────────────────────────────────────────────────────────────
def write_report(summary: str, analysis: str, dry_run: bool):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    date_str = str(datetime.date.today())
    suffix   = "_dryrun" if dry_run else ""
    path     = REPORT_DIR / f"security_{date_str}{suffix}.txt"

    llm_section = (
        "\n=== LLM ANALYSIS ===\n" + analysis
        if analysis
        else "\n=== LLM ANALYSIS SKIPPED (--dry-run) ==="
    )

    path.write_text(summary + llm_section, encoding="utf-8")
    return path


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="UniFi daily security analysis")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and summarize data but skip LLM call — good for first-run validation",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Print site IDs and test both API paths, then exit",
    )
    args = parser.parse_args()

    if args.discover:
        validate_config(require_site_id=False)
        discover()
        return

    validate_config(require_site_id=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n[{datetime.datetime.now():%Y-%m-%d %H:%M}] Starting UniFi security analysis")
    print(f"  Console : {CONSOLE_IP}")
    print(f"  Site ID : {SITE_ID}")
    print(f"  Mode    : {'DRY RUN (no LLM)' if args.dry_run else 'FULL'}\n")

    # Fetch
    print("Fetching UniFi data...")
    events   = fetch_events_24h()
    clients  = fetch_clients()
    alarms   = fetch_alarms()
    rogue_aps = fetch_rogue_aps()

    print(f"  Events   : {len(events)}")
    print(f"  Clients  : {len(clients)}")
    print(f"  Alarms   : {len(alarms)}")
    print(f"  Rogue APs: {len(rogue_aps)}")

    # Summarize
    baseline = load_baseline()
    summary, current_macs = build_summary(events, clients, alarms, rogue_aps, baseline)
    print(f"\n{'='*60}")
    print(summary)
    print('='*60)

    # LLM
    analysis = ""
    if not args.dry_run:
        print("\nSending to LLM for analysis...")
        analysis = analyze_with_llm(summary)
        print("\n=== LLM ANALYSIS ===")
        print(analysis)
    else:
        print("\n[DRY RUN] Skipping LLM call.")

    # Save report
    report_path = write_report(summary, analysis, args.dry_run)
    print(f"\nReport saved: {report_path}")

    # Update baseline (only on full runs so dry runs don't pollute it)
    if not args.dry_run:
        baseline = update_baseline(current_macs, baseline)
        BASELINE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        print("Baseline updated.")

    print("\nDone.\n")


if __name__ == "__main__":
    main()