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
import time
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
# Tolerate a bare host:port in .env (2026-07-15: LLM_ENDPOINT=http://localhost:1234
# made the POST land on LM Studio's root and die with KeyError 'choices').
if "/chat/completions" not in LLM_ENDPOINT:
    LLM_ENDPOINT = LLM_ENDPOINT.rstrip("/") + "/v1/chat/completions"
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

def api_get(path, quiet=False):
    """GET from UniFi console; returns the inner data list/dict, or None on
    HTTP failure (so callers can tell 'endpoint broken' from 'legitimately
    empty' — the old []-on-404 made a quiet night and a dead endpoint look
    identical). quiet=True suppresses the WARN, for fallback chains that only
    warn when EVERY variant fails."""
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
        # Don't let one bad endpoint kill the whole run. 401 is fatal.
        if not quiet:
            print(f"[WARN] HTTP {code} from {url}")
        if code == 401:
            print("        API key rejected — check UNIFI_API_KEY in .env")
            sys.exit(1)
        return None


def api_post(path, body, quiet=False):
    """POST a query to the UniFi console (the v2 endpoints are POST-queries,
    not mutations). Same return contract as api_get."""
    url = f"https://{CONSOLE_IP}/proxy/network{path}"
    try:
        r = requests.post(url, headers={**make_headers(), "Content-Type": "application/json"},
                          json=body, verify=False, timeout=15)
        r.raise_for_status()
        b = r.json()
        return b.get("data", b)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot reach {url} — is the console IP correct?")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code
        if not quiet:
            print(f"[WARN] HTTP {code} from {url}")
        if code == 401:
            print("        API key rejected — check UNIFI_API_KEY in .env")
            sys.exit(1)
        return None


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
    alarms = api_get(f"/api/s/{site_path}/list/alarm")   # stat/alarm 404s on 10.4+
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
# v2 system-log enums, straight from the controller's own 400 error message
# (unpoller/unifi#198, verified against 2026 firmware): send the full sets.
V2_LOG_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
V2_LOG_CATEGORIES = ["SECURITY", "UNIFI_DEVICES", "SOFTWARE_UPDATES", "VPN",
                     "POWER", "UNIFI_ETHERNET_PORTS", "CLIENT_DEVICES",
                     "UNKNOWN", "AUDIT", "INTERNET_AND_WAN"]


def _normalize_v2_event(item):
    """Map a v2 system-log record onto the legacy shape the analysis reads
    (key / msg / time), keeping all original fields."""
    e = dict(item)
    e.setdefault("key", item.get("type") or item.get("category") or "v2-event")
    e.setdefault("msg", item.get("message") or item.get("title")
                 or item.get("description") or "")
    e.setdefault("time", item.get("timestamp") or item.get("time"))
    return e


def fetch_events_24h():
    """UniFi has moved the events endpoint twice (stat/event -> 404 on
    Network 10.4+; list/event exists but 400s on shape). Try the CURRENT
    endpoint first (v2 system-log/all, what the UI's System Log page calls),
    then fall back quietly through the legacy variants; warn only when every
    variant fails. probe_endpoints.py is the re-hunting tool if that happens."""
    now_ms = int(time.time() * 1000)
    v2_body = {"timestampFrom": now_ms - 24 * 3600 * 1000, "timestampTo": now_ms,
               "pageNumber": 0, "pageSize": 1000,
               "severities": V2_LOG_SEVERITIES, "categories": V2_LOG_CATEGORIES}
    attempts = [
        ("v2 system-log/all", True,
         lambda: api_post(f"/v2/api/site/{SITE_NAME}/system-log/all", v2_body, quiet=True)),
        ("stat/event", False,
         lambda: api_get(f"/api/s/{SITE_NAME}/stat/event?within=24", quiet=True)),
        ("list/event GET", False,
         lambda: api_get(f"/api/s/{SITE_NAME}/list/event?within=24&_limit=500&_start=0", quiet=True)),
        ("list/event POST", False,
         lambda: api_post(f"/api/s/{SITE_NAME}/list/event",
                          {"within": 24, "_limit": 500, "_start": 0}, quiet=True)),
    ]
    for label, is_v2, call in attempts:
        data = call()
        if data is None:
            continue                      # endpoint failed - try next variant
        if isinstance(data, dict):        # some v2 replies nest the list
            data = data.get("data") or data.get("elements") or data.get("items") or []
        if isinstance(data, list):
            print(f"  [events] via {label} ({len(data)} in 24h)")
            return [_normalize_v2_event(e) for e in data] if is_v2 else data
    print("[WARN] ALL event endpoint variants failed (v2 system-log/all, "
          "stat/event, list/event GET+POST) - run probe_endpoints.py to re-hunt")
    return []

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
    """stat/alarm 404s on Network 10.4+; list/alarm was confirmed working by
    the 2026-06-27 probe run. Try it first, keep stat/alarm as the fallback
    for older controllers."""
    for label, path in (("list/alarm", f"/api/s/{SITE_NAME}/list/alarm?archived=false"),
                        ("stat/alarm", f"/api/s/{SITE_NAME}/stat/alarm?archived=false")):
        data = api_get(path, quiet=True)
        if isinstance(data, list):
            print(f"  [alarms] via {label} ({len(data)} unarchived)")
            return data
    print("[WARN] both alarm endpoints failed (list/alarm, stat/alarm)")
    return []

def fetch_own_ssids():
    """Configured SSIDs from wlanconf — the reference set for the evil-twin
    check. Quiet: if the endpoint moves someday, the check just degrades."""
    data = api_get(f"/api/s/{SITE_NAME}/rest/wlanconf", quiet=True)
    if not isinstance(data, list):
        return set()
    return {w.get("name") for w in data if w.get("name")}


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
def _alarm_ts(a):
    """Best-effort alarm timestamp in epoch seconds (fields vary by version)."""
    t = a.get("time")
    if isinstance(t, (int, float)):
        return t / 1000.0 if t > 1e12 else t
    dt = a.get("datetime")
    if isinstance(dt, str):
        try:
            return datetime.datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def build_summary(events, clients, alarms, rogue_aps, baseline, own_ssids=None):
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

    # Alarms: list/alarm?archived=false is the ALL-TIME unarchived pile, not a
    # 24h window (2026-07-15: 146 stale alarms — largely Syncthing-era IPS noise
    # from before the 05-20 decommission — read as a fresh incident). Split by
    # timestamp so the LLM reasons on what actually happened in the last day.
    now = time.time()
    recent_alarms = [a for a in alarms if (_alarm_ts(a) or 0) >= now - 24 * 3600]
    alarm_msgs = [str(a.get("msg", ""))[:120] for a in recent_alarms[:15]]

    # Rogue APs + evil-twin check: dozens of neighbor APs are normal noise; a
    # neighbor broadcasting OUR SSID is the actual attack signature.
    _essid = lambda r: r.get("essid") or r.get("ssid") or ""
    twins = [r for r in rogue_aps if own_ssids and _essid(r) in own_ssids]
    twin_desc = [f"{_essid(r)} @ {r.get('bssid', '?')}" for r in twins[:10]]
    rogue_ssids = [_essid(r) or r.get("bssid", "unknown") for r in rogue_aps[:10]]

    summary = f"""=== UniFi 24-Hour Security Summary — {today} ===

CLIENTS
  Total connected : {len(clients)}
  New vs baseline : {len(new_macs)}
  New MAC addresses: {sorted(new_macs) if new_macs else 'None'}

ALARMS: {len(recent_alarms)} in last 24h ({len(alarms)} unarchived all-time backlog — old alarms, not current activity)
{json.dumps(alarm_msgs, indent=2) if recent_alarms else '  (no new alarms in the last 24h)'}

NEIGHBORING ("ROGUE") APs DETECTED: {len(rogue_aps)} (residential noise unless they broadcast our SSID)
  Evil-twin check ({len(own_ssids or [])} own SSIDs compared): {twin_desc if twins else 'no neighbor AP broadcasts our SSIDs'}
  Sample: {rogue_ssids if rogue_ssids else 'None'}

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
        # show WHAT came back, not just which key was missing — a wrong
        # endpoint, an unloaded model, or an LM Studio error object all
        # produce this, and the body names the real reason
        try:
            body = json.dumps(r.json())[:300]
        except Exception:
            body = (r.text or "")[:300]
        return (f"[ERROR] Unexpected LLM response format ({e}) from "
                f"{LLM_ENDPOINT} — response: {body}")


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
    own_ssids = fetch_own_ssids()
    summary, current_macs = build_summary(events, clients, alarms, rogue_aps,
                                          baseline, own_ssids)
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

    # Update baseline on EVERY run, dry included. The daily brief runs
    # --dry-run, so the old only-on-full-runs rule meant the baseline never
    # matured and every device was "new vs baseline" forever (2026-07-15:
    # all 66 clients flagged, LLM verdict rightly called the input absurd).
    # Observing which MACs are present doesn't need the LLM.
    baseline = update_baseline(current_macs, baseline)
    BASELINE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    print("Baseline updated." + (" (dry run counts — the daily brief matures it)"
                                 if args.dry_run else ""))

    print("\nDone.\n")


if __name__ == "__main__":
    main()