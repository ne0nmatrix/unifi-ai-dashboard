#!/usr/bin/env python3
"""archive_alarms.py — inspect, then archive, the UniFi alarm backlog.

Why (2026-07-15): list/alarm?archived=false returns the ALL-TIME unarchived
pile — 146 alarms, largely pre-2026-05-20 Syncthing-era IPS/Tor noise — which
made the first post-endpoint-fix security report look like an active incident.
Once the backlog is archived, an unarchived alarm means something again.

Default run is READ-ONLY: prints a month-by-month histogram and the oldest /
newest alarms so you can VERIFY the pile is historical before acting.

    python archive_alarms.py                 # dry list (no changes)
    python archive_alarms.py --archive-all   # archive everything listed

Archiving is the UniFi UI's own bulk action (cmd/evtmgr archive-all-alarms),
not a delete — archived alarms remain visible under the archived filter.
Uses the same .env as the dashboard (UNIFI_CONSOLE_IP / UNIFI_API_KEY).
"""
import argparse
import datetime
import os
import sys
from collections import Counter

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

IP   = os.getenv("UNIFI_CONSOLE_IP")
KEY  = os.getenv("UNIFI_API_KEY")
SITE = os.getenv("UNIFI_SITE_NAME", "default")
BASE = f"https://{IP}/proxy/network"
H    = {"X-API-KEY": KEY, "Accept": "application/json",
        "Content-Type": "application/json"}


def die(msg):
    print(f"[ERROR] {msg}")
    sys.exit(1)


def alarm_dt(a):
    """Best-effort alarm datetime (fields vary by controller version)."""
    t = a.get("time")
    if isinstance(t, (int, float)):
        return datetime.datetime.fromtimestamp(t / 1000.0 if t > 1e12 else t)
    dt = a.get("datetime")
    if isinstance(dt, str):
        try:
            return datetime.datetime.fromisoformat(dt.replace("Z", "+00:00")) \
                                    .replace(tzinfo=None)
        except ValueError:
            return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive-all", action="store_true",
                    help="actually archive after listing (default: read-only)")
    args = ap.parse_args()

    if not IP or not KEY:
        die("UNIFI_CONSOLE_IP / UNIFI_API_KEY missing — run from the repo dir so .env loads")

    r = requests.get(f"{BASE}/api/s/{SITE}/list/alarm?archived=false",
                     headers=H, verify=False, timeout=15)
    if r.status_code != 200:
        die(f"list/alarm returned HTTP {r.status_code}: {r.text[:200]}")
    alarms = r.json().get("data", [])
    if not alarms:
        print("No unarchived alarms — nothing to do.")
        return

    dts = [d for d in (alarm_dt(a) for a in alarms) if d]
    undated = len(alarms) - len(dts)
    by_month = Counter(d.strftime("%Y-%m") for d in dts)

    print(f"\n{len(alarms)} unarchived alarms"
          + (f" ({undated} with unparseable timestamps)" if undated else ""))
    print("\nBy month:")
    for month in sorted(by_month):
        print(f"  {month}: {by_month[month]:4d}  {'#' * min(by_month[month], 60)}")
    if dts:
        oldest, newest = min(dts), max(dts)
        print(f"\nOldest: {oldest:%Y-%m-%d %H:%M}   Newest: {newest:%Y-%m-%d %H:%M}")
        age_days = (datetime.datetime.now() - newest).days
        if age_days >= 7:
            print(f"Newest alarm is {age_days} days old — this is a historical "
                  "backlog, not current activity.")
        else:
            print(f"NOTE: newest alarm is only {age_days} day(s) old — review "
                  "recent entries before archiving; they may be live signal.")
    print("\nSample (3 oldest):")
    for a in sorted(alarms, key=lambda a: alarm_dt(a) or datetime.datetime.max)[:3]:
        d = alarm_dt(a)
        print(f"  [{d:%Y-%m-%d}] {str(a.get('msg', ''))[:100]}" if d
              else f"  [no date] {str(a.get('msg', ''))[:100]}")

    if not args.archive_all:
        print("\nRead-only pass done. To archive everything above:")
        print("    python archive_alarms.py --archive-all\n")
        return

    r = requests.post(f"{BASE}/api/s/{SITE}/cmd/evtmgr",
                      headers=H, json={"cmd": "archive-all-alarms"},
                      verify=False, timeout=30)
    if r.status_code != 200:
        die(f"archive-all-alarms returned HTTP {r.status_code}: {r.text[:200]} "
            "— archive via the UniFi UI (Alarms -> Archive All) instead")
    # verify, don't trust the 200
    r = requests.get(f"{BASE}/api/s/{SITE}/list/alarm?archived=false",
                     headers=H, verify=False, timeout=15)
    remaining = len(r.json().get("data", [])) if r.status_code == 200 else "?"
    print(f"\nArchived. Unarchived alarms remaining: {remaining}")
    if remaining == 0:
        print("Clean slate — from now on, any unarchived alarm is real signal.\n")


if __name__ == "__main__":
    main()
