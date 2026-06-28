#!/usr/bin/env python3
"""probe_endpoints.py — find which UniFi event/alarm endpoints work on THIS controller.

UniFi-OS Network updates frequently move/rename or change the method on the event &
IPS endpoints. When the "diagnostics" audit reports BROKEN event endpoints, run this:
it tries a matrix of path/method/param variants against your live controller and prints
which return data — and on failures it surfaces UniFi's own error message (meta.msg),
which usually names the missing param.

Read-only: every call just fetches (a POST to an event endpoint is a QUERY, not a
mutation). Uses the same .env as the dashboard. Run:  python probe_endpoints.py
"""
import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

IP   = os.getenv("UNIFI_CONSOLE_IP")
KEY  = os.getenv("UNIFI_API_KEY")
SITE = os.getenv("UNIFI_SITE_NAME", "default")
BASE = f"https://{IP}/proxy/network"
H    = {"X-API-KEY": KEY, "Accept": "application/json", "Content-Type": "application/json"}


def probe(method, path, body=None):
    url = f"{BASE}{path}"
    try:
        if method == "GET":
            r = requests.get(url, headers=H, verify=False, timeout=15)
        else:
            r = requests.post(url, headers=H, json=(body or {}), verify=False, timeout=15)
        code = r.status_code
        n, note = "-", ""
        try:
            j = r.json()
            data = j.get("data")
            meta = j.get("meta") or {}
            if isinstance(data, list):
                n = len(data)
                if data and isinstance(data[0], dict):
                    note = "keys=" + ",".join(list(data[0].keys())[:6])
            if code != 200 and meta.get("msg"):
                note = f"err={meta.get('msg')}"
        except Exception:
            note = (r.text or "")[:70].replace("\n", " ")
        flag = "OK  " if code == 200 else "    "
        bodystr = f"  body={body}" if (method == "POST" and body) else ""
        print(f"  {flag}{method:4} {code}  n={str(n):<5} {path}{bodystr}")
        if note:
            print(f"            {note}")
    except Exception as e:
        print(f"      {method:4} ERR  {type(e).__name__}: {str(e)[:60]}  {path}")


print(f"\n=== UniFi endpoint probe v2 — site='{SITE}' ===\n")

print("[control] known-good client endpoint (proves auth/proxy/site are fine):")
probe("GET", f"/api/s/{SITE}/stat/sta")

print("\n[events] stat/event is GONE (404). list/event EXISTS but returns 400 —")
print("         hunting the request shape. Watch the err= messages for the reason:")
probe("GET",  f"/api/s/{SITE}/list/event")
probe("GET",  f"/api/s/{SITE}/list/event?within=24")
probe("GET",  f"/api/s/{SITE}/list/event?_limit=100")
probe("GET",  f"/api/s/{SITE}/list/event?within=24&_limit=500&_start=0")
probe("POST", f"/api/s/{SITE}/list/event", {"within": 24})
probe("POST", f"/api/s/{SITE}/list/event", {"_limit": 100, "_start": 0})
probe("POST", f"/api/s/{SITE}/list/event", {"within": 24, "_limit": 500,
                                            "_start": 0, "_sort": "-time"})

print("\n[events] also re-test stat/event as POST-with-body (in case only the method moved):")
probe("POST", f"/api/s/{SITE}/stat/event", {"within": 24, "_limit": 500})

print("\n[ips/ids events]  (whole stat/event path is gone, so this may move too):")
probe("GET",  f"/api/s/{SITE}/list/event?within=24&key=IPS")
probe("GET",  f"/api/s/{SITE}/stat/ips/event?within=24")

print("\n[alarms] confirmed working (146) — re-confirm + show an alarm's time fields:")
probe("GET",  f"/api/s/{SITE}/list/alarm?archived=false")

print("\nResult guide: a line marked 'OK' with n>0 is the live events endpoint.")
print("For 400s, the err= line is UniFi's own reason (often the missing/invalid arg).\n")
