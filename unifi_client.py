#!/usr/bin/env python3
"""unifi_client.py — UniFi REST API wrapper with proper 24h filtering."""

import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_24H = datetime.timedelta(hours=24)


def _mb(b):
    return round((b or 0) / 1_048_576, 1)


def _uptime_str(seconds):
    if not seconds:
        return "—"
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    return f"{d}d {h}h" if d else f"{h}h"


class UniFiClient:
    def __init__(self, console_ip, api_key, site_id, site_name="default"):
        self.console_ip = console_ip
        self.api_key    = api_key
        self.site_id    = site_id
        self.site_name  = site_name
        self._base      = f"https://{console_ip}/proxy/network"
        self._headers   = {"X-API-KEY": api_key, "Accept": "application/json"}

    # ── HTTP ───────────────────────────────────────────────────────────────
    def _get(self, path):
        r = requests.get(
            f"{self._base}{path}",
            headers=self._headers,
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        body = r.json()
        return body.get("data", body)

    def _filter_24h(self, items):
        """
        Filter to last 24h. Handles both:
          - ISO datetime string  (alarms: 'datetime' field)
          - Unix timestamp int   (events: 'time' field, milliseconds or seconds)
        """
        cutoff = datetime.datetime.now(datetime.timezone.utc) - _24H
        cutoff_ts = cutoff.timestamp()
        out = []
        for item in (items or []):
            # Try ISO datetime field first (alarms)
            raw = item.get("datetime")
            if raw:
                try:
                    t = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if t.timestamp() > cutoff_ts:
                        out.append(item)
                    continue
                except Exception:
                    pass
            # Try unix timestamp (events use 'time' in seconds)
            ts = item.get("time")
            if ts:
                try:
                    ts = float(ts)
                    # UniFi sometimes returns ms, sometimes seconds
                    if ts > 1e12:
                        ts /= 1000
                    if ts > cutoff_ts:
                        out.append(item)
                except Exception:
                    pass
        return out

    # ── Raw fetchers ───────────────────────────────────────────────────────
    def _clients(self):
        """
        Use internal stat/sta endpoint - returns all known clients including
        recently offline ones, no pagination limit unlike the integration API.
        """
        d = self._get(f"/api/s/{self.site_name}/stat/sta")
        if isinstance(d, list):
            return d
        # Fallback: integration API with pagination
        all_clients = []
        page = 1
        while True:
            d = self._get(
                f"/integration/v1/sites/{self.site_id}/clients"
                f"?pageSize=200&page={page}"
            )
            if not isinstance(d, list) or not d:
                break
            all_clients.extend(d)
            if len(d) < 200:
                break
            page += 1
        return all_clients

    def _alarms_24h(self):
        d = self._get(f"/api/s/{self.site_name}/stat/alarm?archived=false")
        return self._filter_24h(d if isinstance(d, list) else [])

    def _events_24h(self):
        # Internal API returns events newest-first by default, limit to 500
        d = self._get(f"/api/s/{self.site_name}/stat/event?_limit=500")
        items = d if isinstance(d, list) else []
        return self._filter_24h(items)

    def _rogue_aps(self):
        d = self._get(f"/api/s/{self.site_name}/stat/rogueap")
        return d if isinstance(d, list) else []

    def _devices(self):
        d = self._get(f"/api/s/{self.site_name}/stat/device")
        return d if isinstance(d, list) else []

    def _health(self):
        d = self._get(f"/api/s/{self.site_name}/stat/health")
        return d if isinstance(d, list) else []

    # ── Public ─────────────────────────────────────────────────────────────
    def test_connection(self):
        try:
            self._get("/integration/v1/sites")
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_diagnostics(self):
        """
        Returns raw sample records so you can verify the data
        matches what you actually see in the UniFi dashboard.
        """
        events  = self._events_24h()
        alarms  = self._alarms_24h()
        clients = self._clients()

        # Events use unix 'time' field; convert to readable string for display
        def event_ts(e):
            ts = e.get("time")
            if not ts:
                return None
            ts = float(ts)
            if ts > 1e12:
                ts /= 1000
            return datetime.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")

        newest = event_ts(events[0])  if events else None
        oldest = event_ts(events[-1]) if events else None

        # Slim client list for the table (just the fields we need)
        clients_raw = [
            {
                "hostname": c.get("hostname") or c.get("name") or "",
                "ip":       c.get("ip") or c.get("fixed_ip") or "",
                "mac":      c.get("mac") or "",
                "rssi":     c.get("rssi"),
            }
            for c in clients if c.get("mac")
        ]

        return {
            "preset":           "diagnostics",
            "event_count_24h":  len(events),
            "alarm_count_24h":  len(alarms),
            "client_count":     len(clients),
            "clients_raw":      clients_raw,
            "event_time_range": {
                "newest": newest,
                "oldest": oldest,
            },
            # Single raw sample records for field-level inspection
            "sample_event":  events[0]  if events  else None,
            "sample_alarm":  alarms[0]  if alarms  else None,
            "sample_client": clients[0] if clients else None,
        }

    def fetch_security_data(self):
        clients = self._clients()
        alarms  = self._alarms_24h()
        events  = self._events_24h()
        rogues  = self._rogue_aps()

        client_rows = [
            {
                # stat/sta uses 'hostname', integration API uses 'name'
                "hostname": c.get("hostname") or c.get("name") or c.get("oui", "—"),
                # stat/sta uses 'ip', may also be in 'fixed_ip'
                "ip":       c.get("ip") or c.get("fixed_ip", "—"),
                "mac":      c.get("mac", "—"),
                # stat/sta: wired=0/wireless=1, integration: 'WIRED'/'WIRELESS'
                "type":     c.get("type") or ("Wireless" if c.get("is_wired") is False
                             else "Wired" if c.get("is_wired") else "—"),
            }
            for c in clients
            if c.get("mac")   # skip any malformed entries
        ]

        event_counts = {}
        for e in events:
            key = str(e.get("key") or e.get("msg", "unknown"))[:80]
            event_counts[key] = event_counts.get(key, 0) + 1
        top_events = dict(sorted(event_counts.items(), key=lambda x: -x[1])[:15])

        blocks = [
            str(e.get("msg") or e.get("key", ""))[:120]
            for e in events
            if "block" in str(e.get("key", "")).lower()
            or "block" in str(e.get("msg", "")).lower()
        ]

        # WAN summary for broadband context
        health = self._health()
        wan = next((h for h in health if h.get("subsystem") == "wan"), {})
        wan_info = {
            "status":  wan.get("status", "unknown"),
            "latency": wan.get("latency"),
            "rx_mb":   _mb(wan.get("rx_bytes")),
            "tx_mb":   _mb(wan.get("tx_bytes")),
        }

        return {
            "preset":          "security",
            "period":          "last 24 hours",
            "wan":             wan_info,
            "client_count":    len(client_rows),
            "clients":         client_rows,
            "alarm_count":     len(alarms),
            "alarms":          [a.get("msg", "") for a in alarms[:20]],
            "event_count":     len(events),
            "top_events":      top_events,
            "block_count":     len(blocks),
            "firewall_blocks": blocks[:10],
            "rogue_ap_count":  len(rogues),
            # Full rogue AP detail for meaningful LLM analysis
            "rogue_aps": [
                {
                    "ssid":     r.get("ssid", ""),
                    "bssid":    r.get("bssid", ""),
                    "rssi":     r.get("rssi"),
                    "channel":  r.get("channel"),
                    "security": r.get("security", "unknown"),
                    "is_adhoc": r.get("is_adhoc", False),
                }
                for r in sorted(rogues, key=lambda x: x.get("rssi") or -999, reverse=True)[:30]
            ],
            # Flag any rogue AP whose SSID matches one of our own networks
            "evil_twin_candidates": [
                r.get("bssid") for r in rogues
                if r.get("ssid") and r.get("ssid") in [
                    d.get("name","") for d in self._devices()
                    if d.get("name")
                ]
            ],
        }

    def fetch_health_data(self):
        devices = self._devices()
        clients = self._clients()

        device_rows = []
        for d in devices:
            ss = d.get("system-stats") or {}
            device_rows.append({
                "name":    d.get("name") or d.get("hostname", "—"),
                "type":    d.get("type", "—"),
                "model":   d.get("model", "—"),
                "version": d.get("version", "—"),
                "ip":      d.get("ip", "—"),
                "state":   d.get("state", 0),
                "uptime":  _uptime_str(d.get("uptime")),
                "cpu":     ss.get("cpu"),
                "mem":     ss.get("mem"),
            })

        return {
            "preset":       "health",
            "device_count": len(device_rows),
            "client_count": len(clients),
            "devices":      device_rows,
        }

    def fetch_performance_data(self):
        health  = self._health()
        clients = self._clients()

        wan = next((h for h in health if h.get("subsystem") == "wan"), {})
        wan_summary = {
            "status":  wan.get("status", "unknown"),
            "rx_mb":   _mb(wan.get("rx_bytes")),
            "tx_mb":   _mb(wan.get("tx_bytes")),
            "latency": wan.get("latency"),
        }

        top_clients = []
        for c in sorted(
            clients,
            key=lambda x: (x.get("tx_bytes") or 0) + (x.get("rx_bytes") or 0),
            reverse=True,
        )[:10]:
            rx = c.get("rx_bytes") or 0
            tx = c.get("tx_bytes") or 0
            top_clients.append({
                "hostname": c.get("hostname") or c.get("name", "—"),
                "ip":       c.get("ip", "—"),
                "rx_mb":    _mb(rx),
                "tx_mb":    _mb(tx),
                "total_mb": _mb(rx + tx),
            })

        return {
            "preset":       "performance",
            "client_count": len(clients),
            "wan":          wan_summary,
            "top_clients":  top_clients,
        }
