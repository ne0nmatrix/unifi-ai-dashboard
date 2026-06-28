#!/usr/bin/env python3
"""unifi_client.py — UniFi REST API wrapper with 24h filtering and 10.x fallbacks."""

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
        # Track which endpoint paths worked, for diagnostics
        self._endpoint_status = {}

    # ── HTTP ───────────────────────────────────────────────────────────────
    def _get(self, path, raise_on_error=True):
        try:
            r = requests.get(
                f"{self._base}{path}",
                headers=self._headers,
                verify=False,
                timeout=15,
            )
            r.raise_for_status()
            body = r.json()
            self._endpoint_status[path] = "ok"
            return body.get("data", body)
        except Exception as e:
            self._endpoint_status[path] = f"FAIL: {type(e).__name__}: {str(e)[:80]}"
            if raise_on_error:
                raise
            return None

    def _try_paths(self, paths):
        """Try multiple endpoint paths, return first one that works."""
        for path in paths:
            data = self._get(path, raise_on_error=False)
            if isinstance(data, list):
                return data
        return []

    def _filter_24h(self, items):
        """Handles both ISO datetime (alarms) and Unix time (events)."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - _24H
        cutoff_ts = cutoff.timestamp()
        out = []
        for item in (items or []):
            raw = item.get("datetime")
            if raw:
                try:
                    t = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if t.timestamp() > cutoff_ts:
                        out.append(item)
                    continue
                except Exception:
                    pass
            ts = item.get("time")
            if ts:
                try:
                    ts = float(ts)
                    if ts > 1e12:
                        ts /= 1000
                    if ts > cutoff_ts:
                        out.append(item)
                except Exception:
                    pass
        return out

    # ── Raw fetchers (now with fallbacks for UniFi 10.x) ───────────────────
    def _clients(self):
        d = self._get(f"/api/s/{self.site_name}/stat/sta", raise_on_error=False)
        if isinstance(d, list):
            return d
        # Integration API fallback
        all_clients = []
        page = 1
        while True:
            d = self._get(
                f"/integration/v1/sites/{self.site_id}/clients?pageSize=200&page={page}",
                raise_on_error=False,
            )
            if not isinstance(d, list) or not d:
                break
            all_clients.extend(d)
            if len(d) < 200:
                break
            page += 1
        return all_clients

    def _alarms_24h(self):
        """UniFi 10.x changed stat/alarm to list/alarm. Try both."""
        data = self._try_paths([
            f"/api/s/{self.site_name}/list/alarm?archived=false",
            f"/api/s/{self.site_name}/stat/alarm?archived=false",
            f"/api/s/{self.site_name}/rest/alarm?archived=false",
        ])
        return self._filter_24h(data)

    def _events_24h(self):
        """UniFi 10.x — events may have moved. Try generic then IPS paths."""
        data = self._try_paths([
            f"/api/s/{self.site_name}/stat/event?_limit=500",
            f"/api/s/{self.site_name}/list/event?_limit=500",
            f"/api/s/{self.site_name}/stat/ips/event?_limit=500",
        ])
        return self._filter_24h(data)

    def _rogue_aps(self):
        d = self._get(f"/api/s/{self.site_name}/stat/rogueap", raise_on_error=False)
        return d if isinstance(d, list) else []

    def _devices(self):
        d = self._get(f"/api/s/{self.site_name}/stat/device", raise_on_error=False)
        return d if isinstance(d, list) else []

    def _health(self):
        d = self._get(f"/api/s/{self.site_name}/stat/health", raise_on_error=False)
        return d if isinstance(d, list) else []

    def _sysinfo(self):
        d = self._get(f"/api/s/{self.site_name}/stat/sysinfo", raise_on_error=False)
        return d if isinstance(d, list) else []

    def controller_version(self):
        """UniFi Network application version — governs which API endpoints exist.
        Event endpoints move/disappear across Network 10.x, so reports should record
        the version they ran against."""
        si = self._sysinfo()
        if si and isinstance(si[0], dict):
            return si[0].get("version") or si[0].get("build") or "unknown"
        return "unknown"

    def _events_endpoint_ok(self):
        """True if ANY event-fetch path returned successfully (vs all 400/404).
        Lets the diagnostics distinguish 'events endpoint moved' from 'pipeline broken'."""
        return any(
            status == "ok"
            for path, status in self._endpoint_status.items()
            if "event" in path
        )

    # ── Public ─────────────────────────────────────────────────────────────
    def test_connection(self):
        try:
            self._get("/integration/v1/sites")
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_diagnostics(self):
        events  = self._events_24h()
        alarms  = self._alarms_24h()
        clients = self._clients()

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
            "preset":             "diagnostics",
            "controller_version": self.controller_version(),
            "events_endpoint_ok": self._events_endpoint_ok(),
            "event_count_24h":    len(events),
            "alarm_count_24h":    len(alarms),
            "client_count":       len(clients),
            "clients_raw":        clients_raw,
            "event_time_range":  {"newest": newest, "oldest": oldest},
            "sample_event":      events[0]  if events  else None,
            "sample_alarm":      alarms[0]  if alarms  else None,
            "sample_client":     clients[0] if clients else None,
            "endpoint_status":   dict(self._endpoint_status),
        }

    def fetch_security_data(self):
        clients = self._clients()
        alarms  = self._alarms_24h()
        events  = self._events_24h()
        rogues  = self._rogue_aps()

        client_rows = [
            {
                "hostname": c.get("hostname") or c.get("name") or c.get("oui", "—"),
                "ip":       c.get("ip") or c.get("fixed_ip", "—"),
                "mac":      c.get("mac", "—"),
                "type":     c.get("type") or ("Wireless" if c.get("is_wired") is False
                             else "Wired" if c.get("is_wired") else "—"),
            }
            for c in clients
            if c.get("mac")
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

        health = self._health()
        wan = next((h for h in health if h.get("subsystem") == "wan"), {})
        wan_info = {
            "status":  wan.get("status", "unknown"),
            "latency": wan.get("latency"),
            "rx_mb":   _mb(wan.get("rx_bytes")),
            "tx_mb":   _mb(wan.get("tx_bytes")),
        }

        try:
            our_ssids = {d.get("name", "") for d in self._devices() if d.get("name")}
            evil_twins = [
                r.get("bssid") for r in rogues
                if r.get("ssid") and r.get("ssid") in our_ssids
            ]
        except Exception:
            evil_twins = []

        return {
            "preset":             "security",
            "period":             "last 24 hours",
            "controller_version": self.controller_version(),
            "events_endpoint_ok": self._events_endpoint_ok(),
            "wan":                wan_info,
            "client_count":       len(client_rows),
            "clients":         client_rows,
            "alarm_count":     len(alarms),
            "alarms":          [a.get("msg", "") for a in alarms[:20]],
            "event_count":     len(events),
            "top_events":      top_events,
            "block_count":     len(blocks),
            "firewall_blocks": blocks[:10],
            "rogue_ap_count":  len(rogues),
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
            "evil_twin_candidates": evil_twins,
            "endpoint_status": dict(self._endpoint_status),
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