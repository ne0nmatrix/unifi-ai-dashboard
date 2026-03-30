#!/usr/bin/env python3
"""
db.py — SQLite snapshot store for client bandwidth history.

UniFi's stat/sta returns CUMULATIVE byte counters (total since client connected).
We store raw cumulative values and compute deltas between consecutive snapshots
to get "bytes used in this interval" — which is actual bandwidth consumption.
"""

import sqlite3
import datetime
from pathlib import Path


def get_db_path():
    """Resolve DB path from env or default alongside daily reports."""
    import os
    report_dir = os.getenv("REPORT_DIR", "reports")
    path = Path(report_dir)
    path.mkdir(parents=True, exist_ok=True)
    return str(path / "network_history.db")


def _connect():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS client_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at TEXT    NOT NULL,   -- ISO timestamp
                mac         TEXT    NOT NULL,
                hostname    TEXT,
                ip          TEXT,
                rx_bytes    INTEGER,            -- cumulative total from UniFi
                tx_bytes    INTEGER
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_mac_time
            ON client_snapshots (mac, captured_at)
        """)
        conn.commit()


def save_snapshot(clients: list):
    """
    Persist a snapshot of all current clients.
    Called every time the dashboard fetches data.
    """
    now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    rows = [
        (
            now,
            c.get("mac", ""),
            c.get("hostname") or c.get("name") or "",
            c.get("ip") or c.get("fixed_ip") or "",
            c.get("rx_bytes") or 0,
            c.get("tx_bytes") or 0,
        )
        for c in clients
        if c.get("mac")
    ]
    if not rows:
        return
    with _connect() as conn:
        conn.executemany(
            "INSERT INTO client_snapshots "
            "(captured_at, mac, hostname, ip, rx_bytes, tx_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()


def get_known_clients() -> list:
    """
    Return all distinct clients ever seen, with their most recent hostname/IP.
    Used to populate the client picker dropdown.
    """
    with _connect() as conn:
        rows = conn.execute("""
            SELECT mac,
                   hostname,
                   ip,
                   MAX(captured_at) AS last_seen
            FROM client_snapshots
            WHERE mac != ''
            GROUP BY mac
            ORDER BY hostname ASC, last_seen DESC
        """).fetchall()
    return [dict(r) for r in rows]


def get_bandwidth_series(mac: str) -> list:
    """
    Return per-interval bandwidth (MB) for a specific client, computed
    from consecutive cumulative snapshots.

    Returns list of:
      { captured_at, rx_mb, tx_mb, hostname, ip }

    The first snapshot for each session has no prior to diff against so
    it is omitted — only intervals with a valid delta are returned.
    """
    with _connect() as conn:
        rows = conn.execute("""
            SELECT captured_at, rx_bytes, tx_bytes, hostname, ip
            FROM client_snapshots
            WHERE mac = ?
            ORDER BY captured_at ASC
        """, (mac,)).fetchall()

    rows = [dict(r) for r in rows]
    if len(rows) < 2:
        return []

    result = []
    for i in range(1, len(rows)):
        prev = rows[i - 1]
        curr = rows[i]

        # Counters reset when a client reconnects — skip negative deltas
        rx_delta = curr["rx_bytes"] - prev["rx_bytes"]
        tx_delta = curr["tx_bytes"] - prev["tx_bytes"]
        if rx_delta < 0 or tx_delta < 0:
            continue

        result.append({
            "captured_at": curr["captured_at"],
            "rx_mb":       round(rx_delta / 1_048_576, 3),
            "tx_mb":       round(tx_delta / 1_048_576, 3),
            "hostname":    curr["hostname"] or prev["hostname"] or mac,
            "ip":          curr["ip"] or prev["ip"] or "",
        })

    return result


def get_before_after(mac: str, split_date: str) -> dict:
    """
    Split a client's bandwidth history at split_date (YYYY-MM-DD).
    Returns aggregated stats for before and after periods.

    split_date is the date of the change being evaluated —
    'before' = everything before that date, 'after' = that date onwards.
    """
    series = get_bandwidth_series(mac)
    if not series:
        return {"ok": False, "error": "Not enough data for this client yet."}

    before = [s for s in series if s["captured_at"][:10] <  split_date]
    after  = [s for s in series if s["captured_at"][:10] >= split_date]

    def _stats(intervals):
        if not intervals:
            return None
        total_rx  = sum(s["rx_mb"] for s in intervals)
        total_tx  = sum(s["tx_mb"] for s in intervals)
        n         = len(intervals)
        dates     = sorted({s["captured_at"][:10] for s in intervals})
        return {
            "snapshots":      n,
            "days":           len(dates),
            "date_range":     f"{dates[0]} → {dates[-1]}" if dates else "—",
            "total_rx_mb":    round(total_rx, 1),
            "total_tx_mb":    round(total_tx, 1),
            "avg_rx_mb":      round(total_rx / n, 3),
            "avg_tx_mb":      round(total_tx / n, 3),
            # Daily averages (more intuitive for camera comparison)
            "daily_rx_mb":    round(total_rx / max(len(dates), 1), 1),
            "daily_tx_mb":    round(total_tx / max(len(dates), 1), 1),
        }

    hostname = series[-1]["hostname"] if series else mac

    return {
        "ok":        True,
        "mac":       mac,
        "hostname":  hostname,
        "split_date": split_date,
        "before":    _stats(before),
        "after":     _stats(after),
    }
