"""
database.py  –  Thread-safe SQLite persistence layer.

Tables
------
  events      : every telemetry event received from nodes
  ack_log     : per-packet RTT measurements (used for latency reports)
  perf_stats  : aggregated performance snapshots written by the perf collector
"""

import os
import sqlite3
import threading
import time

from config import DB_NAME

# Resolve DB path relative to this file so the server can be launched from
# any working directory.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)

# Use a single connection with check_same_thread=False and protect every
# write with a module-level lock.  (For a production system you would use a
# connection pool; for this project one connection is sufficient and avoids
# "database is locked" races.)
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_lock = threading.Lock()


def _init_schema() -> None:
    cur = _conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            node      TEXT    NOT NULL,
            timestamp INTEGER NOT NULL,
            event     TEXT    NOT NULL,
            metric    TEXT,
            value     TEXT,
            severity  TEXT    DEFAULT 'INFO'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ack_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            node       TEXT    NOT NULL,
            seq        INTEGER NOT NULL,
            sent_ts    REAL    NOT NULL,
            ack_ts     REAL    NOT NULL,
            rtt_ms     REAL    NOT NULL,
            retries    INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS perf_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at     INTEGER NOT NULL,
            active_nodes    INTEGER DEFAULT 0,
            events_per_sec  REAL    DEFAULT 0.0,
            avg_rtt_ms      REAL    DEFAULT 0.0,
            p99_rtt_ms      REAL    DEFAULT 0.0,
            packet_loss_pct REAL    DEFAULT 0.0,
            total_events    INTEGER DEFAULT 0
        )
    """)

    # Indexes to speed up the dashboard queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_node ON events(node)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp)")

    _conn.commit()


_init_schema()


# ── Write helpers ─────────────────────────────────────────────────────────────

def insert_event(node: str, ts: int, event: str,
                 metric: str, value: str, severity: str = "INFO") -> None:
    with _lock:
        _conn.execute(
            "INSERT INTO events(node, timestamp, event, metric, value, severity)"
            " VALUES (?,?,?,?,?,?)",
            (node, ts, event, metric, value, severity),
        )
        _conn.commit()


def insert_ack_log(node: str, seq: int, sent_ts: float,
                   ack_ts: float, retries: int = 0) -> None:
    rtt_ms = (ack_ts - sent_ts) * 1000.0
    with _lock:
        _conn.execute(
            "INSERT INTO ack_log(node, seq, sent_ts, ack_ts, rtt_ms, retries)"
            " VALUES (?,?,?,?,?,?)",
            (node, seq, sent_ts, ack_ts, rtt_ms, retries),
        )
        _conn.commit()


def insert_perf_snapshot(active_nodes: int, events_per_sec: float,
                         avg_rtt_ms: float, p99_rtt_ms: float,
                         packet_loss_pct: float, total_events: int) -> None:
    with _lock:
        _conn.execute(
            "INSERT INTO perf_stats"
            "(captured_at, active_nodes, events_per_sec, avg_rtt_ms,"
            " p99_rtt_ms, packet_loss_pct, total_events)"
            " VALUES (?,?,?,?,?,?,?)",
            (int(time.time()), active_nodes, events_per_sec,
             avg_rtt_ms, p99_rtt_ms, packet_loss_pct, total_events),
        )
        _conn.commit()


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_events(limit: int = 200,
               node_filter: str = "",
               event_filter: str = ""):
    """Return recent events, optionally filtered."""
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    if node_filter:
        query += " AND node LIKE ?"
        params.append(f"%{node_filter}%")
    if event_filter:
        query += " AND event LIKE ?"
        params.append(f"%{event_filter}%")
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with _lock:
        return [dict(r) for r in _conn.execute(query, params).fetchall()]


def get_rtt_stats(since_ts: float = 0.0) -> dict:
    """Return average and P99 RTT since a given epoch timestamp."""
    rows = _conn.execute(
        "SELECT rtt_ms FROM ack_log WHERE ack_ts >= ? ORDER BY rtt_ms",
        (since_ts,),
    ).fetchall()
    if not rows:
        return {"avg": 0.0, "p99": 0.0, "count": 0}
    rtts = [r[0] for r in rows]
    p99_idx = max(0, int(len(rtts) * 0.99) - 1)
    return {
        "avg":   round(sum(rtts) / len(rtts), 3),
        "p99":   round(rtts[p99_idx], 3),
        "count": len(rtts),
    }


def get_perf_history(limit: int = 60):
    """Return recent performance snapshots for the chart."""
    with _lock:
        return [
            dict(r) for r in _conn.execute(
                "SELECT * FROM perf_stats ORDER BY captured_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]


def get_event_count_since(since_ts: int) -> int:
    row = _conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since_ts,)
    ).fetchone()
    return row[0] if row else 0


def get_total_event_count() -> int:
    row = _conn.execute("SELECT COUNT(*) FROM events").fetchone()
    return row[0] if row else 0


def get_db():
    """Return the shared DB connection (for direct queries in web/app.py)."""
    return _conn