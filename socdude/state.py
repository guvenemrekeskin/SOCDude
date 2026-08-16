"""Persistent state for SOCDude: cooldown/rate-limit gating, event
history for correlation, and an IOC enrichment cache - all in one
SQLite file.

Why SQLite instead of the original JSON file + fcntl lock: Wazuh can
spawn several instances of this script concurrently for different
alerts. A single JSON file with an advisory flock works, but it gives
you exactly one bucket of state and no query capability. SQLite in WAL
mode gives us real transactional safety (BEGIN IMMEDIATE serializes
writers, readers don't block writers) *and* a place to store the event
history and enrichment cache the new correlation/enrichment features
need, without inventing a second storage mechanism.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS rule_cooldown (
    rule_key TEXT PRIMARY KEY,
    last_sent REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS burst_window (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    window_start REAL NOT NULL,
    count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    ts REAL NOT NULL,
    rule_id TEXT,
    level INTEGER,
    description TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events(agent_id, ts);

CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc TEXT NOT NULL,
    source TEXT NOT NULL,
    result TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (ioc, source)
);
"""


@contextlib.contextmanager
def connect(db_path: str):
    conn = sqlite3.connect(db_path, timeout=10, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


def gate_check(db_path: str, rule_id: str, agent_id: str, cfg: Dict[str, Any]) -> bool:
    """Per-(rule, agent) cooldown + global burst limiter, applied atomically.

    Returns True if the alert should proceed, False if it should be
    suppressed silently (the caller still logs the suppression).
    """
    key = f"{rule_id}_{agent_id}"
    now = time.time()

    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            row = conn.execute(
                "SELECT last_sent FROM rule_cooldown WHERE rule_key = ?", (key,)
            ).fetchone()
            if row and (now - row[0]) < cfg["cooldown_seconds"]:
                conn.execute("ROLLBACK;")
                return False

            burst = conn.execute(
                "SELECT window_start, count FROM burst_window WHERE id = 1"
            ).fetchone()
            window = cfg["global_rate_limit_seconds"]
            max_burst = cfg["global_rate_limit_max_burst"]

            if burst is None or (now - burst[0]) > window:
                window_start, count = now, 0
            else:
                window_start, count = burst

            if count >= max_burst:
                conn.execute("ROLLBACK;")
                return False

            conn.execute(
                "INSERT INTO burst_window (id, window_start, count) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET window_start = excluded.window_start, "
                "count = excluded.count",
                (window_start, count + 1),
            )
            conn.execute(
                "INSERT INTO rule_cooldown (rule_key, last_sent) VALUES (?, ?) "
                "ON CONFLICT(rule_key) DO UPDATE SET last_sent = excluded.last_sent",
                (key, now),
            )
            # Prune stale cooldown rows so the table doesn't grow forever.
            cutoff = now - (cfg["cooldown_seconds"] * 4)
            conn.execute("DELETE FROM rule_cooldown WHERE last_sent < ?", (cutoff,))
            conn.execute("COMMIT;")
            return True
        except Exception:
            conn.execute("ROLLBACK;")
            raise


def record_event(db_path: str, agent_id: str, rule_id: str, level: int,
                  description: str, raw: Dict[str, Any]) -> None:
    now = time.time()
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO events (agent_id, ts, rule_id, level, description, raw) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, now, rule_id, level, description, json.dumps(raw)[:4000]),
        )
        # Correlation only ever looks back a bounded window, so we don't
        # need to keep event history forever.
        conn.execute("DELETE FROM events WHERE ts < ?", (now - 86400,))


def get_related_events(db_path: str, agent_id: str, window_seconds: int,
                        max_events: int) -> List[Dict[str, Any]]:
    since = time.time() - window_seconds
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT ts, rule_id, level, description FROM events "
            "WHERE agent_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (agent_id, since, max_events),
        ).fetchall()
    return [
        {"ts": r[0], "rule_id": r[1], "level": r[2], "description": r[3]}
        for r in rows
    ]


def cache_get(db_path: str, ioc: str, source: str, ttl_seconds: int) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT result, fetched_at FROM ioc_cache WHERE ioc = ? AND source = ?",
            (ioc, source),
        ).fetchone()
    if not row:
        return None
    result, fetched_at = row
    if time.time() - fetched_at > ttl_seconds:
        return None
    try:
        return json.loads(result)
    except Exception:
        return None


def cache_set(db_path: str, ioc: str, source: str, result: Dict[str, Any]) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO ioc_cache (ioc, source, result, fetched_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ioc, source) DO UPDATE SET result = excluded.result, "
            "fetched_at = excluded.fetched_at",
            (ioc, source, json.dumps(result), time.time()),
        )
