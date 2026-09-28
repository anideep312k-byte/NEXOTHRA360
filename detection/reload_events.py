"""
Cross-process reload coordination.

A shared table `detection_reload_events` records one row per reload
that has been applied to the running process. Every process polls
this table on a bounded interval; when the maximum sequence number
observed in the table exceeds the process's last-seen value, the
process performs a local reload and updates its last-seen marker.

This gives eventual consistency of rule sets across processes. The
propagation delay is bounded by the poll interval (default: 5 s).

No new dependencies. Uses the existing storage backend.
"""
from __future__ import annotations
import threading
import time
from typing import Any, Dict, Optional


_DDL_SQLITE = (
    "CREATE TABLE IF NOT EXISTS detection_reload_events ("
    "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts TEXT NOT NULL,"
    "  actor TEXT,"
    "  origin TEXT,"
    "  loaded INTEGER NOT NULL DEFAULT 0,"
    "  replaced INTEGER NOT NULL DEFAULT 0)"
)
_DDL_POSTGRES = (
    "CREATE TABLE IF NOT EXISTS detection_reload_events ("
    "  seq BIGSERIAL PRIMARY KEY,"
    "  ts TIMESTAMPTZ NOT NULL,"
    "  actor TEXT,"
    "  origin TEXT,"
    "  loaded INTEGER NOT NULL DEFAULT 0,"
    "  replaced INTEGER NOT NULL DEFAULT 0)"
)


def _backend_kind(db) -> str:
    ph = getattr(db, "placeholders", "?")
    return "postgres" if ph == "%s" else "sqlite"


class ReloadEventStore:
    """
    Records reload events and tracks the last-seen sequence number
    for this process. Thread-safe.
    """

    _ensure_lock = threading.Lock()

    def __init__(self, db) -> None:
        self.db = db
        self._lock = threading.Lock()
        self._last_seen: int = 0
        self._ensure_table()

    def _ensure_table(self) -> None:
        kind = _backend_kind(self.db)
        ddl = _DDL_POSTGRES if kind == "postgres" else _DDL_SQLITE
        try:
            with self.db.tx() as c:
                cur = c.cursor() if hasattr(c, "cursor") else c
                if hasattr(self.db, "adapt"):
                    cur.execute(self.db.adapt(ddl))
                else:
                    cur.execute(ddl)
            # Set the current high-water mark to the current max seq so
            # we do not replay history on startup.
            row = self.db.query_one(
                "SELECT COALESCE(MAX(seq),0) AS n FROM detection_reload_events")
            if row is not None:
                try:
                    self._last_seen = int(row["n"])
                except Exception:
                    self._last_seen = 0
        except Exception:
            # Table may already exist, or the backend may not support
            # this table yet. Treat as a no-op; the reload loop will
            # simply see no new events.
            pass

    def record(self, actor: str, origin: str,
               loaded: int = 0, replaced: int = 0) -> int:
        """Insert a reload event and return its seq."""
        kind = _backend_kind(self.db)
        try:
            with self.db.tx() as c:
                cur = c.cursor() if hasattr(c, "cursor") else c
                if kind == "postgres":
                    sql = ("INSERT INTO detection_reload_events"
                           "(ts,actor,origin,loaded,replaced) "
                           "VALUES(NOW(),?,?,?,?) RETURNING seq")
                else:
                    sql = ("INSERT INTO detection_reload_events"
                           "(ts,actor,origin,loaded,replaced) "
                           "VALUES(datetime('now'),?,?,?,?)")
                if hasattr(self.db, "adapt"):
                    sql = self.db.adapt(sql)
                cur.execute(sql, (actor or "", origin or "", int(loaded),
                                  int(replaced)))
                if kind == "postgres":
                    row = cur.fetchone()
                    seq = int(row["seq"]) if row else 0
                else:
                    seq = int(getattr(cur, "lastrowid", 0) or 0)
                with self._lock:
                    if seq > self._last_seen:
                        self._last_seen = seq
                return seq
        except Exception:
            return 0

    def latest_seq(self) -> int:
        try:
            row = self.db.query_one(
                "SELECT COALESCE(MAX(seq),0) AS n FROM detection_reload_events")
            if row is None:
                return 0
            return int(row["n"])
        except Exception:
            return 0

    def has_new(self) -> bool:
        """Return True if the shared table has advanced past last_seen."""
        return self.latest_seq() > self._last_seen

    def mark_seen(self, seq: Optional[int] = None) -> int:
        if seq is None:
            seq = self.latest_seq()
        with self._lock:
            self._last_seen = max(self._last_seen, int(seq))
            return self._last_seen

    def last_seen(self) -> int:
        with self._lock:
            return self._last_seen
