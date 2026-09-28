"""
SQLite storage backend.

Thin wrapper around the existing in-file Database class. It exists so
that call sites can depend on kavach_storage.StorageBackend rather than
on the concrete Database class, and so that a future PostgreSQL backend
can be swapped in without changing call sites.

Behavioral guarantees preserved from the original Database class:
  * Per-thread connections, PRAGMA configuration, WAL mode
  * BEGIN IMMEDIATE for write transactions
  * Stale-transaction auto-rollback in tx()
  * Counter tracking for execute() and begin() calls
  * Bounded connection registry with thread-aware eviction
  * Identical public method signatures

Any caller that used to do `Database(path)` can instead do
`SQLiteStorage(path)` and keep the same call site shape.
"""
from __future__ import annotations
import threading
from typing import Any, Dict, Iterable, List, Optional

from kavach_storage.base import StorageBackend


class SQLiteStorage(StorageBackend):
    """
    SQLite implementation of StorageBackend.

    The implementation delegates to the in-file Database class. That
    class is passed in rather than imported so the storage package
    remains free of circular imports and can be tested in isolation.
    """

    def __init__(self, db_cls, path: str) -> None:
        """
        db_cls: the concrete Database class from KAVACH360.py
        path:   filesystem path to the SQLite file, or ':memory:'
        """
        self._db = db_cls(path)

    # -- lifecycle ------------------------------------------------------
    def close(self) -> None:
        self._db.close()

    # -- data -----------------------------------------------------------
    def execute(self, sql: str, params: Iterable = ()) -> Any:
        return self._db.execute(sql, params)

    def query(self, sql: str, params: Iterable = ()) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._db.query(sql, params)]

    def query_one(self, sql: str, params: Iterable = ()) -> Optional[Dict[str, Any]]:
        row = self._db.query_one(sql, params)
        return dict(row) if row is not None else None

    def tx(self):
        return self._db.tx()

    # -- diagnostics ----------------------------------------------------
    def trace_begins(self):
        return self._db.trace_begins()

    @property
    def counters(self) -> Dict[str, int]:
        return dict(self._db.counters)

    # -- extra surface preserved for compatibility ----------------------
    def _tracked_count(self) -> int:
        """Number of live connections currently tracked. Diagnostic."""
        return self._db._tracked_count()

    def _conn(self):
        """Escape hatch: return the raw per-thread sqlite3 connection."""
        return self._db._conn()

    @property
    def placeholders(self) -> str:
        return "?"
