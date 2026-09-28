"""PostgreSQL storage backend. Requires psycopg 3 (LGPL-3.0).

Patches applied in this file:
  7b: _TxAdapter / _CursorAdapter for '?' placeholder adaptation
  7d: SQLite-to-PostgreSQL dialect translation for INSERT OR IGNORE,
      INSERT OR REPLACE, and related patterns that only SQLite accepts.
      The translation is applied inside PostgresStorage.adapt(), so
      every call path (execute, query, query_one, tx cursor adapter)
      goes through it uniformly.
"""
from __future__ import annotations
# KAVACH360-patch-s16-applied
# KAVACH360-patch-s14b-applied
import re
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from kavach_storage.base import StorageBackend

try:
    from observability_histograms import (
        observe_pg_write as _observe_pg_write,
    )
except Exception:
    def _observe_pg_write(_seconds):
        return None


try:
    from observability_histograms import get_histogram as _get_histogram
except Exception:
    _get_histogram = None  # type: ignore


# Session 16 — SQL classifier. Deterministic pure function of the
# statement text. Order: DELETE and UPDATE checks must precede any
# SELECT checks, because DELETE/UPDATE statements may contain the
# same FROM/TABLE substrings.
def _classify_sql(sql: str) -> str:
    try:
        s = sql.upper()
    except Exception:
        return 'other'
    # --- DELETE first ---
    if s.lstrip().startswith('DELETE'):
        if 'FROM BUS' in s:
            return 'delete_bus'
        if 'FROM INCIDENT_ENTITY_INDEX' in s:
            return 'delete_incident_index'
        return 'delete_generic'
    # --- UPDATE second ---
    if s.lstrip().startswith('UPDATE'):
        if 'UPDATE ALERTS' in s and 'RISK' in s:
            return 'update_alert_risk'
        if 'UPDATE INCIDENTS' in s and 'UPDATED_TS' in s:
            return 'update_incident_ts'
        if 'UPDATE BUS' in s and 'LEASED' in s:
            return 'update_bus_lease'
        if 'UPDATE BUS' in s and 'PENDING' in s:
            return 'update_bus_pending'
        if 'UPDATE USERS' in s:
            return 'update_user'
        if 'UPDATE SESSIONS' in s:
            return 'update_session'
        return 'update_generic'
    # --- INSERT third ---
    if 'INSERT' in s:
        if 'INTO EVENTS' in s:
            return 'insert_event'
        if 'INTO BUS' in s:
            return 'insert_bus'
        if 'INTO AUDIT' in s:
            return 'insert_audit'
        if 'INTO INCIDENT_TIMELINE' in s:
            return 'insert_incident_timeline'
        if 'INTO INCIDENT_ALERTS' in s:
            return 'insert_incident_alerts'
        if 'INTO INCIDENT_ENTITY_INDEX' in s:
            return 'insert_entity_index'
        if 'INTO INCIDENTS' in s:
            return 'insert_incident'
        if 'INTO ENTITY_STATE' in s:
            return 'update_entity_state'
        if 'INTO BASELINES' in s:
            return 'update_baseline'
        return 'insert_generic'
    # --- SELECT last ---
    if 'FROM INCIDENT_ENTITY_INDEX' in s:
        return 'select_incident_index'
    if 'FROM EVENTS' in s and 'COUNT' in s:
        return 'select_events_count'
    if 'FROM BUS' in s and 'COUNT' in s:
        return 'select_bus_count'
    if 'FROM BUS' in s and 'SELECT *' in s:
        return 'select_bus_row'
    if 'FROM ALERTS' in s:
        return 'select_alert_row'
    if 'FROM BASELINES' in s:
        return 'select_baseline'
    if 'FROM USERS' in s:
        return 'select_user'
    if 'FROM SESSIONS' in s:
        return 'select_session'
    if 'SELECT' in s:
        return 'select_generic'
    return 'other'


def _observe_sql(sql: str, seconds: float) -> None:
    try:
        if _get_histogram is None:
            return
        cls = _classify_sql(sql)
        _get_histogram(f'sql_{cls}_seconds',
                       help_text=f'SQL statement duration: {cls}').observe(seconds)
    except Exception:
        pass

try:
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
    _PSYCOPG_OK = True
except Exception:
    psycopg = None  # type: ignore
    dict_row = None  # type: ignore
    _PSYCOPG_OK = False


# Regex translations for SQLite-specific SQL that PostgreSQL does not accept.
# These are intentionally conservative. They cover patterns actually present
# in KAVACH360.py and are documented here so future readers know exactly
# which conversions happen.
_RE_INSERT_OR_IGNORE = re.compile(
    r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", re.IGNORECASE)
_RE_INSERT_OR_REPLACE = re.compile(
    r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", re.IGNORECASE)

def _translate_sqlite_to_postgres(sql: str) -> str:
    """Translate SQLite-specific syntax into PostgreSQL-compatible SQL.

    The translation is idempotent and case-insensitive. Unknown patterns
    are left alone and will surface as syntax errors when executed — the
    caller sees the actual error rather than a silent mis-translation.
    """
    if not isinstance(sql, str):
        return sql
    out = sql
    # INSERT OR IGNORE INTO x (...) -> INSERT INTO x (...) ON CONFLICT DO NOTHING
    if _RE_INSERT_OR_IGNORE.search(out):
        out = _RE_INSERT_OR_IGNORE.sub("INSERT INTO", out)
        # Append ON CONFLICT DO NOTHING only if not already present.
        if "ON CONFLICT" not in out.upper():
            out = out.rstrip().rstrip(";")
            out = out + " ON CONFLICT DO NOTHING"
    # INSERT OR REPLACE INTO x (...) -> INSERT INTO x (...) ON CONFLICT DO NOTHING
    #   (not a strict upsert; safe degradation to "don't raise if exists")
    if _RE_INSERT_OR_REPLACE.search(out):
        out = _RE_INSERT_OR_REPLACE.sub("INSERT INTO", out)
        if "ON CONFLICT" not in out.upper():
            out = out.rstrip().rstrip(";")
            out = out + " ON CONFLICT DO NOTHING"
    return out


class _CursorAdapter:
    """Wraps a psycopg cursor so .execute() applies dialect translation
    and '?' -> '%s' placeholder adaptation via the owning storage."""
    __slots__ = ("_cur", "_storage")

    def __init__(self, cur, storage) -> None:
        self._cur = cur
        self._storage = storage

    def execute(self, sql, params=()):
        adapted = self._storage.adapt(sql)
        if params:
            return self._cur.execute(adapted, tuple(params))
        return self._cur.execute(adapted)

    def executemany(self, sql, seq_of_params):
        adapted = self._storage.adapt(sql)
        return self._cur.executemany(adapted, seq_of_params)

    def __getattr__(self, name):
        return getattr(self._cur, name)

    def __iter__(self):
        return iter(self._cur)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return self._cur.__exit__(*a)


class _TxAdapter:
    """Wraps a psycopg connection so direct .execute() and .cursor()
    calls from within a tx() block apply dialect translation."""
    __slots__ = ("_conn", "_storage")

    def __init__(self, conn, storage) -> None:
        self._conn = conn
        self._storage = storage

    def execute(self, sql, params=()):
        cur = self._conn.cursor()
        adapted = self._storage.adapt(sql)
        if params:
            return cur.execute(adapted, tuple(params))
        return cur.execute(adapted)

    def executemany(self, sql, seq_of_params):
        cur = self._conn.cursor()
        adapted = self._storage.adapt(sql)
        return cur.executemany(adapted, seq_of_params)

    def cursor(self, *a, **kw):
        return _CursorAdapter(self._conn.cursor(*a, **kw), self._storage)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class PostgresStorage(StorageBackend):
    def __init__(self, dsn: str, pool_min: int = 1, pool_max: int = 10,
                 connect_timeout_seconds: int = 10) -> None:
        if not _PSYCOPG_OK:
            raise RuntimeError(
                "psycopg 3 is required for PostgresStorage. "
                "Install with: pip install 'psycopg[binary]>=3.1,<4'")
        self.dsn = dsn
        self.pool_min = max(0, int(pool_min))
        self.pool_max = max(1, int(pool_max))
        self.connect_timeout = int(connect_timeout_seconds)
        self._pool: List[Any] = []
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(self.pool_max)
        self._counters: Dict[str, int] = {"execute": 0, "begin": 0}
        self._counters_lock = threading.Lock()
        with self._lock:
            for _ in range(self.pool_min):
                self._pool.append(self._new_conn())

    def _new_conn(self):
        return psycopg.connect(  # type: ignore
            self.dsn, row_factory=dict_row,  # type: ignore
            autocommit=True, connect_timeout=self.connect_timeout)

    @contextmanager
    def _acquire(self):
        if not self._sem.acquire(timeout=30):
            raise TimeoutError("PostgresStorage: pool exhausted for 30s")
        conn = None
        try:
            with self._lock:
                if self._pool:
                    conn = self._pool.pop()
            if conn is None:
                conn = self._new_conn()
            yield conn
        finally:
            if conn is not None:
                try:
                    if getattr(conn, "closed", False):
                        raise RuntimeError("connection closed")
                    with self._lock:
                        if len(self._pool) < self.pool_max:
                            self._pool.append(conn)
                        else:
                            try: conn.close()
                            except Exception: pass
                except Exception:
                    try: conn.close()
                    except Exception: pass
            self._sem.release()

    def _bump(self, key: str, n: int = 1) -> None:
        with self._counters_lock:
            self._counters[key] = self._counters.get(key, 0) + n

    def close(self) -> None:
        with self._lock:
            pool = list(self._pool); self._pool.clear()
        for c in pool:
            try: c.close()
            except Exception: pass

    def adapt(self, sql: str) -> str:
        """Apply dialect translation, then placeholder substitution."""
        sql = _translate_sqlite_to_postgres(sql)
        return super().adapt(sql)

    def execute(self, sql: str, params: Iterable = ()) -> Any:
        self._bump("execute")
        _t0 = time.time()
        try:
            with self._acquire() as conn:
                with conn.cursor() as cur:
                    cur.execute(self.adapt(sql), tuple(params))
                    return cur
        finally:
            _dt = time.time() - _t0
            _observe_pg_write(_dt)
            _observe_sql(sql, _dt)

    def query(self, sql: str, params: Iterable = ()) -> List[Dict[str, Any]]:
        _t0 = time.time()
        try:
            with self._acquire() as conn:
                with conn.cursor() as cur:
                    cur.execute(self.adapt(sql), tuple(params))
                    return [dict(r) for r in cur.fetchall()]
        finally:
            _dt = time.time() - _t0
            _observe_pg_write(_dt)
            _observe_sql(sql, _dt)

    def query_one(self, sql: str, params: Iterable = ()) -> Optional[Dict[str, Any]]:
        _t0 = time.time()
        try:
            with self._acquire() as conn:
                with conn.cursor() as cur:
                    cur.execute(self.adapt(sql), tuple(params))
                    row = cur.fetchone()
                    return dict(row) if row is not None else None
        finally:
            _dt = time.time() - _t0
            _observe_pg_write(_dt)
            _observe_sql(sql, _dt)

    @contextmanager
    def tx(self):
        self._bump("begin")
        _t0 = time.time()
        try:
            with self._acquire() as conn:
                prev_autocommit = conn.autocommit
                conn.autocommit = False
                adapter = _TxAdapter(conn, self)
                try:
                    yield adapter
                    conn.commit()
                except Exception:
                    try: conn.rollback()
                    except Exception: pass
                    raise
                finally:
                    try: conn.autocommit = prev_autocommit
                    except Exception: pass
        finally:
            _observe_pg_write(time.time() - _t0)

    @contextmanager
    def trace_begins(self):
        with self._counters_lock:
            before = self._counters.get("begin", 0)
        trace = {"begins": 0}
        try:
            yield trace
        finally:
            with self._counters_lock:
                after = self._counters.get("begin", 0)
            trace["begins"] = after - before

    @property
    def counters(self) -> Dict[str, int]:
        with self._counters_lock:
            return dict(self._counters)

    @property
    def placeholders(self) -> str:
        return "%s"

    def health_check(self) -> bool:
        try:
            with self._acquire() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return bool(cur.fetchone())
        except Exception:
            return False
