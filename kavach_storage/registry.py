"""Backend registry."""
from __future__ import annotations
from typing import Callable, Dict

def _make_sqlite(db_cls, path: str, **kwargs):
    from kavach_storage.sqlite_backend import SQLiteStorage
    return SQLiteStorage(db_cls, path)

def _make_postgres(dsn: str, **kwargs):
    from kavach_storage.postgres_backend import PostgresStorage
    return PostgresStorage(dsn, **kwargs)

_BACKENDS: Dict[str, Callable] = {"sqlite": _make_sqlite, "postgres": _make_postgres}

def list_backends():
    return sorted(_BACKENDS.keys())

def get_backend(name: str, **kwargs):
    key = (name or "").strip().lower()
    if key not in _BACKENDS:
        raise ValueError(f"unknown storage backend: {name!r}. known: {sorted(_BACKENDS.keys())}")
    return _BACKENDS[key](**kwargs)
