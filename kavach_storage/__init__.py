"""KAVACH360 storage abstraction layer."""
from kavach_storage.base import StorageBackend
from kavach_storage.sqlite_backend import SQLiteStorage
from kavach_storage.registry import get_backend, list_backends
from kavach_storage.migration_runner import MigrationRunner

try:
    from kavach_storage.postgres_backend import PostgresStorage
    _POSTGRES_AVAILABLE = True
except Exception:
    PostgresStorage = None  # type: ignore
    _POSTGRES_AVAILABLE = False

__all__ = ["StorageBackend", "SQLiteStorage", "PostgresStorage",
           "MigrationRunner", "get_backend", "list_backends"]
__version__ = "0.2.0"
