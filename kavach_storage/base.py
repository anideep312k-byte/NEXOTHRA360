"""
Abstract storage backend interface.

Every concrete backend must implement all abstract methods below.
Anything that is common across backends belongs here as a concrete
method; anything backend-specific belongs in the subclass.

This interface was extracted from the existing in-file Database class
so that the current behavior is preserved while new backends can be
added later. It is deliberately small: five data methods plus three
diagnostic methods.
"""
from __future__ import annotations
import abc
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional


class StorageBackend(abc.ABC):
    """
    Abstract persistence interface.

    Contract:
      * tx() yields a context-managed connection. On normal exit the
        transaction commits. On exception the transaction rolls back
        and the exception propagates.
      * execute() runs a single statement outside an explicit tx().
        Callers that need multi-statement atomicity must use tx().
      * query() returns a list of dict-like rows.
      * query_one() returns a single dict-like row or None.
      * close() releases all connections and any other resources.
      * trace_begins() is a diagnostic context manager: it yields a
        dict whose "begins" key is populated with the number of
        transactions started inside the block.
      * counters is a read-only diagnostic mapping of counter names to
        integer values. Its contents are backend-defined.
    """

    # -- lifecycle ------------------------------------------------------
    @abc.abstractmethod
    def close(self) -> None: ...

    # -- data -----------------------------------------------------------
    @abc.abstractmethod
    def execute(self, sql: str, params: Iterable = ()) -> Any: ...

    @abc.abstractmethod
    def query(self, sql: str, params: Iterable = ()) -> List[Dict[str, Any]]: ...

    @abc.abstractmethod
    def query_one(self, sql: str, params: Iterable = ()) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def tx(self): ...

    # -- diagnostics ----------------------------------------------------
    @abc.abstractmethod
    def trace_begins(self): ...

    @property
    @abc.abstractmethod
    def counters(self) -> Dict[str, int]: ...

    # -- helper: placeholder adaptation --------------------------------
    @property
    def placeholders(self) -> str:
        """
        The DB-API paramstyle this backend uses. '?' for SQLite,
        '%s' for PostgreSQL. Consumers that build SQL dynamically should
        call adapt() rather than hard-coding a style.
        """
        return "?"

    def adapt(self, sql: str) -> str:
        """Rewrite '?' placeholders to this backend's style."""
        if self.placeholders == "?":
            return sql
        return sql.replace("?", self.placeholders)
