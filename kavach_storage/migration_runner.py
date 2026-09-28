"""Schema migration runner for PostgreSQL."""
from __future__ import annotations
import os
import re
from typing import List

from kavach_storage.base import StorageBackend

MIGRATION_NAME_RE = re.compile(r"^(\d{4})_.+\.sql$")

def _split_statements(sql: str) -> List[str]:
    lines = []
    for raw in sql.splitlines():
        if raw.strip().startswith("--"):
            continue
        lines.append(raw)
    out = []
    for chunk in "\n".join(lines).split(";"):
        s = chunk.strip()
        if s:
            out.append(s)
    return out

class MigrationRunner:
    def __init__(self, backend: StorageBackend, migrations_dir: str) -> None:
        self.backend = backend
        self.dir = migrations_dir

    def _discover(self) -> List[str]:
        names = [f for f in os.listdir(self.dir) if MIGRATION_NAME_RE.match(f)]
        names.sort()
        return names

    def _applied(self) -> set:
        try:
            row = self.backend.query_one(
                "SELECT v FROM schema_meta WHERE k='pg_version'")
            if not row:
                return set()
            return set(int(x) for x in str(row["v"]).split(",") if x.strip())
        except Exception:
            return set()

    def _record(self, versions: set) -> None:
        v = ",".join(str(x) for x in sorted(versions))
        with self.backend.tx() as conn:
            cur = conn.cursor()
            cur.execute(
                self.backend.adapt(
                    "INSERT INTO schema_meta(k, v) VALUES ('pg_version', ?) "
                    "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"),
                (v,))

    def migrate(self) -> List[str]:
        applied = self._applied()
        ran: List[str] = []
        for name in self._discover():
            version = int(name.split("_", 1)[0])
            if version in applied:
                continue
            sql = open(os.path.join(self.dir, name), "r", encoding="utf-8").read()
            for stmt in _split_statements(sql):
                self.backend.execute(stmt)
            applied.add(version)
            ran.append(name)
        if ran:
            self._record(applied)
        return ran
