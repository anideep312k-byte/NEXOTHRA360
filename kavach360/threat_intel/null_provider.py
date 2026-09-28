from __future__ import annotations
from .base import TIProvider, TIResult


class NullProvider(TIProvider):
    name = "null"
    def lookup(self, ioc: str, kind: str) -> TIResult | None:
        return None
