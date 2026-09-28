from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(slots=True)
class TIResult:
    ioc: str
    kind: str
    malicious: bool
    score: float
    source: str
    tags: list[str]
    raw: dict


class TIProvider(ABC):
    name: str = "base"
    @abstractmethod
    def lookup(self, ioc: str, kind: str) -> TIResult | None: ...
