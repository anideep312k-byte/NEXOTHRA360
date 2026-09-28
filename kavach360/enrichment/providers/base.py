from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class EnrichmentResult:
    provider: str
    kind: str
    value: str
    data: dict[str, Any] = field(default_factory=dict)
    cached: bool = False
    error: str | None = None


class EnrichmentProvider(ABC):
    name: str = "base"
    @abstractmethod
    def enrich(self, value: str, kind: str) -> EnrichmentResult | None: ...
