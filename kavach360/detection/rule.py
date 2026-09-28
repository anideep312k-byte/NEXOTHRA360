from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    confidence: float
    mitre: list[str]
    description: str
    match: Callable[[dict[str, Any]], bool]
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    confidence: float
    mitre: list[str]
    description: str
    event_id: str
    evidence: dict[str, Any]
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "title": self.title,
                "severity": self.severity, "confidence": self.confidence,
                "mitre": self.mitre, "description": self.description,
                "event_id": self.event_id, "evidence": self.evidence,
                "tags": self.tags}
