from __future__ import annotations
from typing import Any
from .registry import all_rules
from .rule import Detection

_EVIDENCE_FIELDS = ("src_ip", "dst_ip", "user", "host", "process", "url",
                    "domain", "file_hash", "action", "source_type")
_SOURCE_TAGS = {"endpoint", "web", "network", "cloud", "auth", "syslog"}


class RuleEngine:
    def __init__(self) -> None:
        self._by_source: dict[str, list] = {}
        self._generic: list = []
        for rule in all_rules():
            source_tags = [t for t in (rule.tags or []) if t in _SOURCE_TAGS]
            if source_tags:
                for st in source_tags:
                    self._by_source.setdefault(st, []).append(rule)
            else:
                self._generic.append(rule)

    def evaluate(self, event: dict[str, Any]) -> list[Detection]:
        source_type = str(event.get("source_type") or "").lower()
        candidates = list(self._generic)
        candidates.extend(self._by_source.get(source_type, []))
        detections: list[Detection] = []
        for rule in candidates:
            try:
                if rule.match(event):
                    detections.append(Detection(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        confidence=rule.confidence, mitre=rule.mitre,
                        description=rule.description,
                        event_id=event.get("event_id", ""),
                        evidence=self._evidence(event), tags=rule.tags))
            except Exception:
                continue
        return detections

    @staticmethod
    def _evidence(event: dict[str, Any]) -> dict[str, Any]:
        ev = {k: event.get(k) for k in _EVIDENCE_FIELDS if event.get(k) is not None}
        msg = event.get("message")
        if isinstance(msg, str) and msg:
            ev["message"] = msg[:512]
        return ev
