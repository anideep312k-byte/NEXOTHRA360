"""Triage orchestrator: LLM + MITRE + deterministic fallback."""
from __future__ import annotations
import json
import logging
from typing import Any

from ..detection.mitre import map_alert
from .base import LLMProvider, LLMResponse
from .prompts.triage import build_triage_context

log = logging.getLogger("kavach360.ai.triage")


class TriageOrchestrator:
    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def triage(self, alert: dict[str, Any]) -> dict[str, Any]:
        mitre = map_alert(alert)
        context = build_triage_context(alert)
        response: LLMResponse = self.provider.summarize(
            context, "Produce a triage summary for this alert.")
        parsed: dict[str, Any] | None = None
        if response.text and not response.text.startswith(
                ("input_rejected", "output_rejected", "ollama_")):
            try:
                parsed = json.loads(response.text)
            except Exception:
                parsed = None
        if parsed is None:
            parsed = self._fallback(alert, mitre)
        else:
            parsed["mitre_techniques"] = [t["technique_id"]
                                          for t in mitre["techniques"]]
            parsed["ai_confidence"] = response.confidence
        parsed["provider"] = getattr(self.provider, "name", "unknown")
        return parsed

    @staticmethod
    def _fallback(alert: dict[str, Any], mitre: dict[str, Any]) -> dict[str, Any]:
        sev = str(alert.get("severity") or "low").lower()
        return {
            "verdict": alert.get("verdict") or "UNKNOWN",
            "confidence": 0.4,
            "summary": "AI unavailable; deterministic triage only.",
            "next_steps": ["Validate IOC reputation",
                           "Review related alerts",
                           "Check auth/process/network evidence"],
            "mitre_techniques": [t["technique_id"]
                                 for t in mitre["techniques"]],
            "escalation": "L2_review" if sev in {"high", "critical"} else "monitor",
            "ai_confidence": 0.0,
        }
