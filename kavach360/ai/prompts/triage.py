"""Prompt context builder for triage."""
from __future__ import annotations
import json
from typing import Any


def build_triage_context(alert: dict[str, Any], max_indicators: int = 10) -> str:
    safe = {
        "alert_id": str(alert.get("alert_id") or alert.get("event_id") or "")[:64],
        "severity": str(alert.get("severity") or "")[:16],
        "risk_score": alert.get("risk_score") or 0,
        "verdict": str(alert.get("verdict") or "")[:64],
        "source_type": str(alert.get("source_type") or "")[:32],
        "indicators": [str(i)[:256] for i in
                       (alert.get("indicators") or [])[:max_indicators]],
        "source_ips": [str(i)[:64] for i in (alert.get("source_ips") or [])[:10]],
        "message": str(alert.get("message") or "")[:500],
    }
    return json.dumps(safe, separators=(",", ":"))
