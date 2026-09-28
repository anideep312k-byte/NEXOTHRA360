"""Ingestion pipeline with fail-open dedup."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
import datetime as _dt
import hashlib
import ipaddress
import logging
import time
from typing import Any
import uuid

from ..detection.engine import RuleEngine
from ..detection.rule import Detection
from ..detection import rules as _rules  # noqa: F401
from ..threat_intel import get_ti_provider
from ..web.security.redis_rate_limit import (
    RedisSecurityUnavailableError, security_store)
from ..observability.metrics import REDIS_DEGRADED

log = logging.getLogger("kavach360.ingestion.pipeline")

SEVERITIES = ("low", "medium", "high", "critical")
_MAX_FUTURE = _dt.timedelta(minutes=5)
_MAX_PAST = _dt.timedelta(days=365)


@dataclass(slots=True)
class SecurityEvent:
    timestamp: str
    source_type: str
    source: str
    event_type: str
    action: str
    outcome: str
    severity: str = "low"
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    url: str | None = None
    domain: str | None = None
    file_hash: str | None = None
    message: str = ""
    prior_failures: int = 0
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str | None = None
    raw_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        canonical = (
            f"{self.tenant_id or 'global'}:"
            f"{self.timestamp}:{self.source}:{self.action}:"
            f"{self.src_ip}:{self.user}:{self.process}"
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_ts(raw: str) -> str:
    now = _dt.datetime.now(_dt.timezone.utc)
    try:
        dt = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
    except Exception:
        return now.isoformat()
    if dt > now + _MAX_FUTURE:
        return now.isoformat()
    if dt < now - _MAX_PAST:
        return (now - _MAX_PAST).isoformat()
    return dt.isoformat()


class Normalizer:
    @staticmethod
    def normalize(raw: dict[str, Any], tenant_id: str | None = None,
                  source_type: str = "generic") -> SecurityEvent:
        r = raw or {}
        ts_raw = str(r.get("timestamp") or r.get("@timestamp") or "")
        ts = _parse_ts(ts_raw) if ts_raw else \
             _dt.datetime.now(_dt.timezone.utc).isoformat()

        def _s(k, maxlen=1024):
            v = r.get(k)
            return None if v is None else str(v)[:maxlen]

        sev_raw = (_s("severity") or "low").lower()
        severity = sev_raw if sev_raw in SEVERITIES else "low"
        try:
            prior = int(r.get("prior_failures", 0) or 0)
        except (TypeError, ValueError):
            prior = 0

        return SecurityEvent(
            timestamp=ts, source_type=str(source_type)[:64],
            source=_s("source") or _s("service") or str(source_type)[:64],
            event_type=_s("event_type") or "unknown",
            action=_s("action") or "unknown",
            outcome=_s("outcome") or "unknown",
            severity=severity,
            src_ip=_s("src_ip", 45), dst_ip=_s("dst_ip", 45),
            user=_s("user", 128), host=_s("host", 128),
            process=_s("process", 512),
            url=_s("url", 2048), domain=_s("domain", 255),
            file_hash=_s("file_hash", 64),
            message=str(r.get("message") or "")[:4096],
            prior_failures=max(0, prior),
            tenant_id=tenant_id,
            raw_summary={"keys": sorted(list(r.keys()))[:50]})


class DistributedCorrelation:
    def evaluate_auth_burst(self, event: SecurityEvent) -> tuple[bool, int, list[str]]:
        if event.action.lower() not in {"login_failed", "authentication_failure",
                                         "failed_login"}:
            return False, 0, []
        key = (f"auth_fail:{event.tenant_id or 'global'}:"
               f"{event.user or event.src_ip or 'unknown'}")
        try:
            return security_store.track_correlation(
                key_id=key, event_id=event.event_id, now=time.time(),
                window=300, threshold=5, max_retained=100)
        except RedisSecurityUnavailableError:
            REDIS_DEGRADED.labels(component="correlation").inc()
            return False, 0, []


class SOCPipeline:
    SEVERITY_WEIGHTS = {"low": 20, "medium": 40, "high": 70, "critical": 90}

    def __init__(self) -> None:
        self.engine = RuleEngine()
        self.correlation = DistributedCorrelation()
        self.ti = get_ti_provider()

    def _score(self, severity: str, confidence: float, burst: bool,
               ti_score: float) -> tuple[float, str]:
        base = self.SEVERITY_WEIGHTS.get(severity.lower(), 20)
        val = base * float(confidence)
        if burst:
            val += 15.0
        val += 0.25 * float(ti_score)
        final = max(0.0, min(100.0, round(val, 2)))
        p = "P1" if final >= 85 else "P2" if final >= 65 \
            else "P3" if final >= 40 else "P4"
        return final, p

    def process(self, raw: dict[str, Any], tenant_id: str | None = None,
                source_type: str = "generic") -> list[dict[str, Any]]:
        event = Normalizer.normalize(raw, tenant_id=tenant_id,
                                     source_type=source_type)
        if tenant_id:
            try:
                if not security_store.deduplicate_event(tenant_id,
                                                        event.fingerprint()):
                    return []
            except RedisSecurityUnavailableError:
                log.warning("Dedup unavailable tenant=%s event_id=%s (degraded mode)",
                            tenant_id, event.event_id)
                REDIS_DEGRADED.labels(component="dedup").inc()

        event_dict = event.to_dict()
        detections = self.engine.evaluate(event_dict)

        burst, burst_count, burst_members = self.correlation.evaluate_auth_burst(event)
        if burst:
            detections.append(Detection(
                rule_id="KVC-AUTH-BURST",
                title="Repeated Authentication Failures",
                severity="high", confidence=0.92, mitre=["T1110"],
                description=f"{burst_count} failure events in 5m",
                event_id=event.event_id,
                evidence={"failure_count": burst_count,
                          "correlated_events": burst_members},
                tags=["auth", "brute_force"]))

        iocs: list[dict[str, Any]] = []
        ti_score = 0.0
        if event.src_ip:
            try:
                obj = ipaddress.ip_address(event.src_ip)
                kind = "internal" if obj.is_private else "external"
                iocs.append({"kind": "ip", "value": event.src_ip,
                             "classification": kind})
                if kind == "external":
                    res = self.ti.lookup(event.src_ip, "ip")
                    if res:
                        ti_score = res.score
                        iocs[-1]["ti"] = {"source": res.source,
                                          "malicious": res.malicious,
                                          "score": res.score}
            except ValueError:
                pass

        results = []
        for d in detections:
            risk, prio = self._score(d.severity, d.confidence, burst, ti_score)
            results.append({"event": event_dict, "detection": d.to_dict(),
                            "iocs": iocs, "risk_score": risk, "priority": prio,
                            "mitre": d.mitre})
        return results
