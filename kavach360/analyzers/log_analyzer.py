"""Multi-format log analyzer."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from ..config import config
from ..ingestion.pipeline import SOCPipeline
from ..observability.metrics import LOG_LINES_PARSED

MAX_LINE_BYTES = 64 * 1024

_RE_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$")

_RE_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

_RE_ACCESS = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)")?')

_RE_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')

_PRI_SEVERITY = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                 4: "medium", 5: "medium", 6: "low", 7: "low"}


@dataclass(slots=True)
class ParseResult:
    format: str
    raw_line: str
    event: dict[str, Any]
    error: str | None = None


def _parse_json(line: str) -> ParseResult | None:
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    if "eventName" in obj and "userIdentity" in obj:
        ui = obj.get("userIdentity") or {}
        return ParseResult(format="cloudtrail", raw_line=line,
            event={"timestamp": obj.get("eventTime"),
                   "source_type": "cloud", "source": "aws_cloudtrail",
                   "action": obj.get("eventName", "unknown"),
                   "user": ui.get("userName") or ui.get("principalId") or "unknown",
                   "src_ip": obj.get("sourceIPAddress"),
                   "message": f"{obj.get('eventName')} on {obj.get('eventSource')}",
                   "severity": "medium"})
    ev = dict(obj)
    ev.setdefault("source_type", "jsonl")
    ev.setdefault("source", "jsonl")
    ev.setdefault("action", ev.get("event_type") or ev.get("action") or "unknown")
    ev.setdefault("timestamp", ev.get("timestamp") or ev.get("@timestamp"))
    return ParseResult(format="jsonl", raw_line=line, event=ev)


def _parse_access(line: str) -> ParseResult | None:
    m = _RE_ACCESS.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    sev = "medium" if status >= 500 else "low"
    if status in (401, 403):
        sev = "high"
    return ParseResult(format="access", raw_line=line,
        event={"source_type": "web", "source": "http_access",
               "action": "http_request", "src_ip": m.group("src_ip"),
               "url": m.group("url"),
               "message": f"{m.group('method')} {m.group('url')} -> {status}",
               "severity": sev,
               "outcome": "failure" if status >= 400 else "success",
               "timestamp": m.group("ts")})


def _parse_rfc5424(line: str) -> ParseResult | None:
    m = _RE_RFC5424.match(line)
    if not m:
        return None
    pri = int(m.group("pri"))
    sev = _PRI_SEVERITY.get(pri % 8, "low")
    return ParseResult(format="rfc5424", raw_line=line,
        event={"source_type": "syslog", "source": m.group("app"),
               "action": "syslog", "host": m.group("host"),
               "process": m.group("app"),
               "message": m.group("rest")[:2048],
               "severity": sev, "timestamp": m.group("ts")})


def _parse_rfc3164(line: str) -> ParseResult | None:
    m = _RE_RFC3164.match(line)
    if not m:
        return None
    pri = int(m.group("pri"))
    sev = _PRI_SEVERITY.get(pri % 8, "low")
    return ParseResult(format="rfc3164", raw_line=line,
        event={"source_type": "syslog", "source": m.group("tag").strip(),
               "action": "syslog", "host": m.group("host"),
               "process": m.group("tag").strip(),
               "message": m.group("msg")[:2048],
               "severity": sev, "timestamp": m.group("ts")})


def _parse_kv(line: str) -> ParseResult | None:
    pairs = dict(_RE_KV.findall(line))
    if len(pairs) < 2:
        return None
    cleaned = {k: v.strip('"') for k, v in pairs.items()}
    return ParseResult(format="kv", raw_line=line,
        event={"source_type": "generic", "source": cleaned.get("src") or "kv_log",
               "action": cleaned.get("action") or "log",
               "src_ip": cleaned.get("src_ip") or cleaned.get("srcip"),
               "dst_ip": cleaned.get("dst_ip") or cleaned.get("dstip"),
               "user": cleaned.get("user"), "host": cleaned.get("host"),
               "message": line[:2048],
               "severity": cleaned.get("severity", "low")})


_PARSERS = (_parse_json, _parse_access, _parse_rfc5424, _parse_rfc3164, _parse_kv)


class LogAnalyzer:
    def __init__(self, pipeline: SOCPipeline | None = None) -> None:
        self.pipeline = pipeline or SOCPipeline()

    def parse_line(self, line: str) -> ParseResult:
        if not isinstance(line, str):
            return ParseResult("unknown", "", {}, "non_string")
        if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            return ParseResult("unknown", line[:256], {}, "line_too_large")
        stripped = line.strip()
        if not stripped:
            return ParseResult("empty", "", {}, "empty_line")
        for parser in _PARSERS:
            try:
                res = parser(stripped)
            except Exception:
                continue
            if res is not None:
                return res
        return ParseResult(format="raw", raw_line=stripped,
            event={"source_type": "generic", "source": "log", "action": "log",
                   "message": stripped[:2048], "severity": "low"})

    def analyze_lines(self, lines: Iterable[str], tenant_id: str | None,
                      max_lines: int | None = None) -> dict[str, Any]:
        max_lines = max_lines or config.LOG_ANALYZER_MAX_LINES
        formats: dict[str, int] = {}
        detections: list[dict[str, Any]] = []
        errors = 0
        n = 0
        for line in lines:
            if n >= max_lines:
                break
            n += 1
            res = self.parse_line(line)
            formats[res.format] = formats.get(res.format, 0) + 1
            if res.error:
                errors += 1
                continue
            try:
                results = self.pipeline.process(
                    res.event, tenant_id=tenant_id,
                    source_type=res.event.get("source_type", "generic"))
                for r in results:
                    detections.append({
                        "line_no": n, "format": res.format,
                        "rule_id": r["detection"]["rule_id"],
                        "severity": r["detection"]["severity"],
                        "risk_score": r["risk_score"],
                        "priority": r["priority"],
                        "mitre": r["mitre"],
                        "raw_line": res.raw_line[:512],
                    })
            except Exception:
                errors += 1
            LOG_LINES_PARSED.labels(format=res.format,
                                    source=res.event.get("source", "?")).inc()
        return {"lines_analyzed": n, "formats": formats, "errors": errors,
                "detection_count": len(detections), "detections": detections}
