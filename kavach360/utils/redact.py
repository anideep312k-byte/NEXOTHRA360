"""Payload redaction for DLQ storage."""
from __future__ import annotations
import hashlib
import re

_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|pwd|secret|token|apikey|api_key|authorization|"
    r"bearer|session|cookie|private_key|client_secret)",
    re.IGNORECASE)
_JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_EMAIL_LIKE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_CREDIT_CARD_LIKE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PREVIEW_LIMIT = 512


def _redact_string(s: str) -> str:
    s = _JWT_LIKE.sub("[REDACTED_JWT]", s)
    s = _EMAIL_LIKE.sub("[REDACTED_EMAIL]", s)
    s = _CREDIT_CARD_LIKE.sub("[REDACTED_PAN]", s)
    return s


def redact_payload(obj, _depth: int = 0) -> object:
    if _depth > 20:
        return "[DEPTH_LIMIT]"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.search(k):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_payload(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_payload(v, _depth + 1) for v in obj[:100]]
    if isinstance(obj, str):
        return _redact_string(obj)[:_PREVIEW_LIMIT]
    return obj


def payload_fingerprint(raw: str) -> tuple[int, str]:
    if not isinstance(raw, str):
        raw = str(raw)
    return len(raw), hashlib.sha256(raw.encode("utf-8")).hexdigest()
