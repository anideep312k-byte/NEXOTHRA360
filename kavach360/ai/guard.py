"""Prompt injection and output guard."""
from __future__ import annotations
import base64
import re

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all|previous|prior) instructions", re.I),
    re.compile(r"disregard (all|previous|prior)", re.I),
    re.compile(r"you are now", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|im_start\|>", re.I),
    re.compile(r"###\s*instruction", re.I),
    re.compile(r"reveal (your|the) (system|hidden) prompt", re.I),
]
_MAX_INPUT_CHARS = 8000
_B64_LIKE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


class PromptRejected(ValueError):
    pass


def guard_input(text: str) -> str:
    if not isinstance(text, str):
        raise PromptRejected("input must be string")
    if len(text) > _MAX_INPUT_CHARS:
        raise PromptRejected("input too large")
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            raise PromptRejected("possible prompt injection")
    return text


def guard_output(text: str) -> str:
    if not isinstance(text, str):
        raise PromptRejected("output must be string")
    if re.search(r"```(bash|sh|powershell|python|cmd)", text, re.I):
        raise PromptRejected("code block in output rejected")
    for m in _B64_LIKE.finditer(text):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        if len(decoded) >= 20 and any(b < 9 or (13 < b < 32) for b in decoded):
            raise PromptRejected("base64-encoded binary in output rejected")
    return text
