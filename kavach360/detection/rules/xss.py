"""XSS detection rules."""
from __future__ import annotations
import re
from ...utils.normalize import iterative_unquote, normalize_field
from ..registry import register
from ..rule import Rule

_FIELDS = ("url", "message", "user", "host")


def _n(e):
    return {f: normalize_field(iterative_unquote(
        e.get(f) if isinstance(e.get(f), str) else str(e.get(f) or ""))) for f in _FIELDS}


_RE_SCRIPT_TAG = re.compile(r"<\s*script\b", re.IGNORECASE)
_RE_JS_URI = re.compile(r"\b(?:javascript|vbscript|data)\s*:", re.IGNORECASE)
_RE_EVENT_HANDLER = re.compile(
    r"\bon(?:error|load|click|mouseover|mouseout|focus|blur|submit|"
    r"change|input|keydown|keyup|keypress|dblclick)\s*=", re.IGNORECASE)
_RE_IFRAME = re.compile(r"<\s*iframe\b", re.IGNORECASE)
_RE_SVG_ONLOAD = re.compile(r"<\s*svg\b[^>]*\bon\w+\s*=", re.IGNORECASE)
_RE_DOC_COOKIE = re.compile(r"document\s*\.\s*cookie\b", re.IGNORECASE)
_RE_EVAL = re.compile(r"\beval\s*\(", re.IGNORECASE)


def _any(e, pat):
    n = _n(e)
    return any(pat.search(n[f]) for f in _FIELDS if n[f])


register(Rule(id="KVC-XSS-001", title="XSS Script Tag", severity="high",
    confidence=0.85, mitre=["T1190"], tags=["web", "xss"],
    description="<script> tag.", match=lambda e: _any(e, _RE_SCRIPT_TAG)))
register(Rule(id="KVC-XSS-002", title="XSS JavaScript URI", severity="high",
    confidence=0.80, mitre=["T1190"], tags=["web", "xss"],
    description="javascript: URI.", match=lambda e: _any(e, _RE_JS_URI)))
register(Rule(id="KVC-XSS-003", title="XSS Event Handler", severity="high",
    confidence=0.80, mitre=["T1190"], tags=["web", "xss"],
    description="Event-handler attribute.", match=lambda e: _any(e, _RE_EVENT_HANDLER)))
register(Rule(id="KVC-XSS-004", title="XSS Iframe", severity="medium",
    confidence=0.60, mitre=["T1190"], tags=["web", "xss"],
    description="<iframe> tag.", match=lambda e: _any(e, _RE_IFRAME)))
register(Rule(id="KVC-XSS-005", title="XSS SVG onload", severity="high",
    confidence=0.78, mitre=["T1190"], tags=["web", "xss"],
    description="SVG with event handler.", match=lambda e: _any(e, _RE_SVG_ONLOAD)))
register(Rule(id="KVC-XSS-006", title="XSS Cookie Access", severity="high",
    confidence=0.70, mitre=["T1190"], tags=["web", "xss"],
    description="document.cookie reference.", match=lambda e: _any(e, _RE_DOC_COOKIE)))
register(Rule(id="KVC-XSS-007", title="XSS eval()", severity="high",
    confidence=0.72, mitre=["T1190"], tags=["web", "xss"],
    description="eval() call.", match=lambda e: _any(e, _RE_EVAL)))
