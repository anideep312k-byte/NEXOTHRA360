"""Syslog / general log rules."""
from __future__ import annotations
import re
from ...utils.normalize import iterative_unquote, normalize_field
from ..registry import register
from ..rule import Rule

_FIELDS = ("message", "process", "user")


def _n(e):
    return {f: normalize_field(iterative_unquote(
        e.get(f) if isinstance(e.get(f), str) else str(e.get(f) or ""))) for f in _FIELDS}


_RE_SUDO = re.compile(r"sudo\s*:.*command=", re.IGNORECASE)
_RE_SSH_FAIL = re.compile(r"(?:failed\s+password|authentication\s+failure|invalid\s+user)",
                          re.IGNORECASE)
_RE_ROOT_LOGIN = re.compile(r"session\s+opened\s+for\s+user\s+root", re.IGNORECASE)
_RE_KERNEL_OOPS = re.compile(
    r"\b(?:kernel\s+oops|BUG:|general\s+protection\s+fault)\b", re.IGNORECASE)
_RE_AUDIT_TAINT = re.compile(r"audit.*tamper", re.IGNORECASE)


def _any(e, pat):
    n = _n(e)
    return any(pat.search(n[f]) for f in _FIELDS if n[f])


register(Rule(id="KVC-SYSLOG-001", title="Sudo Command Execution", severity="low",
    confidence=0.55, mitre=["T1548.003"], tags=["syslog"],
    description="Sudo command.", match=lambda e: _any(e, _RE_SUDO)))
register(Rule(id="KVC-SYSLOG-002", title="SSH Auth Failure", severity="low",
    confidence=0.50, mitre=["T1110.001"], tags=["syslog"],
    description="Failed SSH auth.", match=lambda e: _any(e, _RE_SSH_FAIL)))
register(Rule(id="KVC-SYSLOG-003", title="Root Session Opened", severity="medium",
    confidence=0.60, mitre=["T1078"], tags=["syslog"],
    description="Root session.", match=lambda e: _any(e, _RE_ROOT_LOGIN)))
register(Rule(id="KVC-SYSLOG-004", title="Kernel Crash Signal", severity="medium",
    confidence=0.70, mitre=["T1499"], tags=["syslog"],
    description="Kernel oops.", match=lambda e: _any(e, _RE_KERNEL_OOPS)))
register(Rule(id="KVC-SYSLOG-005", title="Audit Tampering", severity="high",
    confidence=0.75, mitre=["T1070"], tags=["syslog"],
    description="Audit tampering reference.", match=lambda e: _any(e, _RE_AUDIT_TAINT)))
