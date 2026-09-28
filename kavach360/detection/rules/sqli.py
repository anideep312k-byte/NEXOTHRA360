"""SQL injection detection rules."""
from __future__ import annotations
import re
from ...utils.normalize import iterative_unquote, normalize_field
from ..registry import register
from ..rule import Rule

_FIELDS = ("url", "message", "process", "user", "host")


def _n(e):
    return {f: normalize_field(iterative_unquote(
        e.get(f) if isinstance(e.get(f), str) else str(e.get(f) or ""))) for f in _FIELDS}


_RE_UNION_SELECT = re.compile(r"\bunion\b[\s/*]+(?:all[\s/*]+)?\bselect\b", re.IGNORECASE)
_RE_STACKED = re.compile(r";\s*(?:drop|delete|insert|update|create|alter|truncate)\b", re.IGNORECASE)
_RE_TIME_BASED = re.compile(r"\b(?:sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\(", re.IGNORECASE)
_RE_FILE_EXFIL = re.compile(r"\b(?:load_file|into\s+outfile|into\s+dumpfile)\b", re.IGNORECASE)
_RE_ERR_BASED = re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.IGNORECASE)
_RE_SYS_PROC = re.compile(r"\b(?:xp_cmdshell|sp_executesql|xp_regread)\b", re.IGNORECASE)
_RE_INFO_SCHEMA = re.compile(r"\binformation_schema\b", re.IGNORECASE)
_RE_BOOLEAN = re.compile(
    r"(?:'\s*or\s*'?\w+'?\s*=\s*'?\w+)|(?:\"\s*or\s*\"?\w+\"?\s*=\s*\"?\w+)",
    re.IGNORECASE)


def _any(e, pat):
    n = _n(e)
    return any(pat.search(n[f]) for f in _FIELDS if n[f])


register(Rule(id="KVC-SQLI-001", title="SQL UNION SELECT", severity="high",
    confidence=0.85, mitre=["T1190"], tags=["web", "sqli"],
    description="UNION SELECT pattern.", match=lambda e: _any(e, _RE_UNION_SELECT)))
register(Rule(id="KVC-SQLI-002", title="SQL Stacked Query", severity="critical",
    confidence=0.90, mitre=["T1190"], tags=["web", "sqli"],
    description="Stacked DDL/DML.", match=lambda e: _any(e, _RE_STACKED)))
register(Rule(id="KVC-SQLI-003", title="SQL Time-Based Injection", severity="high",
    confidence=0.85, mitre=["T1190"], tags=["web", "sqli"],
    description="Time-based blind SQLi.", match=lambda e: _any(e, _RE_TIME_BASED)))
register(Rule(id="KVC-SQLI-004", title="SQL File Read/Write", severity="critical",
    confidence=0.88, mitre=["T1190"], tags=["web", "sqli"],
    description="LOAD_FILE / OUTFILE.", match=lambda e: _any(e, _RE_FILE_EXFIL)))
register(Rule(id="KVC-SQLI-005", title="SQL Error-Based Injection", severity="high",
    confidence=0.80, mitre=["T1190"], tags=["web", "sqli"],
    description="Error-based SQLi.", match=lambda e: _any(e, _RE_ERR_BASED)))
register(Rule(id="KVC-SQLI-006", title="SQL System Procedure", severity="critical",
    confidence=0.90, mitre=["T1190"], tags=["web", "sqli"],
    description="DBMS system procedure.", match=lambda e: _any(e, _RE_SYS_PROC)))
register(Rule(id="KVC-SQLI-007", title="SQL information_schema Access", severity="medium",
    confidence=0.65, mitre=["T1190"], tags=["web", "sqli"],
    description="Schema enumeration.", match=lambda e: _any(e, _RE_INFO_SCHEMA)))
register(Rule(id="KVC-SQLI-008", title="SQL Boolean Injection", severity="high",
    confidence=0.80, mitre=["T1190"], tags=["web", "sqli"],
    description="Boolean-based SQLi.", match=lambda e: _any(e, _RE_BOOLEAN)))
