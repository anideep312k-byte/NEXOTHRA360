"""Built-in detection rules."""
from __future__ import annotations
import re
from ...utils.normalize import iterative_unquote, normalize_field
from ..registry import register
from ..rule import Rule

_RE_CMD = re.compile(r"\b(powershell|pwsh|cmd\.exe|wscript|cscript)\b", re.IGNORECASE)
_RE_ENC_CMD = re.compile(r"(-enc|-encodedcommand)\b", re.IGNORECASE)
_RE_LOLBIN = re.compile(r"\b(certutil|bitsadmin|mshta|regsvr32|rundll32)\b", re.IGNORECASE)
_RE_WEB = re.compile(
    r"(<script\b|union[\s/*]+select\b|javascript\s*:|"
    r"on(?:error|load|click|mouseover|focus|submit)\s*=)", re.IGNORECASE)
_RE_TRAVERSAL = re.compile(
    r"(?:^|[/\\?#&])\.\.(?:[/\\]|$|\?|#|&)"
    r"|%2e%2e(?:%2f|%5c)"
    r"|\.\.%2f|%2e%2e/", re.IGNORECASE)
_RE_CRED = re.compile(r"(mimikatz|credential.?dump|sekurlsa)", re.IGNORECASE)

_FIELDS = ("process", "url", "message", "domain", "user", "host")


def _norm(s):
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    return normalize_field(iterative_unquote(s))


def _norm_event(e):
    return {f: _norm(e.get(f)) for f in _FIELDS}


register(Rule(id="KVC-ENDPOINT-001", title="Suspicious Command Interpreter Activity",
    severity="medium", confidence=0.78, mitre=["T1059"], tags=["endpoint", "execution"],
    description="Command/scripting interpreter invocation.",
    match=lambda e: bool(_RE_CMD.search(_norm_event(e)["process"]))))

register(Rule(id="KVC-ENDPOINT-002", title="Encoded PowerShell Command",
    severity="high", confidence=0.85, mitre=["T1059.001"], tags=["endpoint", "obfuscation"],
    description="PowerShell with -enc/-EncodedCommand.",
    match=lambda e: ("powershell" in _norm_event(e)["process"]
                     and bool(_RE_ENC_CMD.search(_norm_event(e)["process"])))))

register(Rule(id="KVC-ENDPOINT-003", title="LOLBin Execution",
    severity="medium", confidence=0.72, mitre=["T1218"], tags=["endpoint", "defense_evasion"],
    description="Living-off-the-land binary invoked.",
    match=lambda e: bool(_RE_LOLBIN.search(_norm_event(e)["process"]))))

register(Rule(id="KVC-WEB-001", title="Exploitation Indicator in Web Request",
    severity="high", confidence=0.88, mitre=["T1190"], tags=["web", "initial_access"],
    description="Web exploit pattern.",
    match=lambda e: bool(_RE_WEB.search(_norm_event(e)["url"]))))

register(Rule(id="KVC-WEB-002", title="Path Traversal Attempt",
    severity="high", confidence=0.90, mitre=["T1190"], tags=["web", "initial_access"],
    description="Path traversal sequence.",
    match=lambda e: bool(_RE_TRAVERSAL.search(_norm_event(e)["url"]))))

register(Rule(id="KVC-CRED-001", title="Credential Dumping Activity",
    severity="critical", confidence=0.95, mitre=["T1003"], tags=["endpoint", "credential_access"],
    description="Credential harvesting signatures.",
    match=lambda e: bool(_RE_CRED.search(_norm_event(e)["message"]))))

register(Rule(id="KVC-AUTH-001", title="Authentication Failure",
    severity="low", confidence=0.40, mitre=["T1110"], tags=["auth"],
    description="Failed authentication event.",
    match=lambda e: _norm_event(e)["action"] in
        {"login_failed", "authentication_failure", "failed_login"}))

register(Rule(id="KVC-AUTH-002", title="Successful Login After Multiple Failures",
    severity="high", confidence=0.80, mitre=["T1078", "T1110"], tags=["auth"],
    description="Successful login after failure burst.",
    match=lambda e: (_norm_event(e)["action"] in {"login_success", "authentication_success"}
                     and int(e.get("prior_failures") or 0) >= 5)))

register(Rule(id="KVC-NET-001", title="Beaconing Pattern (heuristic)",
    severity="medium", confidence=0.55, mitre=["T1071"], tags=["network", "c2"],
    description="Heuristic beaconing signal.",
    match=lambda e: float(e.get("beacon_score", 0) or 0) >= 0.7))

register(Rule(id="KVC-CLOUD-001", title="Root Account Usage",
    severity="high", confidence=0.85, mitre=["T1078.004"], tags=["cloud", "persistence"],
    description="Cloud root account activity.",
    match=lambda e: (_norm_event(e)["user"] in {"root", "administrator"}
                     and _norm_event(e)["source_type"] == "cloud")))
