"""Map alerts to MITRE ATT&CK techniques."""
from __future__ import annotations
from typing import Any
from .tactics import TACTICS
from .techniques import TECHNIQUES

_KEYWORD_MAP = {
    "phishing": "T1566", "brute force": "T1110", "password spray": "T1110",
    "failed login": "T1110.001", "powershell": "T1059.001",
    "cmd.exe": "T1059.003", "bash": "T1059.004", "ransomware": "T1486",
    "c2": "T1071", "command and control": "T1071", "beacon": "T1071",
    "exfiltration": "T1041", "lateral movement": "T1021", "rdp": "T1021.001",
    "smb": "T1021.002", "port scan": "T1046", "privilege": "T1068",
    "persistence": "T1053", "backdoor": "T1543", "rootkit": "T1014",
    "credential": "T1003", "mimikatz": "T1003", "valid account": "T1078",
    "exploit": "T1190", "ddos": "T1498", "data destruction": "T1485",
    "lolbin": "T1218", "certutil": "T1218",
}


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    return str(value)


def map_text(text) -> list[dict[str, str]]:
    if not isinstance(text, str):
        text = _flatten(text)
    lowered = text.lower()
    matched: set[str] = set()
    for tid in TECHNIQUES:
        if tid.lower() in lowered:
            matched.add(tid)
    for kw, tid in _KEYWORD_MAP.items():
        if kw in lowered:
            matched.add(tid)
    expanded: set[str] = set()
    for tid in matched:
        expanded.add(tid)
        if "." in tid:
            expanded.add(tid.split(".", 1)[0])
    out: list[dict[str, str]] = []
    for tid in sorted(expanded):
        tech = TECHNIQUES.get(tid)
        if not tech:
            continue
        tactic_id = tech["tactic"]
        tactic = TACTICS.get(tactic_id, {})
        out.append({
            "technique_id": tid,
            "technique_name": tech["name"],
            "tactic_id": tactic_id,
            "tactic_name": tactic.get("name", ""),
            "is_subtechnique": "." in tid,
        })
    return out


def map_alert(alert: dict[str, Any]) -> dict[str, Any]:
    parts = [alert.get("title"), alert.get("description"), alert.get("message"),
             alert.get("event_type"), alert.get("action"),
             alert.get("indicators"), alert.get("tags")]
    techniques = map_text(_flatten(parts))
    tactics = sorted({t["tactic_id"] for t in techniques})
    by_tactic: dict[str, dict[str, Any]] = {}
    for t in techniques:
        tid = t["tactic_id"]
        by_tactic.setdefault(tid, {"tactic_id": tid,
                                   "tactic_name": t["tactic_name"],
                                   "techniques": []})["techniques"].append(t)
    return {
        "alert_id": alert.get("alert_id") or alert.get("event_id") or "",
        "techniques": techniques,
        "tactics": tactics,
        "by_tactic": list(by_tactic.values()),
        "technique_count": len(techniques),
        "tactic_count": len(tactics),
    }
