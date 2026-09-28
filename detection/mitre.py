"""
MITRE ATT&CK technique reference.

This module contains a curated subset of technique IDs used by the
KAVACH360 rule set. Technique names and tactic mappings are drawn from
public MITRE ATT&CK documentation (https://attack.mitre.org), which is
licensed under the MITRE ATT&CK Terms of Use and is free for defensive
use with attribution.

The subset here is intentionally small. Extending it means adding more
entries to _TECHNIQUES; nothing else in the code needs to change.
"""

# technique_id -> {name, tactics: [tactic_ids], tactic_names: [str]}
_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactics": ["TA0006"],
        "tactic_names": ["Credential Access"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "tactic_names": ["Initial Access", "Persistence",
                         "Privilege Escalation", "Defense Evasion"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["TA0002"],
        "tactic_names": ["Execution"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["TA0010"],
        "tactic_names": ["Exfiltration"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ["TA0010"],
        "tactic_names": ["Exfiltration"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ["TA0011"],
        "tactic_names": ["Command and Control"],
    },
    "T1566": {
        "name": "Phishing",
        "tactics": ["TA0001"],
        "tactic_names": ["Initial Access"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ["TA0001"],
        "tactic_names": ["Initial Access"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["TA0004", "TA0005"],
        "tactic_names": ["Privilege Escalation", "Defense Evasion"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["TA0011"],
        "tactic_names": ["Command and Control"],
    },
}


def mitre_lookup(technique_id: str) -> dict:
    """Return the reference entry for a technique ID, or an empty dict."""
    return dict(_TECHNIQUES.get(technique_id.upper(), {}))


def all_mitre_techniques() -> dict:
    """Return a copy of the entire reference table."""
    return {k: dict(v) for k, v in _TECHNIQUES.items()}
