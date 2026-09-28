"""
KAVACH360 detection package.

Contains the YAML rule loader and MITRE ATT&CK reference. The in-file
DetectionEngine remains the runtime matcher; this package supplies
rule data to it.
"""
from detection.loader import YamlRuleLoader, YamlRule, YamlRuleError
from detection.mitre import mitre_lookup, all_mitre_techniques

__all__ = [
    "YamlRuleLoader", "YamlRule", "YamlRuleError",
    "mitre_lookup", "all_mitre_techniques",
]
__version__ = "0.1.0"
