"""
Rule test framework.

Reads test files from detection/tests/*.yaml, instantiates each rule
under test with a fresh matcher, feeds it the configured events, and
verifies the rule fires (or does not fire) on the last event as
specified by the test.

The framework does not import KAVACH360.py; it uses the loader from
detection.loader directly. Tests are read-only and cannot cause side
effects outside the test process.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _YAML_OK = True
except Exception:
    yaml = None  # type: ignore
    _YAML_OK = False

from detection.loader import YamlRuleLoader, YamlRuleError


class RuleTestError(ValueError):
    pass


def _load_tests(tests_dir: str) -> List[dict]:
    if not _YAML_OK:
        raise RuleTestError("pyyaml is not installed")
    if not os.path.isdir(tests_dir):
        return []
    out: List[dict] = []
    for name in sorted(os.listdir(tests_dir)):
        if not (name.endswith(".yaml") or name.endswith(".yml")):
            continue
        path = os.path.join(tests_dir, name)
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            raise RuleTestError(f"{path}: top-level must be a mapping")
        doc["__file__"] = path
        out.append(doc)
    return out


def run_rule_tests(rules_dir: str, tests_dir: str) -> Dict[str, Any]:
    """
    Run every test in tests_dir. Returns a summary dict:
      {total, passed, failed, failures: [{name, rule_id, reason}]}
    """
    loader = YamlRuleLoader(rules_dir)
    rules = {r.rule_id: r for r in loader.load()}
    tests = _load_tests(tests_dir)
    total = 0
    passed = 0
    failures = []
    for t in tests:
        rule_id = t.get("rule_id")
        if not isinstance(rule_id, str):
            failures.append({"name": "?", "rule_id": None,
                             "reason": "test file missing rule_id"})
            continue
        rule = rules.get(rule_id)
        if rule is None:
            failures.append({"name": t.get("__file__", "?"), "rule_id": rule_id,
                             "reason": "rule id not found in rules dir"})
            continue
        cases = t.get("cases", [])
        if not isinstance(cases, list):
            failures.append({"name": t.get("__file__", "?"), "rule_id": rule_id,
                             "reason": "cases must be a list"})
            continue
        for case in cases:
            total += 1
            name = case.get("name", "?")
            events = case.get("events", [])
            expect = bool(case.get("expect_fire_on_last", False))
            if not isinstance(events, list) or not events:
                failures.append({"name": name, "rule_id": rule_id,
                                 "reason": "no events"})
                continue
            # Fresh matcher per case so state does not leak across cases.
            fresh = YamlRuleLoader(rules_dir).load()
            fresh_rule = next((x for x in fresh if x.rule_id == rule_id), None)
            if fresh_rule is None:
                failures.append({"name": name, "rule_id": rule_id,
                                 "reason": "could not re-load rule"})
                continue
            fired_on_last = False
            for i, ev in enumerate(events):
                fired = bool(fresh_rule.matcher(ev))
                if i == len(events) - 1:
                    fired_on_last = fired
            if fired_on_last == expect:
                passed += 1
            else:
                failures.append({
                    "name": name, "rule_id": rule_id,
                    "reason": f"expected fire={expect} got fire={fired_on_last}",
                })
    return {
        "total": total,
        "passed": passed,
        "failed": len(failures),
        "failures": failures,
    }
