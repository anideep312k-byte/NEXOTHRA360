"""
YAML detection rule loader (with stateful rule support).

Rules are declared in YAML files under a directory. Each file may
contain one or more rules. The loader parses them, validates them,
and returns objects that the in-file DetectionEngine can register.

Schema (per rule):

    id: STRING                              # unique
    title: STRING
    description: STRING
    severity: info|low|medium|high|critical
    enabled: true|false                     # default true
    version: INTEGER                        # default 1
    tags: [STRING, ...]                     # optional
    mitre:                                  # optional
      techniques: [T1110, ...]
      tactics: [TA0006, ...]

    # Either a stateless match block:
    match:
      kind: STRING
      field: STRING
      equals: STRING
      in: [STRING, ...]
      regex: STRING
      numeric_field: STRING
      numeric_gt: NUMBER

    # Or a stateful match block (Session 5):
    stateful:
      kind: STRING                          # event kind that feeds the window
      window_seconds: NUMBER > 0
      threshold: INTEGER >= 1
      result_field: STRING                  # e.g. "result"
      result_equals: STRING                 # e.g. "fail"
      then_result_equals: STRING            # e.g. "success" (optional)
                                            # if absent, rule fires when
                                            # threshold is reached

Stateful rules are pure functions of the event stream but keep their
own per-rule-instance state. Tenant-scoped state is NOT implemented in
this session; all tenants share the same window counters. This is
documented as a known limitation.

Validation is strict: unknown keys under `match:` or `stateful:` are
rejected, and `kind` is required in either block.
"""
from __future__ import annotations
# KAVACH360-patch-9b-applied
import os
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import yaml  # type: ignore
    _YAML_OK = True
except Exception:
    yaml = None  # type: ignore
    _YAML_OK = False


class YamlRuleError(ValueError):
    """Raised when a YAML rule file is malformed or invalid."""


_ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
_ALLOWED_MATCH_KEYS = {"kind", "field", "equals", "in", "regex",
                       "numeric_field", "numeric_gt"}
_ALLOWED_STATEFUL_KEYS = {"kind", "window_seconds", "threshold",
                          "result_field", "result_equals",
                          "then_result_equals"}


@dataclass
class YamlRule:
    rule_id: str
    title: str
    description: str
    severity: str
    enabled: bool
    version: int
    tags: List[str]
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    matcher: Callable[[Dict[str, Any]], bool] = field(repr=False)
    source: str = "yaml"
    source_file: str = ""
    stateful: bool = False


def _compile_stateless_matcher(spec: dict, rule_id: str) -> Callable[[Dict[str, Any]], bool]:
    """Compile a non-stateful match spec into a callable."""
    unknown = set(spec.keys()) - _ALLOWED_MATCH_KEYS
    if unknown:
        raise YamlRuleError(
            f"rule {rule_id}: unknown match keys {sorted(unknown)}")
    kind = spec.get("kind")
    if not isinstance(kind, str) or not kind:
        raise YamlRuleError(f"rule {rule_id}: match.kind is required")

    field_name = spec.get("field")
    equals_val = spec.get("equals")
    in_vals = spec.get("in")
    regex_str = spec.get("regex")
    numeric_field = spec.get("numeric_field")
    numeric_gt = spec.get("numeric_gt")

    compiled_re = None
    if regex_str is not None:
        try:
            compiled_re = re.compile(str(regex_str))
        except re.error as e:
            raise YamlRuleError(
                f"rule {rule_id}: invalid regex {regex_str!r}: {e}")

    def _get_raw(ev: dict, name: str):
        if name in ev and ev.get(name) not in (None, ""):
            return ev.get(name)
        raw = ev.get("raw") or {}
        if isinstance(raw, dict):
            return raw.get(name)
        return None

    def matcher(ev: dict) -> bool:
        try:
            if ev.get("kind") != kind:
                return False
            if field_name is not None:
                v = ev.get(field_name)
                if equals_val is not None and v != equals_val:
                    return False
                if in_vals is not None:
                    if not isinstance(in_vals, (list, tuple)):
                        return False
                    if v not in in_vals:
                        return False
                if compiled_re is not None:
                    if not isinstance(v, str):
                        return False
                    if compiled_re.search(v) is None:
                        return False
            if numeric_field is not None and numeric_gt is not None:
                raw_v = _get_raw(ev, numeric_field)
                try:
                    nv = int(raw_v)
                except (TypeError, ValueError):
                    try:
                        nv = float(raw_v)
                    except (TypeError, ValueError):
                        return False
                if nv <= float(numeric_gt):
                    return False
            return True
        except Exception:
            return False

    return matcher


class _StatefulMatcher:
    """
    Per-rule-instance stateful matcher.

    Maintains a bounded deque of timestamps for events that satisfy
    (kind, result_field == result_equals) for the same key. When
    threshold events occur within window_seconds, the rule fires.
    If then_result_equals is provided, the rule fires only on an event
    whose result_field equals that value AND the threshold of
    result_equals events was met within the window.

    The key is derived from a per-rule configured field, defaulting to
    'actor'. Only the fields tenant_id and the key field are used to
    partition state. Tenant_id is included so that tenant A's failures
    never contribute to tenant B's window.
    """

    MAX_DEQUE = 10_000  # absolute cap on retained timestamps per key

    def __init__(self, rule_id: str, spec: dict) -> None:
        self.rule_id = rule_id
        self.kind = spec["kind"]
        self.window_seconds = float(spec["window_seconds"])
        self.threshold = int(spec["threshold"])
        self.result_field = spec["result_field"]
        self.result_equals = spec["result_equals"]
        self.then_result_equals = spec.get("then_result_equals")
        self._by_key: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def _partition_key(self, ev: dict) -> str:
        tenant = str(ev.get("tenant_id", ""))
        # Use the actor as the partition dimension. If absent, fall back
        # to src_ip, then host. This keeps the rule meaningful across
        # different event shapes without requiring configuration.
        who = ev.get("actor") or ev.get("src_ip") or ev.get("host") or ""
        return f"{tenant}|{who}"

    def matcher(self, ev: dict) -> bool:
        try:
            if ev.get("kind") != self.kind:
                return False
            now = time.time()
            key = self._partition_key(ev)
            result_val = ev.get(self.result_field)
            fires = False

            with self._lock:
                dq = self._by_key.get(key)
                if dq is None:
                    dq = deque(maxlen=self.MAX_DEQUE)
                    self._by_key[key] = dq

                # Prune entries outside the window.
                cutoff = now - self.window_seconds
                while dq and dq[0] < cutoff:
                    dq.popleft()

                if self.then_result_equals is None:
                    # Threshold mode: count matching events and fire when
                    # the threshold is reached.
                    if result_val == self.result_equals:
                        dq.append(now)
                    fires = len(dq) >= self.threshold
                else:
                    # Followed-by mode: fire when the threshold of
                    # result_equals events has been met AND the current
                    # event's result field equals then_result_equals.
                    if result_val == self.then_result_equals:
                        fires = len(dq) >= self.threshold
                    if result_val == self.result_equals:
                        dq.append(now)

                # Bound the size of the state dict. This is a
                # defensive measure; per-key deques are already
                # bounded by MAX_DEQUE.
                if len(self._by_key) > 10_000:
                    # Drop keys with empty deques first; if still too
                    # many, drop the oldest-inserted keys.
                    empty = [k for k, v in self._by_key.items() if not v]
                    for k in empty:
                        self._by_key.pop(k, None)
                    if len(self._by_key) > 10_000:
                        for k in list(self._by_key)[:1_000]:
                            self._by_key.pop(k, None)

            return bool(fires)
        except Exception:
            return False

    def __call__(self, ev: dict) -> bool:
        """Allow the matcher instance itself to be invoked as
        rule.matcher(ev), matching the stateless rule convention."""
        return self.matcher(ev)

    def reset(self) -> None:
        """Clear all state. Used by tests and reload."""
        with self._lock:
            self._by_key.clear()


def _compile_stateful_matcher(spec: dict, rule_id: str) -> _StatefulMatcher:
    unknown = set(spec.keys()) - _ALLOWED_STATEFUL_KEYS
    if unknown:
        raise YamlRuleError(
            f"rule {rule_id}: unknown stateful keys {sorted(unknown)}")
    kind = spec.get("kind")
    if not isinstance(kind, str) or not kind:
        raise YamlRuleError(f"rule {rule_id}: stateful.kind is required")
    ws = spec.get("window_seconds")
    if not isinstance(ws, (int, float)) or ws <= 0:
        raise YamlRuleError(
            f"rule {rule_id}: stateful.window_seconds must be > 0")
    thr = spec.get("threshold")
    if not isinstance(thr, int) or thr < 1:
        raise YamlRuleError(
            f"rule {rule_id}: stateful.threshold must be int >= 1")
    rf = spec.get("result_field")
    if not isinstance(rf, str) or not rf:
        raise YamlRuleError(
            f"rule {rule_id}: stateful.result_field is required")
    re_ = spec.get("result_equals")
    if not isinstance(re_, str) or not re_:
        raise YamlRuleError(
            f"rule {rule_id}: stateful.result_equals is required")
    tre = spec.get("then_result_equals")
    if tre is not None and (not isinstance(tre, str) or not tre):
        raise YamlRuleError(
            f"rule {rule_id}: stateful.then_result_equals must be non-empty str "
            "or omitted")
    return _StatefulMatcher(rule_id, spec)


def _validate_rule_dict(raw: dict, source_file: str) -> YamlRule:
    if not isinstance(raw, dict):
        raise YamlRuleError(f"{source_file}: each rule must be a mapping")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise YamlRuleError(f"{source_file}: rule has no id")
    rule_id = rule_id.strip()
    title = raw.get("title", "")
    if not isinstance(title, str):
        raise YamlRuleError(f"{source_file}: rule {rule_id}: title must be str")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: description must be str")
    severity = str(raw.get("severity", "")).lower().strip()
    if severity not in _ALLOWED_SEVERITY:
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: severity {severity!r} invalid")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: enabled must be bool")
    version = raw.get("version", 1)
    if not isinstance(version, int) or version < 1:
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: version must be int >= 1")
    tags = raw.get("tags", []) or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: tags must be list of str")
    mitre = raw.get("mitre", {}) or {}
    if not isinstance(mitre, dict):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: mitre must be a mapping")
    mitre_techniques = mitre.get("techniques", []) or []
    if not isinstance(mitre_techniques, list) or \
            not all(isinstance(t, str) for t in mitre_techniques):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: mitre.techniques must be list of str")
    mitre_tactics = mitre.get("tactics", []) or []
    if not isinstance(mitre_tactics, list) or \
            not all(isinstance(t, str) for t in mitre_tactics):
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: mitre.tactics must be list of str")

    match_spec = raw.get("match")
    stateful_spec = raw.get("stateful")
    if match_spec is not None and stateful_spec is not None:
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: cannot have both match and stateful")
    if match_spec is None and stateful_spec is None:
        raise YamlRuleError(
            f"{source_file}: rule {rule_id}: must have match or stateful")

    is_stateful = stateful_spec is not None
    if is_stateful:
        if not isinstance(stateful_spec, dict):
            raise YamlRuleError(
                f"{source_file}: rule {rule_id}: stateful must be a mapping")
        matcher = _compile_stateful_matcher(stateful_spec, rule_id)
    else:
        if not isinstance(match_spec, dict):
            raise YamlRuleError(
                f"{source_file}: rule {rule_id}: match must be a mapping")
        matcher = _compile_stateless_matcher(match_spec, rule_id)

    return YamlRule(
        rule_id=rule_id, title=title, description=description,
        severity=severity, enabled=bool(enabled), version=int(version),
        tags=list(tags),
        mitre_techniques=[t.upper() for t in mitre_techniques],
        mitre_tactics=[t.upper() for t in mitre_tactics],
        matcher=matcher, source="yaml", source_file=source_file,
        stateful=is_stateful,
    )


class YamlRuleLoader:
    """
    Load YAML rule files from a directory.

    Safe hot-reload: reload() parses everything into a fresh list; if
    any file fails, the previous rule set is kept and the error is
    returned to the caller. The engine is never left in a partial state.
    """

    def __init__(self, rules_dir: str) -> None:
        self.rules_dir = rules_dir
        self._lock = threading.Lock()

    def load(self) -> List[YamlRule]:
        """Parse and validate all rules. Raises YamlRuleError on failure."""
        if not _YAML_OK:
            raise YamlRuleError(
                "pyyaml is not installed; cannot load YAML rules. "
                "Install with: pip install 'pyyaml>=6,<7'")
        if not os.path.isdir(self.rules_dir):
            return []
        rules: List[YamlRule] = []
        seen_ids: Dict[str, str] = {}
        for name in sorted(os.listdir(self.rules_dir)):
            if not name.endswith(".yaml") and not name.endswith(".yml"):
                continue
            path = os.path.join(self.rules_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            except Exception as e:
                raise YamlRuleError(f"{path}: YAML parse error: {e}")
            if doc is None:
                continue
            if isinstance(doc, dict):
                doc = [doc]
            if not isinstance(doc, list):
                raise YamlRuleError(
                    f"{path}: top-level must be a mapping or a list of mappings")
            for entry in doc:
                rule = _validate_rule_dict(entry, path)
                if rule.rule_id in seen_ids:
                    raise YamlRuleError(
                        f"{path}: duplicate rule id {rule.rule_id!r} "
                        f"(also in {seen_ids[rule.rule_id]})")
                seen_ids[rule.rule_id] = path
                rules.append(rule)
        return rules

    def register_into(self, engine, engine_lock=None) -> Dict[str, Any]:
        """
        Register all loaded rules into a DetectionEngine instance using
        a copy-on-write pattern so a concurrent match() call cannot see
        a partially-populated rules dict.

        Returns a summary dict.
        """
        parsed = self.load()
        replaced = 0
        added = 0
        lock = engine_lock or getattr(engine, "_register_lock", None) or self._lock
        with lock:
            # Copy-on-write: build a fresh rules dict and swap.
            current = dict(getattr(engine, "_rules", {}) or {})
            for rule in parsed:
                if not rule.enabled:
                    continue
                if rule.rule_id in current:
                    replaced += 1
                else:
                    added += 1
                current[rule.rule_id] = _EngineRule(rule)
            engine._rules = current
        return {
            "loaded": len(parsed),
            "added": added,
            "replaced": replaced,
            "files": sorted({r.source_file for r in parsed}),
        }


class _EngineRule:
    """
    Adapter that exposes a YamlRule with the shape DetectionEngine
    expects (rule_id, title, description, tags, severity, matcher).
    """
    def __init__(self, yaml_rule: YamlRule) -> None:
        self.rule_id = yaml_rule.rule_id
        self.title = yaml_rule.title
        self.description = yaml_rule.description
        self.tags = list(yaml_rule.tags)
        from types import SimpleNamespace
        self.severity = SimpleNamespace(value=yaml_rule.severity)
        self._matcher = yaml_rule.matcher
        self.source = yaml_rule.source
        self.version = yaml_rule.version
        self.mitre_techniques = list(yaml_rule.mitre_techniques)
        self.mitre_tactics = list(yaml_rule.mitre_tactics)
        self.stateful = bool(yaml_rule.stateful)

    def matcher(self, ev: dict) -> bool:
        return self._matcher(ev)
