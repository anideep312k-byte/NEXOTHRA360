from __future__ import annotations
from typing import Iterable
from .rule import Rule

_REGISTRY: dict[str, Rule] = {}


def register(rule: Rule) -> Rule:
    if rule.id in _REGISTRY:
        raise ValueError(f"Duplicate rule id: {rule.id}")
    _REGISTRY[rule.id] = rule
    return rule


def all_rules() -> Iterable[Rule]:
    return list(_REGISTRY.values())


def get(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id)
