"""SOAR engine with dual-custody."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable
from ..storage.database import PlaybookState


@dataclass(slots=True)
class PlaybookDefinition:
    name: str
    description: str
    parameters_schema: dict[str, type]
    requires_approval: bool
    handler: Callable[[dict[str, Any]], dict[str, Any]]


def _isolate_host(ctx):
    return {"action": "isolate_host", "target": ctx.get("host"), "status": "executed"}


def _block_ip(ctx):
    return {"action": "block_ip", "target": ctx.get("ip"), "status": "executed"}


def _revoke_session(ctx):
    return {"action": "revoke_session", "target": ctx.get("user"), "status": "executed"}


REGISTRY: dict[str, PlaybookDefinition] = {
    "isolate_workstation": PlaybookDefinition(
        "isolate_workstation",
        "Terminate network interfaces except management plane.",
        {"host": str}, True, _isolate_host),
    "block_perimeter_ip": PlaybookDefinition(
        "block_perimeter_ip",
        "Drop perimeter ingress from malicious external address.",
        {"ip": str}, True, _block_ip),
    "kill_user_sessions": PlaybookDefinition(
        "kill_user_sessions",
        "Revoke active user sessions.",
        {"user": str}, True, _revoke_session),
}


class PlaybookEngine:
    @staticmethod
    def available_playbooks() -> list[dict[str, Any]]:
        return [{"name": p.name, "description": p.description,
                 "requires_approval": p.requires_approval,
                 "parameters": list(p.parameters_schema.keys())}
                for p in REGISTRY.values()]

    @staticmethod
    def validate_parameters(name: str, params: dict[str, Any]) -> None:
        if name not in REGISTRY:
            raise KeyError(f"Playbook {name} does not exist")
        definition = REGISTRY[name]
        if not isinstance(params, dict):
            raise TypeError("Parameters must be a JSON object")
        for key, expected in definition.parameters_schema.items():
            if key not in params:
                raise ValueError(f"Missing mandatory parameter: {key}")
            if not isinstance(params[key], expected):
                raise TypeError(f"Parameter {key} must be {expected.__name__}")

    @classmethod
    def dry_run(cls, name: str, params: dict[str, Any]) -> dict[str, Any]:
        cls.validate_parameters(name, params)
        d = REGISTRY[name]
        return {"playbook": name, "mode": "DRY_RUN",
                "required_approval": d.requires_approval,
                "target_parameters": params,
                "projected_actions": [d.description]}

    @classmethod
    def execute(cls, name: str, params: dict[str, Any], requested_by: str,
                approved_by: str) -> dict[str, Any]:
        cls.validate_parameters(name, params)
        if requested_by == approved_by:
            raise PermissionError(
                "Dual-custody violation: requester cannot approve own execution")
        d = REGISTRY[name]
        result = d.handler(params)
        return {"playbook": name, "state": PlaybookState.COMPLETED.value,
                "requested_by": requested_by, "approved_by": approved_by,
                "result": result}
