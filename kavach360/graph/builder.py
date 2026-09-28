"""Attacker path graph builder."""
from __future__ import annotations
import datetime
import hashlib
import logging
import uuid
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import config
from ..observability.metrics import GRAPH_EDGES, GRAPH_NODES
from ..storage.database import AttackerPathEdge, AttackerPathNode

log = logging.getLogger("kavach360.graph.builder")

_NODE_EXTRACTORS = (
    ("src_ip", "ip"), ("dst_ip", "ip"), ("host", "host"),
    ("user", "user"), ("process", "process"), ("domain", "domain"),
    ("file_hash", "file"),
)

_EDGE_RULES = (
    ("user", "src_ip", "authenticated_from"),
    ("process", "host", "executed_on"),
    ("host", "domain", "resolved_to"),
    ("src_ip", "dst_ip", "connected_to"),
    ("user", "file_hash", "accessed"),
)


def _node_id(tenant_id: str, kind: str, value: str) -> str:
    h = hashlib.sha256(f"{tenant_id}|{kind}|{value}".encode()).hexdigest()
    return h[:32]


class AttackerPathBuilder:
    def __init__(self, db: Session, tenant_id: str) -> None:
        self.db = db
        self.tenant_id = tenant_id

    def _upsert_node(self, kind: str, value: str, risk: int = 0,
                     meta: dict | None = None) -> str | None:
        if not value:
            return None
        value = str(value)[:255]
        nid = _node_id(self.tenant_id, kind, value)
        now = datetime.datetime.now(datetime.timezone.utc)
        existing = (self.db.query(AttackerPathNode)
                    .filter(AttackerPathNode.id == nid).first())
        if existing:
            existing.last_seen = now
            if risk > (existing.risk_score or 0):
                existing.risk_score = risk
            return nid
        node = AttackerPathNode(
            id=nid, tenant_id=self.tenant_id, kind=kind, value=value,
            first_seen=now, last_seen=now, risk_score=risk,
            metadata_json=meta or {})
        self.db.add(node)
        return nid

    def _upsert_edge(self, src_id: str, dst_id: str, relation: str,
                     incident_id: str | None = None,
                     evidence_event_id: str | None = None) -> None:
        if not src_id or not dst_id or src_id == dst_id:
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        existing = (self.db.query(AttackerPathEdge)
                    .filter(AttackerPathEdge.tenant_id == self.tenant_id,
                            AttackerPathEdge.src_id == src_id,
                            AttackerPathEdge.dst_id == dst_id,
                            AttackerPathEdge.relation == relation)
                    .first())
        if existing:
            existing.last_seen = now
            existing.observation_count = (existing.observation_count or 0) + 1
            return
        edge = AttackerPathEdge(
            id=str(uuid.uuid4()), tenant_id=self.tenant_id,
            src_id=src_id, dst_id=dst_id, relation=relation,
            first_seen=now, last_seen=now, observation_count=1,
            incident_id=incident_id, evidence_event_id=evidence_event_id)
        self.db.add(edge)

    def ingest(self, event: dict[str, Any], risk: int = 0,
               incident_id: str | None = None) -> None:
        node_count = (self.db.query(func.count(AttackerPathNode.id))
                      .filter(AttackerPathNode.tenant_id == self.tenant_id)
                      .scalar() or 0)
        if node_count >= config.GRAPH_MAX_NODES:
            log.warning("Graph node limit reached for tenant %s (%d)",
                        self.tenant_id, node_count)
            return

        ids: dict[str, str | None] = {}
        for field, kind in _NODE_EXTRACTORS:
            v = event.get(field)
            if v:
                ids[field] = self._upsert_node(kind, str(v), risk=risk)
            else:
                ids[field] = None

        for src_field, dst_field, relation in _EDGE_RULES:
            self._upsert_edge(ids.get(src_field), ids.get(dst_field),
                              relation, incident_id=incident_id,
                              evidence_event_id=event.get("event_id"))

        GRAPH_NODES.set(node_count + 1)
        edge_count = (self.db.query(func.count(AttackerPathEdge.id))
                      .filter(AttackerPathEdge.tenant_id == self.tenant_id)
                      .scalar() or 0)
        GRAPH_EDGES.set(edge_count)

    def commit(self) -> None:
        self.db.commit()
