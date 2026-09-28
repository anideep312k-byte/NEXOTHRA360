"""Attacker path query."""
from __future__ import annotations
import logging
from typing import Any

import networkx as nx
from sqlalchemy.orm import Session

from ..storage.database import AttackerPathEdge, AttackerPathNode

log = logging.getLogger("kavach360.graph.query")


class AttackerPathQuery:
    def __init__(self, db: Session, tenant_id: str) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self._graph: nx.DiGraph | None = None

    def _load(self) -> nx.DiGraph:
        if self._graph is not None:
            return self._graph
        g = nx.DiGraph()
        nodes = (self.db.query(AttackerPathNode)
                 .filter(AttackerPathNode.tenant_id == self.tenant_id)
                 .all())
        for n in nodes:
            g.add_node(n.id, kind=n.kind, value=n.value,
                       risk=n.risk_score,
                       first_seen=n.first_seen.isoformat() if n.first_seen else None,
                       last_seen=n.last_seen.isoformat() if n.last_seen else None)
        edges = (self.db.query(AttackerPathEdge)
                 .filter(AttackerPathEdge.tenant_id == self.tenant_id)
                 .all())
        for e in edges:
            g.add_edge(e.src_id, e.dst_id, relation=e.relation,
                       count=e.observation_count,
                       last_seen=e.last_seen.isoformat() if e.last_seen else None)
        self._graph = g
        return g

    def node_by_value(self, kind: str, value: str) -> str | None:
        g = self._load()
        for nid, data in g.nodes(data=True):
            if data.get("kind") == kind and data.get("value") == value:
                return nid
        return None

    def shortest_path(self, src_kind: str, src_val: str,
                      dst_kind: str, dst_val: str) -> list[dict[str, Any]]:
        g = self._load()
        s = self.node_by_value(src_kind, src_val)
        d = self.node_by_value(dst_kind, dst_val)
        if not s or not d:
            return []
        try:
            path = nx.shortest_path(g, source=s, target=d)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        return [{"node_id": nid, **g.nodes[nid]} for nid in path]

    def blast_radius(self, kind: str, value: str, max_depth: int = 3) -> dict[str, Any]:
        g = self._load()
        nid = self.node_by_value(kind, value)
        if not nid:
            return {"root": None, "reached": []}
        try:
            lengths = nx.single_source_shortest_path_length(g, nid, cutoff=max_depth)
        except nx.NodeNotFound:
            return {"root": None, "reached": []}
        reached = []
        for other, dist in lengths.items():
            if other == nid:
                continue
            data = g.nodes[other]
            reached.append({"node_id": other, "distance": dist, **data})
        reached.sort(key=lambda x: (x["distance"], -x.get("risk", 0)))
        return {"root": {"node_id": nid, **g.nodes[nid]}, "reached": reached}

    def high_risk_communities(self, max_communities: int = 5) -> list[dict[str, Any]]:
        g = self._load()
        if g.number_of_nodes() == 0:
            return []
        undirected = g.to_undirected()
        try:
            communities = nx.community.greedy_modularity_communities(undirected)
        except Exception as exc:
            log.warning("Community detection failed: %s", exc)
            return []
        results = []
        for comm in list(communities)[:max_communities]:
            nodes = []
            total_risk = 0
            for nid in comm:
                data = g.nodes[nid]
                nodes.append({"node_id": nid, **data})
                total_risk += data.get("risk", 0) or 0
            results.append({
                "size": len(nodes),
                "total_risk": total_risk,
                "avg_risk": round(total_risk / max(1, len(nodes)), 2),
                "nodes": sorted(nodes, key=lambda x: -x.get("risk", 0))[:20],
            })
        results.sort(key=lambda x: -x["total_risk"])
        return results

    def stats(self) -> dict[str, Any]:
        g = self._load()
        return {
            "nodes": g.number_of_nodes(),
            "edges": g.number_of_edges(),
            "density": round(nx.density(g), 6) if g.number_of_nodes() > 1 else 0.0,
            "is_dag": nx.is_directed_acyclic_graph(g) if g.number_of_nodes() else True,
        }
