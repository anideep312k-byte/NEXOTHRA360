"""SOC endpoints."""
from __future__ import annotations
import datetime
import hashlib
import json
import uuid

from flask import Blueprint, g, jsonify, request
from sqlalchemy.orm import Session

from ...broker import stream_names
from ...config import config
from ...detection.registry import all_rules
from ...enrichment.queue import EnrichmentQueue
from ...ingestion.pipeline import SOCPipeline
from ...playbooks.engine import PlaybookEngine
from ...storage.database import (
    EvidenceModel, IncidentModel, IncidentStatus, IngestionDLQ,
    PlaybookExecution, PlaybookState,
)
from ...observability.metrics import DETECTIONS_FIRED, EVENTS_INGESTED
from ...utils.normalize import check_json_depth
from ...utils.redact import payload_fingerprint, redact_payload
from ..security.audit import verify_audit_chain, write_audit
from ..security.csrf import require_browser_security
from ..security.rbac import (
    current_tenant_id, get_current_user, require_auth,
    require_permission, require_role,
)
from ..security.redis_rate_limit import (
    RedisSecurityUnavailableError, rate_limit, security_store)

soc_bp = Blueprint("soc", __name__, url_prefix="/api/v1/soc")
pipeline = SOCPipeline()

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
VALID_KINDS = frozenset({"screenshot", "pcap", "file", "log", "ioc", "note"})

_ORDER = {
    IncidentStatus.NEW.value: 0,
    IncidentStatus.TRIAGE.value: 1,
    IncidentStatus.INVESTIGATING.value: 2,
    IncidentStatus.CONTAINED.value: 3,
    IncidentStatus.RESOLVED.value: 4,
    IncidentStatus.CLOSED.value: 5,
}

VALID_TRANSITIONS = {
    IncidentStatus.NEW.value: {IncidentStatus.TRIAGE.value, IncidentStatus.CLOSED.value},
    IncidentStatus.TRIAGE.value: {IncidentStatus.INVESTIGATING.value, IncidentStatus.CLOSED.value},
    IncidentStatus.INVESTIGATING.value: {IncidentStatus.CONTAINED.value,
                                          IncidentStatus.RESOLVED.value,
                                          IncidentStatus.CLOSED.value},
    IncidentStatus.CONTAINED.value: {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value},
    IncidentStatus.RESOLVED.value: {IncidentStatus.CLOSED.value,
                                     IncidentStatus.INVESTIGATING.value},
    IncidentStatus.CLOSED.value: {IncidentStatus.INVESTIGATING.value},
}


def _audit(db: Session, tenant_id: str, action: str, details: dict,
           resource: str = "soc"):
    user = get_current_user()
    return write_audit(db, tenant_id=tenant_id,
                       user_id=user.id if user else None,
                       action=action, resource=resource, details=details,
                       ip_address=request.remote_addr,
                       request_id=getattr(g, "request_id", None))


@soc_bp.post("/events")
@require_auth
@require_permission("write:alerts")
@require_browser_security
@rate_limit("soc_ingest", config.RATELIMIT_INGEST,
            lambda: current_tenant_id() or "anon")
def ingest_event():
    try:
        lag = security_store.stream_length(stream_names()["detections"])
        if lag > config.MAX_STREAM_LAG:
            return jsonify({"error": "backpressure", "stream_length": lag}), 429
    except Exception:
        pass
    body = request.get_json(silent=True)
    tid = current_tenant_id()
    if not isinstance(body, dict):
        raw = request.get_data(as_text=True, cache=True)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str):
            raw = str(raw)
        size, sha = payload_fingerprint(raw)
        try:
            parsed = json.loads(raw)
            redacted = json.dumps(redact_payload(parsed),
                                  separators=(",", ":"))[:8192]
        except Exception:
            redacted = redact_payload(raw)[:8192]
        g.db.add(IngestionDLQ(tenant_id=tid,
                              error_reason="MALFORMED_JSON_PAYLOAD",
                              redacted_payload=redacted,
                              raw_payload_size=size,
                              raw_payload_sha256=sha))
        g.db.commit()
        return jsonify({"error": "invalid_payload"}), 400
    if not check_json_depth(body, max_depth=config.MAX_JSON_DEPTH):
        size, sha = payload_fingerprint(json.dumps(body, separators=(",", ":")))
        g.db.add(IngestionDLQ(tenant_id=tid,
                              error_reason="JSON_DEPTH_EXCEEDED",
                              redacted_payload=json.dumps(
                                  redact_payload(body),
                                  separators=(",", ":"))[:8192],
                              raw_payload_size=size,
                              raw_payload_sha256=sha))
        g.db.commit()
        return jsonify({"error": "payload_too_deep"}), 400
    source_type = str(body.pop("source_type", "generic"))[:64]
    try:
        results = pipeline.process(body, tenant_id=tid, source_type=source_type)
    except RuntimeError as exc:
        return jsonify({"error": "service_unavailable", "message": str(exc)}), 503
    EVENTS_INGESTED.labels(tenant=tid or "global", source_type=source_type).inc()
    for r in results:
        DETECTIONS_FIRED.labels(tenant=tid or "global",
                                rule_id=r["detection"]["rule_id"],
                                severity=r["detection"]["severity"]).inc()
    if results:
        try:
            EnrichmentQueue.enqueue_alert(
                results[0]["detection"]["event_id"], tid or "global",
                {"event_id": results[0]["detection"]["event_id"],
                 "detections": [r["detection"] for r in results]})
        except RedisSecurityUnavailableError as exc:
            return jsonify({"error": "service_unavailable", "message": str(exc)}), 503
    return jsonify({"count": len(results),
                    "detections": [{"rule_id": r["detection"]["rule_id"],
                                    "severity": r["detection"]["severity"],
                                    "confidence": r["detection"]["confidence"],
                                    "mitre": r["detection"]["mitre"],
                                    "risk_score": r["risk_score"],
                                    "priority": r["priority"]}
                                   for r in results]}), 202


@soc_bp.get("/detections/rules")
@require_auth
@require_permission("read:alerts")
def list_rules():
    return jsonify({"rules": [{"id": r.id, "title": r.title, "severity": r.severity,
                               "mitre": r.mitre, "tags": r.tags,
                               "description": r.description}
                              for r in all_rules()]})


@soc_bp.get("/incidents")
@require_auth
@require_permission("read:alerts")
@rate_limit("soc_read", config.RATELIMIT_READ, lambda: current_tenant_id() or "anon")
def list_incidents():
    tid = current_tenant_id()
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except ValueError:
        limit = 50
    cursor = request.args.get("cursor")
    q = g.db.query(IncidentModel).filter(IncidentModel.tenant_id == tid)
    if cursor:
        try:
            ts, last_id = cursor.split("|", 1)
            ts_dt = datetime.datetime.fromisoformat(ts)
            q = q.filter((IncidentModel.created_at < ts_dt) |
                         ((IncidentModel.created_at == ts_dt) &
                          (IncidentModel.id > last_id)))
        except Exception:
            return jsonify({"error": "invalid_cursor"}), 400
    items = q.order_by(IncidentModel.created_at.desc(),
                       IncidentModel.id.asc()).limit(limit + 1).all()
    next_cursor = None
    if len(items) > limit:
        last = items[limit - 1]
        next_cursor = f"{last.created_at.isoformat()}|{last.id}"
        items = items[:limit]
    return jsonify({"incidents": [
        {"id": i.id, "title": i.title, "severity": i.severity,
         "status": i.status,
         "created_at": i.created_at.isoformat() if i.created_at else None,
         "detections_count": len(i.detections or [])} for i in items],
        "next_cursor": next_cursor})


@soc_bp.post("/incidents")
@require_auth
@require_permission("write:alerts")
@require_browser_security
def create_incident():
    body = request.get_json(silent=True) or {}
    title = str(body.get("title", "")).strip()
    if not title:
        return jsonify({"error": "validation_failed", "field": "title"}), 400
    severity = str(body.get("severity", "medium")).strip().lower()
    if severity not in VALID_SEVERITIES:
        return jsonify({"error": "validation_failed", "field": "severity"}), 400
    detections = body.get("detections")
    if detections is not None and not isinstance(detections, list):
        return jsonify({"error": "validation_failed", "field": "detections"}), 400
    tid = current_tenant_id()
    iid = f"INC-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
    inc = IncidentModel(id=iid, tenant_id=tid, title=title[:255], severity=severity,
                        status=IncidentStatus.NEW.value,
                        detections=detections or [], notes=[])
    g.db.add(inc)
    _audit(g.db, tid, "incident_created",
           {"incident_id": iid, "title": title, "severity": severity})
    g.db.commit()
    return jsonify({"id": inc.id, "status": inc.status, "title": inc.title}), 201


@soc_bp.post("/incidents/<iid>/evidence")
@require_auth
@require_permission("write:cases")
@require_browser_security
def attach_evidence(iid: str):
    body = request.get_json(silent=True) or {}
    kind = str(body.get("kind", "")).strip().lower()
    payload = body.get("payload")
    if kind not in VALID_KINDS or payload is None:
        return jsonify({"error": "validation_failed",
                        "allowed_kinds": sorted(VALID_KINDS)}), 400
    tid = current_tenant_id()
    user = get_current_user()
    inc = (g.db.query(IncidentModel)
           .filter(IncidentModel.id == iid, IncidentModel.tenant_id == tid)
           .one_or_none())
    if not inc:
        return jsonify({"error": "not_found"}), 404
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    ev = EvidenceModel(incident_id=iid, tenant_id=tid, actor_id=user.id,
                       kind=kind, sha256=sha, canonical_payload=canonical,
                       payload=payload)
    g.db.add(ev)
    _audit(g.db, tid, "evidence_attached",
           {"incident_id": iid, "sha256": sha, "kind": kind})
    g.db.commit()
    return jsonify({"id": ev.id, "sha256": ev.sha256, "status": "sealed"}), 201


@soc_bp.patch("/incidents/<iid>/status")
@require_auth
@require_permission("write:alerts")
@require_browser_security
def transition_incident(iid: str):
    body = request.get_json(silent=True) or {}
    new_status = str(body.get("status", "")).strip().lower()
    tid = current_tenant_id()
    inc = (g.db.query(IncidentModel)
           .filter(IncidentModel.id == iid, IncidentModel.tenant_id == tid)
           .with_for_update().one_or_none())
    if not inc:
        return jsonify({"error": "not_found"}), 404
    allowed = VALID_TRANSITIONS.get(inc.status, set())
    if new_status not in allowed:
        return jsonify({"error": "invalid_transition", "current": inc.status,
                        "target": new_status}), 400
    if _ORDER.get(new_status, 0) < _ORDER.get(inc.status, 0):
        if not str(body.get("reason", "")).strip():
            return jsonify({"error": "validation_failed", "field": "reason",
                            "message": "Backward transitions require a reason"}), 400
    old = inc.status
    inc.status = new_status
    _audit(g.db, tid, "incident_status_changed",
           {"incident_id": iid, "from": old, "to": new_status})
    g.db.commit()
    return jsonify({"id": inc.id, "previous_status": old,
                    "current_status": inc.status})


@soc_bp.get("/playbooks")
@require_auth
@require_permission("read:alerts")
def list_playbooks():
    return jsonify({"playbooks": PlaybookEngine.available_playbooks()})


@soc_bp.post("/playbooks/<name>/dry-run")
@require_auth
@require_permission("write:alerts")
@require_browser_security
def playbook_dry_run(name: str):
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(PlaybookEngine.dry_run(name, body))
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"error": "validation_failed", "message": str(exc)}), 400


@soc_bp.post("/incidents/<iid>/playbooks/<name>/request")
@require_auth
@require_permission("write:alerts")
@require_browser_security
def request_playbook_execution(iid: str, name: str):
    body = request.get_json(silent=True) or {}
    tid = current_tenant_id()
    user = get_current_user()
    inc = (g.db.query(IncidentModel)
           .filter(IncidentModel.id == iid, IncidentModel.tenant_id == tid)
           .one_or_none())
    if not inc:
        return jsonify({"error": "not_found"}), 404
    try:
        PlaybookEngine.validate_parameters(name, body)
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"error": "validation_failed", "message": str(exc)}), 400
    ex = PlaybookExecution(tenant_id=tid, incident_id=iid, playbook_name=name,
                           state=PlaybookState.PENDING_APPROVAL.value,
                           requested_by=user.id, parameters=body)
    g.db.add(ex)
    _audit(g.db, tid, "playbook_requested",
           {"execution_id": ex.id, "playbook": name})
    g.db.commit()
    return jsonify({"execution_id": ex.id, "state": ex.state}), 202


@soc_bp.post("/playbooks/executions/<xid>/approve")
@require_auth
@require_role("admin")
@require_browser_security
def approve_playbook_execution(xid: str):
    tid = current_tenant_id()
    user = get_current_user()
    ex = (g.db.query(PlaybookExecution)
          .filter(PlaybookExecution.id == xid,
                  PlaybookExecution.tenant_id == tid)
          .with_for_update().one_or_none())
    if not ex:
        return jsonify({"error": "not_found"}), 404
    if ex.state != PlaybookState.PENDING_APPROVAL.value:
        return jsonify({"error": "invalid_state", "current_state": ex.state}), 400
    expected_version = (request.get_json(silent=True) or {}).get("expected_version")
    if expected_version is not None:
        try:
            expected_int = int(expected_version)
        except (TypeError, ValueError):
            return jsonify({"error": "validation_failed",
                            "field": "expected_version"}), 400
        if expected_int != ex.version_id:
            return jsonify({"error": "concurrent_modification",
                            "current_version": ex.version_id,
                            "expected_version": expected_int}), 409
    try:
        result = PlaybookEngine.execute(name=ex.playbook_name, params=ex.parameters,
                                        requested_by=ex.requested_by,
                                        approved_by=user.id)
        ex.state = PlaybookState.COMPLETED.value
        ex.approved_by = user.id
        ex.execution_log = [result]
        _audit(g.db, tid, "playbook_executed",
               {"execution_id": ex.id, "result": result})
        g.db.commit()
        return jsonify(result)
    except PermissionError as exc:
        g.db.rollback()
        return jsonify({"error": "authorization_denied",
                        "message": str(exc)}), 403
    except Exception as exc:
        g.db.rollback()
        ex = (g.db.query(PlaybookExecution)
              .filter(PlaybookExecution.id == xid,
                      PlaybookExecution.tenant_id == tid)
              .with_for_update().one_or_none())
        if ex:
            ex.state = PlaybookState.FAILED.value
            ex.execution_log = [{"error": str(exc)}]
            _audit(g.db, tid, "playbook_failed",
                   {"execution_id": xid, "error": str(exc)})
            g.db.commit()
        return jsonify({"error": "execution_failed"}), 500


@soc_bp.get("/audit/verify")
@require_role("admin")
@rate_limit("audit_verify", "5 per minute", lambda: current_tenant_id() or "anon")
def audit_verify():
    tid = current_tenant_id()
    ok, broken_id, truncated = verify_audit_chain(g.db, tid)
    from ...observability.metrics import AUDIT_CHAIN_VERIFY
    AUDIT_CHAIN_VERIFY.labels(result="ok" if ok and not truncated
                              else "broken" if not ok
                              else "truncated").inc()
    return jsonify({"ok": ok, "broken_event_id": broken_id,
                    "truncated": truncated}), (200 if ok else 500)


@soc_bp.post("/mitre/map")
@require_auth
@require_permission("read:alerts")
def mitre_map():
    body = request.get_json(silent=True) or {}
    from ...detection.mitre import map_alert
    return jsonify(map_alert(body.get("alert", body)))


@soc_bp.post("/ai/triage")
@require_auth
@require_permission("read:alerts")
@require_browser_security
def ai_triage():
    body = request.get_json(silent=True) or {}
    alert = body.get("alert") or {}
    if not isinstance(alert, dict):
        return jsonify({"error": "validation_failed", "field": "alert"}), 400
    from ...ai import get_llm_provider, TriageOrchestrator
    orch = TriageOrchestrator(get_llm_provider())
    result = orch.triage(alert)
    tid = current_tenant_id()
    _audit(g.db, tid, "ai_triage_executed",
           {"provider": result.get("provider"),
            "confidence": result.get("confidence"),
            "escalation": result.get("escalation")})
    g.db.commit()
    return jsonify(result)


@soc_bp.post("/analyze/logs")
@require_auth
@require_permission("write:alerts")
@require_browser_security
@rate_limit("soc_log_analyze", "30 per minute",
            lambda: current_tenant_id() or "anon")
def analyze_logs():
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    lines = body.get("lines")
    if text is not None and not isinstance(text, str):
        return jsonify({"error": "validation_failed", "field": "text"}), 400
    if lines is not None and not isinstance(lines, list):
        return jsonify({"error": "validation_failed", "field": "lines"}), 400
    if text is None and lines is None:
        return jsonify({"error": "validation_failed",
                        "message": "provide text or lines"}), 400
    from ...analyzers import LogAnalyzer
    analyzer = LogAnalyzer(pipeline=pipeline)
    if text is not None:
        iterable = text.splitlines()
    else:
        iterable = [str(x) for x in lines]
    tid = current_tenant_id()
    result = analyzer.analyze_lines(iterable, tenant_id=tid)
    _audit(g.db, tid, "log_analysis_executed",
           {"lines": result["lines_analyzed"],
            "detections": result["detection_count"],
            "formats": result["formats"]})
    g.db.commit()
    return jsonify(result), 200


@soc_bp.post("/graph/ingest")
@require_auth
@require_permission("write:alerts")
@require_browser_security
def graph_ingest():
    body = request.get_json(silent=True) or {}
    event = body.get("event") or {}
    if not isinstance(event, dict):
        return jsonify({"error": "validation_failed", "field": "event"}), 400
    try:
        risk = int(body.get("risk", 0))
    except (TypeError, ValueError):
        risk = 0
    incident_id = body.get("incident_id")
    tid = current_tenant_id()
    from ...graph import AttackerPathBuilder
    builder = AttackerPathBuilder(g.db, tid)
    builder.ingest(event, risk=max(0, min(100, risk)), incident_id=incident_id)
    builder.commit()
    _audit(g.db, tid, "graph_ingest",
           {"event_id": event.get("event_id"), "risk": risk})
    g.db.commit()
    return jsonify({"ok": True}), 200


@soc_bp.get("/graph/stats")
@require_auth
@require_permission("read:alerts")
def graph_stats():
    tid = current_tenant_id()
    from ...graph import AttackerPathQuery
    q = AttackerPathQuery(g.db, tid)
    return jsonify(q.stats())


@soc_bp.get("/graph/path")
@require_auth
@require_permission("read:alerts")
def graph_path():
    tid = current_tenant_id()
    src_kind = request.args.get("src_kind")
    src_val = request.args.get("src_val")
    dst_kind = request.args.get("dst_kind")
    dst_val = request.args.get("dst_val")
    if not all([src_kind, src_val, dst_kind, dst_val]):
        return jsonify({"error": "validation_failed",
                        "required": ["src_kind", "src_val", "dst_kind", "dst_val"]}), 400
    from ...graph import AttackerPathQuery
    q = AttackerPathQuery(g.db, tid)
    path = q.shortest_path(src_kind, src_val, dst_kind, dst_val)
    return jsonify({"path": path, "hops": max(0, len(path) - 1)})


@soc_bp.get("/graph/blast-radius")
@require_auth
@require_permission("read:alerts")
def graph_blast_radius():
    tid = current_tenant_id()
    kind = request.args.get("kind")
    value = request.args.get("value")
    if not kind or not value:
        return jsonify({"error": "validation_failed",
                        "required": ["kind", "value"]}), 400
    try:
        depth = min(int(request.args.get("depth", 3)), 6)
    except ValueError:
        depth = 3
    from ...graph import AttackerPathQuery
    q = AttackerPathQuery(g.db, tid)
    return jsonify(q.blast_radius(kind, value, max_depth=depth))


@soc_bp.get("/graph/communities")
@require_auth
@require_permission("read:alerts")
def graph_communities():
    tid = current_tenant_id()
    from ...graph import AttackerPathQuery
    q = AttackerPathQuery(g.db, tid)
    return jsonify({"communities": q.high_risk_communities()})
