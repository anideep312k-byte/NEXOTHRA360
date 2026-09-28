"""Audit-chain writer."""
from __future__ import annotations
import datetime
import decimal
import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from ...config import config
from ...storage.database import AuditEvent


def _default(o: Any) -> Any:
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, uuid.UUID):
        return str(o)
    if isinstance(o, decimal.Decimal):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return sorted(map(str, o))
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def canonicalize_details(details: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(details, dict):
        details = {"_value": details}
    canonical = json.dumps(details, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=_default)
    if len(canonical.encode("utf-8")) > config.MAX_AUDIT_DETAILS_BYTES:
        canonical = json.dumps({"_truncated": True, "size": len(canonical)},
                               sort_keys=True, separators=(",", ":"))
    try:
        return json.loads(canonical), canonical
    except Exception:
        fallback = json.dumps({"_canonical_parse_failed": True,
                               "raw_size": len(canonical)},
                              sort_keys=True, separators=(",", ":"))
        return json.loads(fallback), fallback


def _advisory_key(tenant_id: str) -> int:
    digest = hashlib.sha256(tenant_id.encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def write_audit(db: Session, *, tenant_id: str, user_id: str | None, action: str,
                resource: str, details: dict[str, Any], ip_address: str | None,
                request_id: str | None = None) -> AuditEvent:
    if not tenant_id:
        raise ValueError("tenant_id is required")
    safe_details, canonical = canonicalize_details(details)
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                   {"k": _advisory_key(tenant_id)})
    last = (db.query(AuditEvent)
            .filter(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.desc())
            .with_for_update()
            .first())
    prev_hash = last.curr_hash if last else "GENESIS"
    next_seq = (last.seq + 1) if last else 1
    now = datetime.datetime.now(datetime.timezone.utc)
    curr_hash = AuditEvent.calculate_hash(
        prev_hash=prev_hash, timestamp=now.isoformat(), tenant_id=tenant_id,
        user_id=user_id, action=action, resource=resource,
        ip_address=ip_address, details=safe_details)
    event = AuditEvent(
        id=str(uuid.uuid4()), tenant_id=tenant_id, seq=next_seq, user_id=user_id,
        action=action, resource=resource, details=safe_details,
        details_canonical=canonical, ip_address=ip_address,
        request_id=request_id, prev_hash=prev_hash, curr_hash=curr_hash, timestamp=now)
    db.add(event)
    return event


def verify_audit_chain(db: Session, tenant_id: str,
                       max_rows: int = 1_000_000) -> tuple[bool, str | None, bool]:
    q = (db.query(AuditEvent)
         .filter(AuditEvent.tenant_id == tenant_id)
         .order_by(AuditEvent.seq.asc())
         .yield_per(1000))
    prev = "GENESIS"
    seen = 0
    for ev in q:
        seen += 1
        if seen > max_rows:
            return True, None, True
        try:
            details = (json.loads(ev.details_canonical)
                       if ev.details_canonical else (ev.details or {}))
        except Exception:
            return False, ev.id, False
        expected = AuditEvent.calculate_hash(
            prev_hash=prev,
            timestamp=ev.timestamp.isoformat() if ev.timestamp else "",
            tenant_id=ev.tenant_id, user_id=ev.user_id, action=ev.action,
            resource=ev.resource, ip_address=ev.ip_address, details=details)
        if expected != ev.curr_hash or (ev.prev_hash or "GENESIS") != prev:
            return False, ev.id, False
        prev = ev.curr_hash
    return True, None, False
