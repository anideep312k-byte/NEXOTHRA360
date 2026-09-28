"""Database models with forensic integrity, audit locks, and RLS support."""
from __future__ import annotations
import datetime
from enum import Enum
import hashlib
import json
from typing import Any, Generator
import uuid

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, ForeignKey, Index,
    Integer, String, Text, create_engine, event, text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator

from ..config import config

Base = declarative_base()

TENANT_TABLES = (
    "users", "audit_events", "incidents", "incident_evidence",
    "playbook_executions", "password_resets", "attacker_path_nodes",
    "attacker_path_edges",
)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class RoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class PlaybookState(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class PortableJSON(TypeDecorator):
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return json.loads(value)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)
    slug = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(64), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default=RoleEnum.ANALYST.value)
    is_active = Column(Boolean, default=True, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(64), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    tenant = relationship("Tenant")


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    seq = Column(BigInteger, nullable=False)
    user_id = Column(String(36), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    resource = Column(String(64), nullable=False)
    details = Column(PortableJSON, nullable=False, default=dict)
    details_canonical = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=True)
    request_id = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=True)
    curr_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_tenant_seq", "tenant_id", "seq", unique=True),
        Index("ix_audit_tenant_time", "tenant_id", "timestamp"),
    )

    @staticmethod
    def calculate_hash(prev_hash, timestamp, tenant_id, user_id, action, resource,
                       ip_address, details) -> str:
        payload = {
            "prev_hash": prev_hash or "GENESIS",
            "timestamp": timestamp,
            "tenant_id": tenant_id,
            "user_id": user_id or "",
            "action": action,
            "resource": resource,
            "ip_address": ip_address or "",
            "details": details,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@event.listens_for(AuditEvent, "before_insert")
def _audit_event_require_canonical(mapper, connection, target):
    if not target.details_canonical or target.details_canonical == "{}":
        raise ValueError(
            "AuditEvent.details_canonical must be populated by write_audit(). "
            "Direct inserts are forbidden.")


class IncidentModel(Base):
    __tablename__ = "incidents"
    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, default="medium", index=True)
    status = Column(String(32), nullable=False, default=IncidentStatus.NEW.value, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
                        nullable=False)
    detections = Column(PortableJSON, nullable=False, default=list)
    notes = Column(PortableJSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_created", "tenant_id", "created_at"),
    )


class EvidenceModel(Base):
    __tablename__ = "incident_evidence"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    actor_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"),
                      nullable=False, index=True)
    kind = Column(String(64), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    canonical_payload = Column(Text, nullable=False)
    payload = Column(PortableJSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (Index("ix_evidence_tenant_incident", "tenant_id", "incident_id"),)


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    playbook_name = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False, default=PlaybookState.PENDING_APPROVAL.value)
    requested_by = Column(String(36), nullable=False)
    approved_by = Column(String(36), nullable=True)
    parameters = Column(PortableJSON, nullable=False, default=dict)
    execution_log = Column(PortableJSON, nullable=False, default=list)
    version_id = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
                        nullable=False)

    __mapper_args__ = {"version_id_col": version_id}


class IngestionDLQ(Base):
    __tablename__ = "ingestion_dlq"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=True, index=True)
    error_reason = Column(String(255), nullable=False)
    redacted_payload = Column(Text, nullable=False)
    raw_payload_size = Column(BigInteger, nullable=False, default=0)
    raw_payload_sha256 = Column(String(64), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class AttackerPathNode(Base):
    __tablename__ = "attacker_path_nodes"
    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    kind = Column(String(32), nullable=False, index=True)
    value = Column(String(255), nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    metadata_json = Column(PortableJSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_apn_tenant_kind_value", "tenant_id", "kind", "value", unique=True),
    )


class AttackerPathEdge(Base):
    __tablename__ = "attacker_path_edges"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    src_id = Column(String(64), ForeignKey("attacker_path_nodes.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    dst_id = Column(String(64), ForeignKey("attacker_path_nodes.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    relation = Column(String(64), nullable=False)
    first_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    observation_count = Column(Integer, nullable=False, default=1)
    incident_id = Column(String(64), nullable=True, index=True)
    evidence_event_id = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_ape_tenant_src_dst_rel", "tenant_id", "src_id", "dst_id", "relation",
              unique=True),
    )


# =========================================================================
# ENGINE + SESSION
# =========================================================================
engine_args: dict[str, Any] = {"pool_pre_ping": True}
if config.DATABASE_URL.startswith("postgresql"):
    engine_args.update({
        "pool_size": 25, "max_overflow": 15, "pool_recycle": 1800, "pool_timeout": 30,
    })

engine = create_engine(config.DATABASE_URL, **engine_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    if config.APP_ENV != "production":
        Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def set_tenant_context(db: Session, tenant_id: str | None) -> None:
    if db.bind.dialect.name != "postgresql":
        return
    if not tenant_id:
        tenant_id = "00000000-0000-0000-0000-000000000000"
    db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"),
               {"tid": tenant_id})


def rls_ddl_statement() -> list[str]:
    stmts = []
    for tbl in TENANT_TABLES:
        stmts.append(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        stmts.append(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        stmts.append(f"DROP POLICY IF EXISTS tenant_isolation ON {tbl};")
        stmts.append(
            f"CREATE POLICY tenant_isolation ON {tbl} "
            f"USING (tenant_id::text = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));"
        )
    return stmts
