"""Initial schema with RLS enablement."""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


TENANT_TABLES = (
    "users", "audit_events", "incidents", "incident_evidence",
    "playbook_executions", "password_resets",
    "attacker_path_nodes", "attacker_path_edges",
)


def upgrade() -> None:
    op.create_table("tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("slug", sa.String(128), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_tenants_slug", "tenants", ["slug"])
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("mfa_secret", sa.String(64), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_users_tenant", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table("password_resets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_password_resets_token_hash", "password_resets", ["token_hash"])
    op.create_table("audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("details", JSONB(), nullable=False),
        sa.Column("details_canonical", sa.Text(), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("curr_hash", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_audit_tenant_seq", "audit_events",
                    ["tenant_id", "seq"], unique=True)
    op.create_index("ix_audit_tenant_time", "audit_events",
                    ["tenant_id", "timestamp"])
    op.create_table("incidents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detections", JSONB(), nullable=False),
        sa.Column("notes", JSONB(), nullable=False))
    op.create_index("ix_incidents_tenant_status", "incidents", ["tenant_id", "status"])
    op.create_index("ix_incidents_tenant_created", "incidents",
                    ["tenant_id", "created_at"])
    op.create_table("incident_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(64),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_evidence_tenant_incident", "incident_evidence",
                    ["tenant_id", "incident_id"])
    op.create_table("playbook_executions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(64),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("playbook_name", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("requested_by", sa.String(36), nullable=False),
        sa.Column("approved_by", sa.String(36), nullable=True),
        sa.Column("parameters", JSONB(), nullable=False),
        sa.Column("execution_log", JSONB(), nullable=False),
        sa.Column("version_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("ingestion_dlq",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("error_reason", sa.String(255), nullable=False),
        sa.Column("redacted_payload", sa.Text(), nullable=False),
        sa.Column("raw_payload_size", sa.BigInteger(), nullable=False),
        sa.Column("raw_payload_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("attacker_path_nodes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False))
    op.create_index("ix_apn_tenant_kind_value", "attacker_path_nodes",
                    ["tenant_id", "kind", "value"], unique=True)
    op.create_table("attacker_path_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("src_id", sa.String(64),
                  sa.ForeignKey("attacker_path_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dst_id", sa.String(64),
                  sa.ForeignKey("attacker_path_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.String(64), nullable=True),
        sa.Column("evidence_event_id", sa.String(64), nullable=True))
    op.create_index("ix_ape_tenant_src_dst_rel", "attacker_path_edges",
                    ["tenant_id", "src_id", "dst_id", "relation"], unique=True)

    if op.get_bind().dialect.name == "postgresql":
        for tbl in TENANT_TABLES:
            op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
            op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {tbl};")
            op.execute(
                f"CREATE POLICY tenant_isolation ON {tbl} "
                f"USING (tenant_id::text = current_setting('app.tenant_id', true)) "
                f"WITH CHECK (tenant_id::text = current_setting('app.tenant_id', true));"
            )


def downgrade() -> None:
    for t in ["attacker_path_edges", "attacker_path_nodes", "ingestion_dlq",
              "playbook_executions", "incident_evidence", "incidents",
              "audit_events", "password_resets", "users", "tenants"]:
        op.drop_table(t)
