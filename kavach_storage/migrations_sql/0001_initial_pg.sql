-- KAVACH360 PostgreSQL schema, version 1.
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_ts  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id                 TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenants(tenant_id),
    username                TEXT NOT NULL,
    role                    TEXT NOT NULL,
    pw_hash                 TEXT NOT NULL,
    pw_salt                 TEXT NOT NULL,
    pw_iter                 INTEGER NOT NULL,
    mfa_secret              TEXT,
    mfa_enabled             INTEGER NOT NULL DEFAULT 0,
    failed_attempts         INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    created_ts              TIMESTAMPTZ NOT NULL,
    must_change_password    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, username)
);
CREATE TABLE IF NOT EXISTS sessions (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    tenant_id   TEXT NOT NULL,
    issued_ts   TIMESTAMPTZ NOT NULL,
    expires_ts  TIMESTAMPTZ NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_ts);
CREATE TABLE IF NOT EXISTS bus (
    id          BIGSERIAL PRIMARY KEY,
    topic       TEXT NOT NULL,
    payload     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    enqueued_ts TIMESTAMPTZ NOT NULL,
    lease_ts    TIMESTAMPTZ,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_bus_status ON bus(status, id);
CREATE TABLE IF NOT EXISTS dlq (
    id          BIGSERIAL PRIMARY KEY,
    topic       TEXT NOT NULL,
    payload     TEXT NOT NULL,
    error       TEXT,
    moved_ts    TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    source      TEXT NOT NULL,
    event_ts    TIMESTAMPTZ NOT NULL,
    ingested_ts TIMESTAMPTZ NOT NULL,
    normalized  TEXT NOT NULL,
    quality     REAL NOT NULL DEFAULT 0.0,
    dedup_key   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts ON events(tenant_id, event_ts);
CREATE INDEX IF NOT EXISTS idx_events_dedup     ON events(tenant_id, dedup_key);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    entity      TEXT,
    event_ids   TEXT NOT NULL,
    risk        REAL NOT NULL DEFAULT 0.0,
    confidence  REAL NOT NULL DEFAULT 0.5,
    status      TEXT NOT NULL DEFAULT 'new',
    created_ts  TIMESTAMPTZ NOT NULL,
    updated_ts  TIMESTAMPTZ,
    assignee    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_ts ON alerts(tenant_id, created_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(tenant_id, status);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    title       TEXT NOT NULL,
    state       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk        REAL NOT NULL DEFAULT 0.0,
    assignee    TEXT,
    alert_ids   TEXT NOT NULL,
    entities    TEXT NOT NULL,
    timeline    TEXT NOT NULL,
    created_ts  TIMESTAMPTZ NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL,
    notes       TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents(tenant_id, created_ts);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    added_ts    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE TABLE IF NOT EXISTS incident_timeline (
    id          BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    kind        TEXT NOT NULL,
    alert_id    TEXT,
    title       TEXT,
    actor       TEXT,
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_inc ON incident_timeline(incident_id, id);
CREATE TABLE IF NOT EXISTS incident_entity_index (
    tenant_id   TEXT NOT NULL,
    entity      TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, entity)
);
CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    incident_id TEXT,
    title       TEXT NOT NULL,
    state       TEXT NOT NULL,
    notes       TEXT NOT NULL,
    created_ts  TIMESTAMPTZ NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    ioc_type    TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.5,
    severity    TEXT NOT NULL DEFAULT 'medium',
    expires_ts  TIMESTAMPTZ,
    created_ts  TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_lookup ON iocs(tenant_id, ioc_type, value);
CREATE TABLE IF NOT EXISTS entity_state (
    tenant_id   TEXT NOT NULL,
    entity      TEXT NOT NULL,
    state       TEXT NOT NULL,
    risk        REAL NOT NULL DEFAULT 0.0,
    updated_ts  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, entity)
);
CREATE TABLE IF NOT EXISTS baselines (
    tenant_id   TEXT NOT NULL,
    entity      TEXT NOT NULL,
    metric      TEXT NOT NULL,
    mean        REAL NOT NULL,
    std         REAL NOT NULL,
    n           INTEGER NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, entity, metric)
);
CREATE TABLE IF NOT EXISTS audit (
    seq         BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    actor       TEXT,
    tenant_id   TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    result      TEXT NOT NULL,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    row_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit(tenant_id, seq);
CREATE TABLE IF NOT EXISTS audit_anchor (
    seq         BIGINT PRIMARY KEY,
    root_hash   TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS response_actions (
    action_id           TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    incident_id         TEXT,
    action_type         TEXT NOT NULL,
    params              TEXT NOT NULL,
    state               TEXT NOT NULL,
    requested_by        TEXT NOT NULL,
    approved_by         TEXT,
    executed_ts         TIMESTAMPTZ,
    result              TEXT,
    rollback_available  INTEGER NOT NULL DEFAULT 0,
    created_ts          TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
    tenant_id   TEXT NOT NULL,
    k           TEXT NOT NULL,
    v           TEXT NOT NULL,
    updated_ts  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, k)
);
CREATE TABLE IF NOT EXISTS schema_meta (
    k   TEXT PRIMARY KEY,
    v   TEXT NOT NULL
);
INSERT INTO schema_meta(k, v) VALUES ('version', '1')
    ON CONFLICT (k) DO NOTHING;
