-- AgentShield V2 — Database Schema
-- Owner: Pavan (schema design) | Alok (migrations and ORM models)
--
-- Run via Docker Compose init: /docker-entrypoint-initdb.d/init.sql
-- Also used by Alembic migrations.

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────────────
-- Tenants
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id       TEXT        PRIMARY KEY,
    display_name    TEXT        NOT NULL,
    environment     TEXT        NOT NULL CHECK (environment IN ('demo','staging','production')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Agents
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agents (
    agent_id            TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL REFERENCES tenants(tenant_id),
    display_name        TEXT,
    permitted_tools     TEXT[]      NOT NULL DEFAULT '{}',
    max_amount_minor    BIGINT,     -- NULL = policy-controlled only
    environment         TEXT        NOT NULL CHECK (environment IN ('demo','staging','production')),
    registered          BOOLEAN     NOT NULL DEFAULT TRUE,
    revoked             BOOLEAN     NOT NULL DEFAULT FALSE,
    api_key_hash        TEXT        NOT NULL,    -- bcrypt hash; NEVER store plaintext
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_revoked ON agents(revoked) WHERE revoked = TRUE;

-- ─────────────────────────────────────────────────────────────────────────────
-- Revocations (separate table for fast lookup + durability)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id   UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        TEXT        NOT NULL REFERENCES agents(agent_id),
    tenant_id       TEXT        NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_by      TEXT        NOT NULL,
    reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_revocations_agent ON revocations(agent_id, tenant_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Approval Requests
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               TEXT        NOT NULL,
    intent_id               TEXT        NOT NULL,
    action_digest           TEXT        NOT NULL,
    approval_type           TEXT        NOT NULL,
    decision                TEXT        CHECK (decision IN ('approved','rejected')),
    approver_identity       TEXT,                   -- Set when decision submitted
    consumed                BOOLEAN     NOT NULL DEFAULT FALSE,
    approval_policy_version INTEGER,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL,
    decided_at              TIMESTAMPTZ,
    approver_note           TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approval_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_approvals_intent ON approval_requests(intent_id);
CREATE INDEX IF NOT EXISTS idx_approvals_digest ON approval_requests(action_digest);

-- ─────────────────────────────────────────────────────────────────────────────
-- Execution Records
-- UNIQUE(jti) is the core replay protection constraint.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS execution_records (
    execution_id        UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti                 TEXT        NOT NULL UNIQUE,    -- UNIQUE = replay protection
    principal_id        TEXT        NOT NULL,
    tenant_id           TEXT        NOT NULL,
    tool                TEXT        NOT NULL,
    resource            TEXT        NOT NULL,
    action_digest       TEXT        NOT NULL,
    approval_id         UUID,
    state               TEXT        NOT NULL
                            CHECK (state IN (
                                'ISSUED','CLAIMED','RUNNING',
                                'SUCCEEDED','FAILED_FINAL','UNKNOWN'
                            )),
    idempotency_key     TEXT        NOT NULL,           -- = jti; passed to mock tool
    result              JSONB,
    error               TEXT,
    receipt_id          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exec_tenant   ON execution_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exec_agent    ON execution_records(principal_id);
CREATE INDEX IF NOT EXISTS idx_exec_digest   ON execution_records(action_digest);
CREATE INDEX IF NOT EXISTS idx_exec_state    ON execution_records(state)
    WHERE state IN ('CLAIMED','RUNNING','UNKNOWN');

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER exec_updated_at
    BEFORE UPDATE ON execution_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─────────────────────────────────────────────────────────────────────────────
-- Execution Receipts
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS execution_receipts (
    receipt_id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id        UUID        NOT NULL REFERENCES execution_records(execution_id),
    tenant_id           TEXT        NOT NULL,
    principal_id        TEXT        NOT NULL,
    action_digest       TEXT        NOT NULL,
    jti                 TEXT        NOT NULL,
    approval_id         UUID,
    execution_result    TEXT        NOT NULL
                            CHECK (execution_result IN ('succeeded','failed','unknown')),
    timestamp           TIMESTAMPTZ NOT NULL,
    executor_id         TEXT        NOT NULL DEFAULT 'agentshield-executor-v1',
    schema_version      INTEGER     NOT NULL DEFAULT 1,
    kid                 TEXT        NOT NULL,
    signature           TEXT        NOT NULL,
    signed_payload      JSONB       NOT NULL    -- Full receipt payload that was signed
);

CREATE INDEX IF NOT EXISTS idx_receipts_execution ON execution_receipts(execution_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Audit Events (hash-chained)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_events (
    seq             BIGSERIAL   PRIMARY KEY,
    event_id        UUID        NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type      TEXT        NOT NULL,
    tenant_id       TEXT        NOT NULL,
    principal_id    TEXT,
    action_digest   TEXT,
    jti             TEXT,
    execution_id    UUID,
    approval_id     UUID,
    prev_hash       TEXT        NOT NULL,    -- Hash of previous record (GENESIS=000...0)
    record_hash     TEXT        NOT NULL,    -- SHA-256 of this record (excluding record_hash)
    signature       TEXT,                   -- Optional Ed25519 signature (Girish's module)
    kid             TEXT,
    extra           JSONB                   -- Additional event-specific data
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant    ON audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_agent     ON audit_events(principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_type      ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_digest    ON audit_events(action_digest);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);

-- ─────────────────────────────────────────────────────────────────────────────
-- Mock Protected Tool State (maintained by mock_tool service)
-- Listed here for schema completeness; mock_tool service owns this table.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mock_orders (
    order_id            TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    customer_name       TEXT        NOT NULL DEFAULT 'Demo Customer',
    total_amount_minor  BIGINT      NOT NULL,
    refund_issued       BOOLEAN     NOT NULL DEFAULT FALSE,
    refund_amount_minor BIGINT      NOT NULL DEFAULT 0,
    refund_idempotency_key TEXT,        -- jti of the execution that triggered the refund
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Demo fixture data (loaded on reset)
-- Populated by POST /v1/demo/reset
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO tenants (tenant_id, display_name, environment) VALUES
    ('tenant-demo', 'Demo Tenant', 'demo')
ON CONFLICT (tenant_id) DO NOTHING;
