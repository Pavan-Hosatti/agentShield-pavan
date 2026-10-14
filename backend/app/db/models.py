"""
AgentShield V2 — SQLAlchemy ORM Models

Owner: Pavan (schema specification) | Alok (database integration)

These models mirror the schema in backend/db/init.sql exactly.
The UNIQUE constraint on execution_records.jti is the replay-protection
durable lock — Alok must NEVER remove it.

Security-critical constraints:
  execution_records.jti        UNIQUE  — replay protection (I4)
  audit_events.event_id        UNIQUE  — audit deduplication
  approval_requests.approval_id  PRIMARY KEY

All monetary amounts are stored as BIGINT (paise) — never FLOAT.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, ForeignKey, Index,
    Integer, String, Text, UniqueConstraint, event,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID, ARRAY
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id    = Column(String(128), primary_key=True)
    display_name = Column(String(256), nullable=False)
    environment  = Column(String(32),  nullable=False)
    created_at   = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    agents   = relationship("Agent",   back_populates="tenant")


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

class Agent(Base):
    __tablename__ = "agents"

    agent_id         = Column(String(128), primary_key=True)
    tenant_id        = Column(String(128), ForeignKey("tenants.tenant_id"), nullable=False)
    display_name     = Column(String(256))
    permitted_tools  = Column(ARRAY(Text), nullable=False, default=list)
    max_amount_minor = Column(BigInteger)   # NULL = policy-controlled only
    environment      = Column(String(32),  nullable=False)
    registered       = Column(Boolean,     nullable=False, default=True)
    revoked          = Column(Boolean,     nullable=False, default=False)
    api_key_hash     = Column(Text,        nullable=False)   # bcrypt hash — NEVER plaintext
    created_at       = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    revoked_at       = Column(DateTime(timezone=True))

    tenant           = relationship("Tenant", back_populates="agents")
    revocations      = relationship("Revocation", back_populates="agent")
    executions       = relationship("ExecutionRecord", back_populates="agent",
                                    foreign_keys="ExecutionRecord.principal_id",
                                    primaryjoin="Agent.agent_id == ExecutionRecord.principal_id")

    __table_args__ = (
        Index("idx_agents_tenant", "tenant_id"),
        Index("idx_agents_revoked", "revoked",
              postgresql_where=Column("revoked") == True),  # noqa: E712
    )


# ---------------------------------------------------------------------------
# Revocations
# ---------------------------------------------------------------------------

class Revocation(Base):
    __tablename__ = "revocations"

    revocation_id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    agent_id      = Column(String(128), ForeignKey("agents.agent_id"), nullable=False)
    tenant_id     = Column(String(128), nullable=False)
    revoked_at    = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    revoked_by    = Column(String(256), nullable=False)
    reason        = Column(Text)

    agent = relationship("Agent", back_populates="revocations")

    __table_args__ = (
        Index("idx_revocations_agent", "agent_id", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# Approval Requests
# ---------------------------------------------------------------------------

class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    approval_id             = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    tenant_id               = Column(String(128), nullable=False)
    intent_id               = Column(String(128), nullable=False)
    action_digest           = Column(String(64),  nullable=False)  # hex SHA-256
    approval_type           = Column(String(64),  nullable=False)
    decision                = Column(String(16))   # "approved" | "rejected" | NULL (pending)
    approver_identity       = Column(Text)          # Set when decision is submitted
    consumed                = Column(Boolean,     nullable=False, default=False)
    approval_policy_version = Column(Integer)
    created_at              = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at              = Column(DateTime(timezone=True), nullable=False)
    decided_at              = Column(DateTime(timezone=True))
    approver_note           = Column(Text)

    __table_args__ = (
        Index("idx_approvals_tenant", "tenant_id"),
        Index("idx_approvals_intent", "intent_id"),
        Index("idx_approvals_digest", "action_digest"),
    )


# ---------------------------------------------------------------------------
# Execution Records
# CRITICAL: jti UNIQUE constraint is replay protection (Invariant I4)
# ---------------------------------------------------------------------------

class ExecutionRecord(Base):
    __tablename__ = "execution_records"

    execution_id    = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    jti             = Column(String(128), nullable=False, unique=True)  # UNIQUE = replay protection
    principal_id    = Column(String(128), nullable=False)
    tenant_id       = Column(String(128), nullable=False)
    tool            = Column(String(64),  nullable=False)
    resource        = Column(String(256), nullable=False)
    action_digest   = Column(String(64),  nullable=False)
    approval_id     = Column(UUID(as_uuid=False))
    state           = Column(String(32),  nullable=False)   # ISSUED|CLAIMED|RUNNING|SUCCEEDED|FAILED_FINAL|UNKNOWN
    idempotency_key = Column(String(128), nullable=False)   # = jti; passed to mock tool
    result          = Column(JSONB)
    error           = Column(Text)
    receipt_id      = Column(UUID(as_uuid=False))
    created_at      = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at      = Column(DateTime(timezone=True), default=_utcnow,
                             onupdate=_utcnow, nullable=False)

    agent = relationship("Agent", foreign_keys=[principal_id],
                         primaryjoin="ExecutionRecord.principal_id == Agent.agent_id")

    __table_args__ = (
        UniqueConstraint("jti", name="uq_execution_jti"),  # explicit name for migrations
        Index("idx_exec_tenant",   "tenant_id"),
        Index("idx_exec_agent",    "principal_id"),
        Index("idx_exec_digest",   "action_digest"),
        # Partial index on in-flight states for recovery queries
        Index("idx_exec_inflight", "state",
              postgresql_where=Column("state").in_(["CLAIMED", "RUNNING", "UNKNOWN"])),
    )


# ---------------------------------------------------------------------------
# Execution Receipts
# ---------------------------------------------------------------------------

class ExecutionReceipt(Base):
    __tablename__ = "execution_receipts"

    receipt_id       = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    execution_id     = Column(UUID(as_uuid=False),
                               ForeignKey("execution_records.execution_id"), nullable=False)
    tenant_id        = Column(String(128), nullable=False)
    principal_id     = Column(String(128), nullable=False)
    action_digest    = Column(String(64),  nullable=False)
    jti              = Column(String(128), nullable=False)
    approval_id      = Column(UUID(as_uuid=False))
    execution_result = Column(String(16),  nullable=False)  # succeeded|failed|unknown
    timestamp        = Column(DateTime(timezone=True), nullable=False)
    executor_id      = Column(String(64),  nullable=False, default="agentshield-executor-v1")
    schema_version   = Column(Integer,     nullable=False, default=1)
    kid              = Column(String(64),  nullable=False)
    signature        = Column(Text,        nullable=False)
    signed_payload   = Column(JSONB,       nullable=False)

    __table_args__ = (
        Index("idx_receipts_execution", "execution_id"),
    )


# ---------------------------------------------------------------------------
# Audit Events (hash-chained)
# CRITICAL: Never truncate this table in production.
# ---------------------------------------------------------------------------

class AuditEvent(Base):
    __tablename__ = "audit_events"

    seq           = Column(BigInteger,     primary_key=True, autoincrement=True)
    event_id      = Column(UUID(as_uuid=False), nullable=False, unique=True, default=_new_uuid)
    timestamp     = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    event_type    = Column(String(64),  nullable=False)
    tenant_id     = Column(String(128), nullable=False)
    principal_id  = Column(String(128))
    action_digest = Column(String(64))
    jti           = Column(String(128))
    execution_id  = Column(UUID(as_uuid=False))
    approval_id   = Column(UUID(as_uuid=False))
    prev_hash     = Column(String(64),  nullable=False)   # SHA-256 of previous record
    record_hash   = Column(String(64),  nullable=False)   # SHA-256 of this record
    signature     = Column(Text)                           # Optional Ed25519 (Girish)
    kid           = Column(String(64))
    extra         = Column(JSONB)

    __table_args__ = (
        Index("idx_audit_tenant",    "tenant_id"),
        Index("idx_audit_agent",     "principal_id"),
        Index("idx_audit_type",      "event_type"),
        Index("idx_audit_digest",    "action_digest"),
        Index("idx_audit_timestamp", "timestamp"),
    )


# ---------------------------------------------------------------------------
# Mock Orders (mock protected tool state)
# ---------------------------------------------------------------------------

class MockOrder(Base):
    __tablename__ = "mock_orders"

    order_id              = Column(String(128), primary_key=True)
    tenant_id             = Column(String(128), nullable=False)
    customer_name         = Column(String(256), nullable=False, default="Demo Customer")
    total_amount_minor    = Column(BigInteger,  nullable=False)
    refund_issued         = Column(Boolean,     nullable=False, default=False)
    refund_amount_minor   = Column(BigInteger,  nullable=False, default=0)
    refund_idempotency_key = Column(String(128))  # jti of the execution that triggered it
    last_updated          = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
