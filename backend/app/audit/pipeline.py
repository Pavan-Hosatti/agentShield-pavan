"""
AgentShield V2 — Audit Pipeline

Owner: Pavan (pipeline design) | Alok (DB integration) | Girish (signing)

Every security-relevant event MUST produce an audit record.
The pipeline:
  1. Builds a hash-chained audit record (via app.security.audit_chain)
  2. Persists it to PostgreSQL (append-only)
  3. Optionally signs it (Girish's module, when signing key is configured)

Durable delivery guarantee:
  The executor writes the audit event AFTER persisting the execution record.
  If audit delivery fails, the execution record still exists as evidence.
  Gaps in the chain are detectable by the verifier.

FAIL BEHAVIOR:
  Audit write failure does NOT roll back the execution. Log the error,
  emit a structured alert, and let the execution succeed.
  The execution record is the ground truth; the audit chain is verification.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from app.security.audit_chain import (
    AuditEventType,
    GENESIS_PREV_HASH,
    build_audit_record,
    get_chain_head_hash,
    verify_audit_chain,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event builders — one function per event type
# All callers use these; never construct raw audit dicts manually.
# ---------------------------------------------------------------------------

def make_action_authorized_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: Optional[str] = None,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.ACTION_AUTHORIZED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti, prev_hash=prev_hash,
    )


def make_capability_issued_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.CAPABILITY_ISSUED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti, prev_hash=prev_hash,
    )


def make_execution_claimed_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: str, execution_id: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.EXECUTION_CLAIMED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti,
        execution_id=execution_id, prev_hash=prev_hash,
    )


def make_execution_succeeded_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: str, execution_id: str,
    approval_id: Optional[str] = None,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.EXECUTION_SUCCEEDED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti,
        execution_id=execution_id, approval_id=approval_id,
        prev_hash=prev_hash,
    )


def make_execution_denied_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: Optional[str] = None,
    reason: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.EXECUTION_DENIED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti, prev_hash=prev_hash,
        extra={"denial_reason": reason},
    )


def make_agent_revoked_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    revoked_by: str, reason: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.AGENT_REVOKED,
        tenant_id=tenant_id, principal_id=principal_id, prev_hash=prev_hash,
        extra={"revoked_by": revoked_by, "reason": reason},
    )


def make_approval_consumed_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, approval_id: str, jti: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.APPROVAL_CONSUMED,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, approval_id=approval_id,
        jti=jti, prev_hash=prev_hash,
    )


def make_execution_unknown_event(
    *, seq: int, prev_hash: str,
    tenant_id: str, principal_id: str,
    action_digest: str, jti: str, execution_id: str,
    error: str,
) -> dict[str, Any]:
    return build_audit_record(
        seq=seq, event_type=AuditEventType.EXECUTION_UNKNOWN,
        tenant_id=tenant_id, principal_id=principal_id,
        action_digest=action_digest, jti=jti,
        execution_id=execution_id, prev_hash=prev_hash,
        extra={"error": error},
    )


# ---------------------------------------------------------------------------
# Chain prev_hash resolver
# ---------------------------------------------------------------------------

def get_latest_record_hash(db_session: Any) -> str:
    """
    Get the record_hash of the last audit event for chain linking.
    Returns GENESIS_PREV_HASH if the table is empty.

    Args:
        db_session: SQLAlchemy session (Alok provides the DB layer).

    Returns:
        64-character hex hash string.
    """
    from app.db.models import AuditEvent
    last = (
        db_session.query(AuditEvent.record_hash)
        .order_by(AuditEvent.seq.desc())
        .first()
    )
    if last is None:
        return GENESIS_PREV_HASH
    return last.record_hash


def get_next_seq(db_session: Any) -> int:
    """
    Get the next sequence number for a new audit event.
    PostgreSQL BIGSERIAL handles this automatically on INSERT,
    but this is useful for building the record before insertion.

    In practice, Alok lets the DB auto-increment seq.
    This helper is for in-memory chain construction in tests.
    """
    from app.db.models import AuditEvent
    result = db_session.query(AuditEvent.seq).order_by(AuditEvent.seq.desc()).first()
    if result is None:
        return 1
    return result.seq + 1


# ---------------------------------------------------------------------------
# Persist audit record
# ---------------------------------------------------------------------------

def persist_audit_record(db_session: Any, record: dict[str, Any]) -> None:
    """
    Persist a single audit record to PostgreSQL.
    Alok calls this after every security event.

    Args:
        db_session: SQLAlchemy session.
        record:     Dict from build_audit_record() (already has record_hash).

    Raises:
        Exception: If DB write fails. Caller logs and continues (see module docstring).
    """
    from app.db.models import AuditEvent
    import uuid
    from datetime import datetime, timezone

    ts = record.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            ts = datetime.now(timezone.utc)

    event = AuditEvent(
        event_id      = record.get("event_id", str(uuid.uuid4())),
        timestamp     = ts,
        event_type    = record["event_type"],
        tenant_id     = record["tenant_id"],
        principal_id  = record.get("principal_id"),
        action_digest = record.get("action_digest"),
        jti           = record.get("jti"),
        execution_id  = record.get("execution_id"),
        approval_id   = record.get("approval_id"),
        prev_hash     = record["prev_hash"],
        record_hash   = record["record_hash"],
        extra         = record.get("extra"),
    )
    db_session.add(event)
    # Caller is responsible for db_session.commit()
