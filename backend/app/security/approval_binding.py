"""
AgentShield V2 — Approval Binding and Verification

Owner: Girish (storage integration) | Pavan (protocol specification)

An approval is a security primitive, not a UI event.
It binds the exact action_digest — changing any action parameter
produces a different digest, invalidating the approval.

Invariants:
  I5a: Approval bound to exact action_digest
  I5b: Single-use (consumed flag atomically set at execution)

Protocol: SECURITY_PROTOCOL.md §Step 8 and §Step 11g
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ApprovalVerificationResult:
    valid: bool
    reason: str
    approval_id: Optional[str] = None

    @classmethod
    def ok(cls, approval_id: str) -> "ApprovalVerificationResult":
        return cls(valid=True, reason="OK", approval_id=approval_id)

    @classmethod
    def fail(cls, reason: str) -> "ApprovalVerificationResult":
        return cls(valid=False, reason=reason)


def verify_approval(
    approval: dict[str, Any],
    expected_action_digest: str,
    expected_tenant_id: str,
) -> ApprovalVerificationResult:
    """
    Verify that an approval record is valid for the given execution context.

    This is called by the executor at Step 11g BEFORE atomically consuming.
    The actual consumption (setting consumed=True) must be done atomically
    by the caller in a single PostgreSQL transaction together with the
    execution_records INSERT.

    Args:
        approval:               The approval record from PostgreSQL.
        expected_action_digest: The action_digest of the execution-time action.
        expected_tenant_id:     The tenant_id from the capability.

    Returns:
        ApprovalVerificationResult — always structured, never raises silently.

    Reason codes:
        APPROVAL_ALREADY_CONSUMED
        APPROVAL_REJECTED
        APPROVAL_EXPIRED
        APPROVAL_DIGEST_MISMATCH
        APPROVAL_TENANT_MISMATCH
        APPROVAL_MISSING_FIELDS
    """
    # Check required fields exist
    required = {"approval_id", "action_digest", "tenant_id", "decision",
                "consumed", "expires_at"}
    missing = required - set(approval.keys())
    if missing:
        return ApprovalVerificationResult.fail(
            f"APPROVAL_MISSING_FIELDS: {', '.join(sorted(missing))}"
        )

    # Single-use enforcement
    if approval["consumed"]:
        return ApprovalVerificationResult.fail("APPROVAL_ALREADY_CONSUMED")

    # Decision check
    if approval["decision"] != "approved":
        return ApprovalVerificationResult.fail("APPROVAL_REJECTED")

    # Expiry check
    expires_at = approval["expires_at"]
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except ValueError:
            return ApprovalVerificationResult.fail("APPROVAL_MISSING_FIELDS")

    now = datetime.now(timezone.utc)
    # Ensure timezone-aware comparison
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        return ApprovalVerificationResult.fail("APPROVAL_EXPIRED")

    # Exact digest binding — the core security check
    if approval["action_digest"] != expected_action_digest:
        return ApprovalVerificationResult.fail("APPROVAL_DIGEST_MISMATCH")

    # Tenant binding
    if approval["tenant_id"] != expected_tenant_id:
        return ApprovalVerificationResult.fail("APPROVAL_TENANT_MISMATCH")

    return ApprovalVerificationResult.ok(approval["approval_id"])


def create_approval_request(
    *,
    tenant_id: str,
    intent_id: str,
    action_digest: str,
    approval_type: str,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """
    Build an approval request record for persistence.
    Called by the gateway when OPA returns needs_approval.
    """
    import uuid
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    return {
        "approval_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "intent_id": intent_id,
        "action_digest": action_digest,
        "approval_type": approval_type,
        "decision": None,              # Pending
        "approver_identity": None,     # Set when decision is submitted
        "consumed": False,
        "approval_policy_version": None,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
    }
