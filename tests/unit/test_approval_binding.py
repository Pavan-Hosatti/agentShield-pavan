"""
AgentShield V2 — Approval Binding Tests

Owner: Pavan

Tests the approval verification logic end-to-end.
Every failure mode from SECURITY_PROTOCOL.md §Step 11g must be covered.
"""
from __future__ import annotations

import pytest
import sys, os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.approval_binding import (
    verify_approval,
    create_approval_request,
    ApprovalVerificationResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_DIGEST  = "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"
TAMPERED_DIGEST = "ae72f0c9106d392e8533feb5fff153e29b9ba0686ed7d0216e2d1710aab56b28"

def fresh_approval(
    action_digest: str = VALID_DIGEST,
    tenant_id: str = "tenant-demo",
    decision: str = "approved",
    consumed: bool = False,
    hours_until_expiry: float = 1.0,
) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "approval_id": "approval-test-001",
        "tenant_id": tenant_id,
        "intent_id": "intent-demo-001",
        "action_digest": action_digest,
        "approver_identity": "approver-manager-01",
        "decision": decision,
        "consumed": consumed,
        "approval_policy_version": 3,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=hours_until_expiry)).isoformat(),
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestApprovalVerificationHappyPath:
    def test_valid_approval_is_accepted(self):
        result = verify_approval(
            fresh_approval(),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is True
        assert result.reason == "OK"
        assert result.approval_id == "approval-test-001"

    def test_returns_approval_id_on_success(self):
        result = verify_approval(
            fresh_approval(),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.approval_id is not None


# ---------------------------------------------------------------------------
# Single-use enforcement (I5b)
# ---------------------------------------------------------------------------

class TestApprovalSingleUse:
    def test_consumed_approval_rejected(self):
        """I5b: A consumed approval must never authorize another execution."""
        result = verify_approval(
            fresh_approval(consumed=True),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_ALREADY_CONSUMED"

    def test_consumed_check_runs_before_digest_check(self):
        """Consumed check runs first — consumed approval rejected even with wrong digest."""
        result = verify_approval(
            fresh_approval(consumed=True, action_digest=TAMPERED_DIGEST),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_ALREADY_CONSUMED"


# ---------------------------------------------------------------------------
# Digest binding (I5a)
# ---------------------------------------------------------------------------

class TestApprovalDigestBinding:
    def test_wrong_digest_rejected(self):
        """I5a: Approval for one action cannot authorize another action."""
        result = verify_approval(
            fresh_approval(action_digest=TAMPERED_DIGEST),  # approval for tampered amount
            expected_action_digest=VALID_DIGEST,            # executing original action
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_DIGEST_MISMATCH"

    def test_exact_digest_match_required(self):
        """Even a one-character difference must cause rejection."""
        near_match = VALID_DIGEST[:-1] + ("a" if VALID_DIGEST[-1] != "a" else "b")
        result = verify_approval(
            fresh_approval(action_digest=near_match),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_DIGEST_MISMATCH"


# ---------------------------------------------------------------------------
# Decision validation
# ---------------------------------------------------------------------------

class TestApprovalDecision:
    def test_rejected_decision_not_accepted(self):
        """A rejected approval cannot authorize execution."""
        result = verify_approval(
            fresh_approval(decision="rejected"),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_REJECTED"

    def test_pending_decision_not_accepted(self):
        """A pending approval (not yet decided) cannot authorize execution."""
        result = verify_approval(
            fresh_approval(decision="pending"),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_REJECTED"


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

class TestApprovalExpiry:
    def test_expired_approval_rejected(self):
        """Expired approval must be rejected."""
        result = verify_approval(
            fresh_approval(hours_until_expiry=-1),  # expired 1 hour ago
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_EXPIRED"

    def test_just_expired_approval_rejected(self):
        """An approval that expired right now must be rejected."""
        result = verify_approval(
            fresh_approval(hours_until_expiry=-0.0001),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_EXPIRED"

    def test_not_yet_expired_approval_accepted(self):
        """An approval that expires in 1 second must be accepted."""
        result = verify_approval(
            fresh_approval(hours_until_expiry=0.001),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is True


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

class TestApprovalTenantBinding:
    def test_wrong_tenant_approval_rejected(self):
        """An approval from tenant-evil cannot authorize tenant-demo's action."""
        result = verify_approval(
            fresh_approval(tenant_id="tenant-evil"),
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",  # executing as tenant-demo
        )
        assert result.valid is False
        assert result.reason == "APPROVAL_TENANT_MISMATCH"


# ---------------------------------------------------------------------------
# Missing fields
# ---------------------------------------------------------------------------

class TestApprovalMissingFields:
    @pytest.mark.parametrize("missing_field", [
        "approval_id", "action_digest", "tenant_id", "decision",
        "consumed", "expires_at",
    ])
    def test_missing_required_field_rejected(self, missing_field):
        """Any missing required field must cause a structured failure."""
        approval = fresh_approval()
        del approval[missing_field]
        result = verify_approval(
            approval,
            expected_action_digest=VALID_DIGEST,
            expected_tenant_id="tenant-demo",
        )
        assert result.valid is False
        assert "APPROVAL_MISSING_FIELDS" in result.reason


# ---------------------------------------------------------------------------
# Approval request builder
# ---------------------------------------------------------------------------

class TestCreateApprovalRequest:
    def test_creates_pending_approval_request(self):
        req = create_approval_request(
            tenant_id="tenant-demo",
            intent_id="intent-001",
            action_digest=VALID_DIGEST,
            approval_type="manager_approval",
        )
        assert req["decision"] is None  # Pending
        assert req["consumed"] is False
        assert req["action_digest"] == VALID_DIGEST
        assert req["tenant_id"] == "tenant-demo"
        assert req["approval_id"] is not None

    def test_approval_request_has_expiry(self):
        req = create_approval_request(
            tenant_id="tenant-demo",
            intent_id="intent-001",
            action_digest=VALID_DIGEST,
            approval_type="manager_approval",
            ttl_seconds=3600,
        )
        from datetime import datetime, timezone
        expires = datetime.fromisoformat(req["expires_at"])
        now = datetime.now(timezone.utc)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        assert expires > now

    def test_two_approval_requests_have_different_ids(self):
        req1 = create_approval_request(
            tenant_id="t", intent_id="i", action_digest="d", approval_type="a"
        )
        req2 = create_approval_request(
            tenant_id="t", intent_id="i", action_digest="d", approval_type="a"
        )
        assert req1["approval_id"] != req2["approval_id"]
