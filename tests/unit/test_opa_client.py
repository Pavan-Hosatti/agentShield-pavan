"""
AgentShield V2 — OPA Client Unit Tests

Owner: Pavan

Tests the OPA input builder and decision parsing without a live OPA server.
Integration tests against the real OPA server go in tests/integration/.
"""
from __future__ import annotations

import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.policy.opa_client import (
    build_opa_input,
    PolicyDecision,
    PolicyResult,
    PolicyCheckUnavailable,
)


# ---------------------------------------------------------------------------
# Input builder
# ---------------------------------------------------------------------------

VALID_ACTION = {
    "schema_version": 1,
    "tenant_id": "tenant-demo",
    "principal_id": "agent-support-01",
    "tool": "issue_refund",
    "resource": "orders/ORDER-123",
    "arguments": {"order_id": "ORDER-123", "amount_minor": 50000},
    "environment": "demo",
    "policy_version": 3,
    "intent_id": "intent-demo-001",
}

VALID_AGENT = {
    "registered": True,
    "revoked": False,
    "tenant_id": "tenant-demo",
    "permitted_tools": ["issue_refund"],
    "max_amount_minor": None,
}

VALID_RESOURCE = {"owner_tenant_id": "tenant-demo"}
VALID_DIGEST   = "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"


class TestBuildOpaInput:
    def test_builds_valid_input(self):
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
        )
        assert "action" in inp
        assert "agent" in inp
        assert "resource" in inp
        assert inp["action"]["action_digest"] == VALID_DIGEST

    def test_action_digest_is_embedded(self):
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
        )
        assert inp["action"]["action_digest"] == VALID_DIGEST

    def test_approval_included_when_provided(self):
        approval = {
            "action_digest": VALID_DIGEST, "tenant_id": "tenant-demo",
            "consumed": False, "decision": "approved",
        }
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
            approval=approval,
        )
        assert "approval" in inp
        assert inp["approval"]["valid"] is True

    def test_consumed_approval_is_not_valid(self):
        approval = {
            "action_digest": VALID_DIGEST, "tenant_id": "tenant-demo",
            "consumed": True, "decision": "approved",
        }
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
            approval=approval,
        )
        assert inp["approval"]["valid"] is False

    def test_rejected_approval_is_not_valid(self):
        approval = {
            "action_digest": VALID_DIGEST, "tenant_id": "tenant-demo",
            "consumed": False, "decision": "rejected",
        }
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
            approval=approval,
        )
        assert inp["approval"]["valid"] is False

    def test_no_approval_field_when_none(self):
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
        )
        assert "approval" not in inp

    def test_revoked_agent_correctly_embedded(self):
        revoked_agent = {**VALID_AGENT, "revoked": True}
        inp = build_opa_input(
            action=VALID_ACTION, agent=revoked_agent,
            resource=VALID_RESOURCE, action_digest=VALID_DIGEST,
        )
        assert inp["agent"]["revoked"] is True

    def test_cross_tenant_resource_embedded(self):
        evil_resource = {"owner_tenant_id": "tenant-evil"}
        inp = build_opa_input(
            action=VALID_ACTION, agent=VALID_AGENT,
            resource=evil_resource, action_digest=VALID_DIGEST,
        )
        assert inp["resource"]["owner_tenant_id"] == "tenant-evil"


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------

class TestPolicyDecision:
    def test_allow_decision(self):
        d = PolicyDecision(result=PolicyResult.ALLOW, reason="POLICY_ALLOW")
        assert d.is_allowed
        assert not d.is_denied
        assert not d.needs_approval

    def test_deny_decision(self):
        d = PolicyDecision(result=PolicyResult.DENY, reason="HARD_DENY")
        assert d.is_denied
        assert not d.is_allowed
        assert not d.needs_approval

    def test_needs_approval_decision(self):
        d = PolicyDecision(
            result=PolicyResult.NEEDS_APPROVAL,
            reason="APPROVAL_REQUIRED_FOR_AMOUNT",
            approval_type="manager_approval",
        )
        assert d.needs_approval
        assert not d.is_allowed
        assert not d.is_denied
        assert d.approval_type == "manager_approval"

    def test_policy_result_enum_values(self):
        assert PolicyResult.ALLOW.value == "allow"
        assert PolicyResult.DENY.value == "deny"
        assert PolicyResult.NEEDS_APPROVAL.value == "needs_approval"


# ---------------------------------------------------------------------------
# Error response structure
# ---------------------------------------------------------------------------

class TestErrorResponses:
    def test_error_response_has_required_fields(self):
        from app.api.errors import error_response, ReasonCode
        resp = error_response(ReasonCode.DIGEST_MISMATCH, "amounts differ")
        assert "request_id" in resp
        assert "trace_id" in resp
        assert "reason" in resp
        assert resp["reason"] == "DIGEST_MISMATCH"

    def test_success_response_has_required_fields(self):
        from app.api.errors import success_response
        resp = success_response({"key": "value"})
        assert "request_id" in resp
        assert "trace_id" in resp
        assert "data" in resp
        assert resp["data"]["key"] == "value"

    def test_all_reason_codes_are_strings(self):
        from app.api.errors import ReasonCode
        for attr in dir(ReasonCode):
            if attr.startswith("_"):
                continue
            val = getattr(ReasonCode, attr)
            if isinstance(val, str):
                assert val == val.upper(), f"{attr} should be UPPER_SNAKE_CASE"
