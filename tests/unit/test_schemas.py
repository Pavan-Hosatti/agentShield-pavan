"""
AgentShield V2 — Action Schema Validation Tests

Tests that the canonical action schema rejects all invalid inputs
and accepts all valid inputs as specified in ACTION_CONTRACT.md.

Owner: Pavan (test design) | Alok (schema implementation)
"""

import pytest
from pydantic import ValidationError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.schemas import ActionEnvelope, ExecutionState, ApprovalDecision


# ─── Valid action fixture ─────────────────────────────────────────────────────

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


def make_action(**overrides):
    """Return a valid action dict with optional field overrides."""
    data = {**VALID_ACTION}
    data.update(overrides)
    return data


# ─── Happy path ───────────────────────────────────────────────────────────────

class TestValidAction:
    def test_valid_action_parses_successfully(self):
        action = ActionEnvelope(**VALID_ACTION)
        assert action.tenant_id == "tenant-demo"
        assert action.tool == "issue_refund"
        assert action.arguments["amount_minor"] == 50000

    def test_valid_action_all_environments(self):
        for env in ("demo", "staging", "production"):
            action = ActionEnvelope(**make_action(environment=env))
            assert action.environment.value == env

    def test_minimum_valid_amount(self):
        action = ActionEnvelope(**make_action(
            arguments={"order_id": "ORDER-1", "amount_minor": 1}
        ))
        assert action.arguments["amount_minor"] == 1

    def test_policy_version_minimum(self):
        action = ActionEnvelope(**make_action(policy_version=1))
        assert action.policy_version == 1


# ─── Schema version ──────────────────────────────────────────────────────────

class TestSchemaVersion:
    def test_schema_version_2_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ActionEnvelope(**make_action(schema_version=2))
        assert "schema_version" in str(exc_info.value).lower() or "2" in str(exc_info.value)

    def test_schema_version_0_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(schema_version=0))

    def test_schema_version_string_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(schema_version="1"))


# ─── Unknown fields ──────────────────────────────────────────────────────────

class TestUnknownFields:
    def test_unknown_top_level_field_rejected(self):
        """Unknown fields must be rejected (extra='forbid')."""
        with pytest.raises(ValidationError) as exc_info:
            ActionEnvelope(**make_action(injected_field="malicious"))
        assert "extra" in str(exc_info.value).lower() or "injected_field" in str(exc_info.value)

    def test_unknown_nested_argument_field_rejected(self):
        """Unknown fields in arguments must also be rejected."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 50000, "evil_field": "x"}
            ))


# ─── Monetary amounts ─────────────────────────────────────────────────────────

class TestMonetaryAmounts:
    def test_float_amount_rejected(self):
        """Float amounts are never permitted. Must be integer paise."""
        with pytest.raises(ValidationError) as exc_info:
            ActionEnvelope(**make_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 500.00}
            ))
        assert "integer" in str(exc_info.value).lower() or "float" in str(exc_info.value).lower()

    def test_float_as_string_amount_rejected(self):
        """Float-like strings are rejected by integer type validation."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(
                arguments={"order_id": "ORDER-123", "amount_minor": "500.00"}
            ))

    def test_zero_amount_rejected(self):
        """Zero amount is invalid (gt=0 constraint)."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 0}
            ))

    def test_negative_amount_rejected(self):
        """Negative amount is invalid."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(
                arguments={"order_id": "ORDER-123", "amount_minor": -100}
            ))

    def test_large_integer_amount_accepted(self):
        """Large integer amounts are accepted (policy will limit them)."""
        action = ActionEnvelope(**make_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 1000000}
        ))
        assert action.arguments["amount_minor"] == 1000000


# ─── Identifier fields ───────────────────────────────────────────────────────

class TestIdentifierFields:
    def test_tenant_id_leading_whitespace_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(tenant_id=" tenant-demo"))

    def test_tenant_id_trailing_whitespace_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(tenant_id="tenant-demo "))

    def test_principal_id_whitespace_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(principal_id=" agent-support-01"))

    def test_empty_tenant_id_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(tenant_id=""))

    def test_empty_principal_id_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(principal_id=""))


# ─── Tool validation ──────────────────────────────────────────────────────────

class TestToolValidation:
    def test_unknown_tool_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ActionEnvelope(**make_action(tool="wire_transfer"))
        assert "unknown tool" in str(exc_info.value).lower() or "wire_transfer" in str(exc_info.value)

    def test_empty_tool_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(tool=""))


# ─── Environment validation ───────────────────────────────────────────────────

class TestEnvironmentValidation:
    def test_invalid_environment_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(environment="local"))

    def test_uppercase_environment_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**make_action(environment="DEMO"))


# ─── Missing required fields ─────────────────────────────────────────────────

class TestRequiredFields:
    @pytest.mark.parametrize("field", [
        "schema_version", "tenant_id", "principal_id", "tool",
        "resource", "arguments", "environment", "policy_version", "intent_id"
    ])
    def test_missing_required_field_rejected(self, field):
        data = {**VALID_ACTION}
        del data[field]
        with pytest.raises(ValidationError):
            ActionEnvelope(**data)


# ─── ExecutionState enum ─────────────────────────────────────────────────────

class TestExecutionState:
    def test_all_states_defined(self):
        expected = {"ISSUED", "CLAIMED", "RUNNING", "SUCCEEDED", "FAILED_FINAL", "UNKNOWN"}
        actual = {s.value for s in ExecutionState}
        assert actual == expected


# ─── ApprovalDecision enum ───────────────────────────────────────────────────

class TestApprovalDecision:
    def test_decisions_defined(self):
        assert ApprovalDecision.APPROVED.value == "approved"
        assert ApprovalDecision.REJECTED.value == "rejected"
