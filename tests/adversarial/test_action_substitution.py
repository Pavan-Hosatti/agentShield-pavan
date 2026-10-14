"""
AgentShield V2 — A2: Action Substitution Attack Tests

Invariant tested: I2 — No execution when action digest differs.

Attack: Obtain a valid capability for amount_minor=50000.
        Submit execution request with amount_minor=500000.
Expected: Executor returns 403 DIGEST_MISMATCH; mock tool state unchanged.

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.schemas import ActionEnvelope
from app.security.canonicalization import calculate_action_digest, verify_digest_matches


# ---------------------------------------------------------------------------
# Unit-level digest tests (no services needed)
# These prove that the canonicalization layer correctly detects substitution.
# ---------------------------------------------------------------------------

class TestDigestMismatchDetection:
    """
    These tests run at unit level.
    They prove the crypto layer will catch substitution.
    Full integration (executor rejects) is in TestActionSubstitutionIntegration.
    """

    def test_amount_substitution_changes_digest(self, valid_action, tampered_action,
                                                 valid_action_digest, tampered_action_digest):
        """Changing amount_minor MUST change the digest."""
        assert valid_action_digest != tampered_action_digest, \
            "SECURITY FAILURE: Tampered action produces the same digest as original"

    def test_original_digest_rejects_tampered_action(self, tampered_action, valid_action_digest):
        """verify_digest_matches must return False for tampered action + original digest."""
        result = verify_digest_matches(tampered_action, valid_action_digest)
        assert result is False, \
            "SECURITY FAILURE: verify_digest_matches accepted tampered action with original digest"

    def test_tampered_digest_accepts_tampered_action(self, tampered_action, tampered_action_digest):
        """Control: tampered action matches its own digest."""
        result = verify_digest_matches(tampered_action, tampered_action_digest)
        assert result is True

    @pytest.mark.parametrize("field,new_value", [
        ("resource", "orders/ORDER-999"),
        ("tenant_id", "tenant-evil"),
        ("principal_id", "agent-evil-99"),
        ("intent_id", "intent-different"),
        ("policy_version", 2),
    ])
    def test_any_field_change_invalidates_digest(self, valid_action, valid_action_digest,
                                                  field, new_value):
        """Changing any field in the action envelope must change the digest."""
        data = valid_action.model_dump()
        data[field] = new_value
        # environment enum needs special handling
        if field == "environment":
            pass
        modified_action = ActionEnvelope(**data)
        assert not verify_digest_matches(modified_action, valid_action_digest), \
            f"SECURITY FAILURE: Changing {field} did not invalidate the digest"

    def test_argument_key_addition_changes_digest(self, valid_action_digest):
        """Adding an extra argument field changes the digest."""
        # Extra fields are rejected by schema, so this can't produce a valid ActionEnvelope.
        # The schema (extra='forbid') prevents this attack vector at the schema level.
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ActionEnvelope(
                schema_version=1,
                tenant_id="tenant-demo",
                principal_id="agent-support-01",
                tool="issue_refund",
                resource="orders/ORDER-123",
                arguments={"order_id": "ORDER-123", "amount_minor": 50000, "evil_param": "x"},
                environment="demo",
                policy_version=3,
                intent_id="intent-demo-001",
            )


# ---------------------------------------------------------------------------
# Integration tests (require docker-compose up)
# Gururaj fills in the actual HTTP calls and assertions.
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestActionSubstitutionIntegration:
    """
    A2: Full integration attack test.

    Setup:
    1. Register agent (POST /v1/agents)
    2. Authorize action with amount_minor=50000 (POST /v1/actions/authorize)
       → receive capability token
    3. Modify amount_minor to 500000 in execution request
    4. Submit execution (POST /v1/actions/execute)

    Expected:
    - HTTP 403 with reason_code = DIGEST_MISMATCH
    - Mock tool state unchanged (no refund issued)
    - Execution record does not exist or is in FAILED state
    - Audit event shows EXECUTION_DENIED
    """

    def test_amount_changed_after_authorization(self, gateway_url, demo_agent_token,
                                                 valid_action_data, tampered_action_data):
        """
        OWNER: Gururaj — implement with real HTTP calls to gateway_url.
        This stub defines the contract.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up. Implement in Gururaj's pass.")

    def test_resource_changed_after_authorization(self, gateway_url, demo_agent_token,
                                                   valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_tenant_changed_after_authorization(self, gateway_url, demo_agent_token,
                                                 valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_tool_changed_after_authorization(self, gateway_url, demo_agent_token,
                                               valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")
