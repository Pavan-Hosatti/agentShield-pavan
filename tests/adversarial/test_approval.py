"""
AgentShield V2 — A4: Approval Replay and Approval Binding Tests

Invariants tested:
  I5a — Required approval is bound to the exact action
  I5b — Approval cannot be reused (single-use)

Attacks:
  - Present an approval for action A when executing action B (wrong digest)
  - Reuse a consumed approval for a second execution
  - Present an expired approval
  - Present a rejected approval

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))


# ---------------------------------------------------------------------------
# Unit-level approval binding verification
# ---------------------------------------------------------------------------

class TestApprovalBindingUnit:
    """
    Verify that approval validation logic correctly checks digest binding.
    These tests use the fixtures from conftest.py.
    """

    def test_valid_approval_matches_action(self, valid_approval_record, valid_action_digest):
        """A valid approval should have the correct action_digest."""
        assert valid_approval_record["action_digest"] == valid_action_digest
        assert valid_approval_record["consumed"] is False
        assert valid_approval_record["decision"] == "approved"

    def test_consumed_approval_is_flagged(self, consumed_approval_record):
        """Consumed approval must have consumed=True."""
        assert consumed_approval_record["consumed"] is True

    def test_expired_approval_is_past_expiry(self, expired_approval_record):
        """Expired approval must have expires_at in the past."""
        from datetime import datetime, timezone
        exp = datetime.fromisoformat(expired_approval_record["expires_at"])
        now = datetime.now(timezone.utc)
        assert exp < now, "Expired approval fixture must have a past expiry"

    def test_wrong_digest_approval_record(self, wrong_digest_approval_record,
                                           valid_action_digest, tampered_action_digest):
        """Wrong digest approval has a different digest than the original action."""
        assert wrong_digest_approval_record["action_digest"] != valid_action_digest
        assert wrong_digest_approval_record["action_digest"] == tampered_action_digest

    def test_approval_digest_binding_logic(self, valid_approval_record,
                                            valid_action_digest, tampered_action_digest):
        """
        Simulate the executor's approval verification logic.
        Approval is valid only if: action_digest matches AND not consumed AND not expired AND decision=approved.
        """
        from datetime import datetime, timezone

        def verify_approval(approval: dict, execution_digest: str) -> tuple[bool, str]:
            """Mimics the executor's approval check."""
            if approval["consumed"]:
                return False, "APPROVAL_ALREADY_CONSUMED"
            if approval["decision"] != "approved":
                return False, "APPROVAL_REJECTED"
            exp = datetime.fromisoformat(approval["expires_at"])
            if exp < datetime.now(timezone.utc):
                return False, "APPROVAL_EXPIRED"
            if approval["action_digest"] != execution_digest:
                return False, "APPROVAL_DIGEST_MISMATCH"
            return True, "OK"

        # Valid approval for correct action
        ok, reason = verify_approval(valid_approval_record, valid_action_digest)
        assert ok is True, f"Expected OK, got {reason}"

        # Valid approval for tampered action (wrong digest)
        ok, reason = verify_approval(valid_approval_record, tampered_action_digest)
        assert ok is False
        assert reason == "APPROVAL_DIGEST_MISMATCH"

        # Consumed approval
        ok, reason = verify_approval({**valid_approval_record, "consumed": True}, valid_action_digest)
        assert ok is False
        assert reason == "APPROVAL_ALREADY_CONSUMED"

        # Rejected approval
        ok, reason = verify_approval({**valid_approval_record, "decision": "rejected"}, valid_action_digest)
        assert ok is False
        assert reason == "APPROVAL_REJECTED"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestApprovalIntegration:
    """
    A4: Approval replay and binding tests against live services.
    """

    def test_approval_wrong_amount_rejected(self, gateway_url, demo_agent_token,
                                             valid_action_data, tampered_action_data):
        """
        Obtain approval for amount_minor=50000.
        Attempt execution with amount_minor=500000.
        Expected: 403 APPROVAL_INVALID (digest mismatch).
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_approval_wrong_resource_rejected(self, gateway_url, demo_agent_token,
                                               valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_approval_wrong_tenant_rejected(self, gateway_url, demo_agent_token):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_expired_approval_rejected(self, gateway_url, demo_agent_token,
                                        valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_rejected_approval_not_accepted(self, gateway_url, demo_agent_token,
                                             valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_concurrent_approval_consumption(self, gateway_url, demo_agent_token,
                                               approval_required_action_data):
        """
        Concurrent execution attempts with the same approval.
        At most one should succeed; others get 403 APPROVAL_ALREADY_CONSUMED.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")
