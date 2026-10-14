"""
AgentShield V2 — A6: Revocation Race Tests

Invariant tested: I6 — Revocation after authorization prevents execution.

Attack: Issue capability for a valid agent. Revoke the agent. Then attempt execution.
Expected: Executor returns 403 AGENT_REVOKED; mock tool state unchanged.

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))


# ---------------------------------------------------------------------------
# Unit-level revocation logic tests
# ---------------------------------------------------------------------------

class TestRevocationPolicyLogic:
    """Test that the policy simulator correctly hard-denies revoked agents."""

    def test_revoked_agent_is_hard_denied(self):
        """Revoked agent must be denied regardless of valid action."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from unit.test_policy import simulate_policy_decision, make_agent, make_action, make_resource

        result = simulate_policy_decision(
            action=make_action(),
            agent=make_agent(revoked=True),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "AGENT_REVOKED" in result["reason"]

    def test_revoked_agent_with_valid_approval_still_denied(self):
        """A revoked agent with a valid approval must still be denied."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from unit.test_policy import simulate_policy_decision, make_agent, make_action, make_resource

        digest = "test-revocation-digest"
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest=digest),
            agent=make_agent(revoked=True),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": digest,
                "tenant_id": "tenant-demo",
                "consumed": False,
                "decision": "approved",
            },
        )
        assert result["result"] == "deny"
        assert "AGENT_REVOKED" in result["reason"]


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestRevocationIntegration:
    """
    A6: Revocation race — capability issued before revocation, execution after.

    Sequence:
    1. Register agent (POST /v1/agents)
    2. Authorize action (POST /v1/actions/authorize) → capability issued
    3. Revoke agent (POST /v1/agents/{id}/revoke)
    4. Attempt execution (POST /v1/actions/execute) with the pre-issued capability

    Expected:
    - Step 4 returns 403 AGENT_REVOKED
    - Mock tool state unchanged
    - Audit event shows EXECUTION_DENIED with reason AGENT_REVOKED
    """

    def test_revocation_between_auth_and_execution(self, gateway_url, demo_agent_token,
                                                     valid_action_data):
        """
        OWNER: Gururaj — implement with real HTTP calls.

        Evidence required:
        - capability issued successfully (200 from authorize)
        - revocation confirmed (200 from revoke endpoint)
        - execution rejected (403 AGENT_REVOKED)
        - mock_tool state unchanged
        - audit event with EXECUTION_DENIED present
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_revoked_agent_cannot_authorize(self, gateway_url, demo_agent_token,
                                              valid_action_data):
        """
        After revocation, the agent must also fail to get new capabilities.
        Expected: 403 AGENT_REVOKED from the authorize endpoint.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_revocation_is_durable_after_redis_restart(self, gateway_url, demo_agent_token,
                                                         valid_action_data):
        """
        Revocation is stored in PostgreSQL. Even if Redis is cleared,
        the executor must still check PG and deny the revoked agent.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")
