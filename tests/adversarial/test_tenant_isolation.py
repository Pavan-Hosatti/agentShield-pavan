"""
AgentShield V2 — A5: Identity Spoof and Cross-Tenant Tests

Invariant tested: I8 — Cross-tenant access is denied.

Attacks:
- Agent submits request body with forged principal_id or tenant_id
- Agent requests resource owned by different tenant

Expected: Gateway resolves identity from credentials, not body → 403

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.schemas import ActionEnvelope
from app.security.canonicalization import calculate_action_digest


# ---------------------------------------------------------------------------
# Unit-level: Verify that digest covers tenant_id
# ---------------------------------------------------------------------------

class TestTenantIsolationDigest:
    """
    Tenant isolation is enforced at multiple layers:
    1. Gateway checks resource ownership (resource must belong to tenant)
    2. Capability binds tenant_id (cannot be changed after issuance)
    3. Executor verifies capability.tenant_id == execution.tenant_id
    4. Digest covers tenant_id (changing it changes the digest)

    These unit tests verify layer 4.
    """

    def test_tenant_id_is_covered_by_digest(self, valid_action):
        """Changing tenant_id must change the action digest."""
        from app.security.canonicalization import calculate_action_digest
        original_digest = calculate_action_digest(valid_action)

        evil_action = ActionEnvelope(
            **{**valid_action.model_dump(), "tenant_id": "tenant-evil"}
        )
        evil_digest = calculate_action_digest(evil_action)
        assert original_digest != evil_digest, \
            "SECURITY FAILURE: tenant_id change did not change the digest"

    def test_canonical_bytes_include_tenant_id(self, valid_action):
        """Canonical bytes must contain the tenant_id."""
        from app.security.canonicalization import canonicalize_action
        canonical = canonicalize_action(valid_action)
        assert b"tenant-demo" in canonical

    def test_spoofed_tenant_produces_different_digest(self):
        """A spoofed tenant action has a different digest — cannot reuse a legitimate capability."""
        legitimate = ActionEnvelope(
            schema_version=1, tenant_id="tenant-demo", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 50000},
            environment="demo", policy_version=3, intent_id="intent-demo-001",
        )
        spoofed = ActionEnvelope(
            schema_version=1, tenant_id="tenant-evil", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 50000},
            environment="demo", policy_version=3, intent_id="intent-demo-001",
        )
        d_legit = calculate_action_digest(legitimate)
        d_spoof = calculate_action_digest(spoofed)
        assert d_legit != d_spoof


# ---------------------------------------------------------------------------
# Unit-level: Policy correctly denies cross-tenant
# ---------------------------------------------------------------------------

class TestCrossTenantPolicy:
    def test_cross_tenant_action_denied_by_policy(self):
        """Policy hard-denies when action.tenant_id != agent.tenant_id."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from unit.test_policy import simulate_policy_decision, make_agent, make_action, make_resource

        result = simulate_policy_decision(
            action=make_action(tenant_id="tenant-evil"),
            agent=make_agent(tenant_id="tenant-demo"),
            resource=make_resource(owner_tenant_id="tenant-demo"),
        )
        assert result["result"] == "deny"
        assert "CROSS_TENANT_ACCESS" in result["reason"]

    def test_resource_not_owned_by_tenant_denied(self):
        """Resource owned by tenant-B must be denied for tenant-A's agent."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from unit.test_policy import simulate_policy_decision, make_agent, make_action, make_resource

        # Use amount < 30000 to reach the resource ownership check
        result = simulate_policy_decision(
            action=make_action(tenant_id="tenant-demo", amount=10000),
            agent=make_agent(tenant_id="tenant-demo"),
            resource=make_resource(owner_tenant_id="tenant-evil"),  # wrong owner
        )
        assert result["result"] == "deny"
        assert "RESOURCE_OWNERSHIP_FAILED" in result["reason"]


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestIdentitySpoofIntegration:
    """
    A5: Identity spoof via body fields.

    Gateway must resolve identity from credential, not request body.
    """

    def test_identity_spoof_in_body_rejected(self, gateway_url, demo_agent_token,
                                               valid_action_data):
        """
        Submit a valid request body but with principal_id and tenant_id
        that differ from the credential-resolved identity.
        Expected: 403 IDENTITY_MISMATCH
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_cross_tenant_resource_rejected(self, gateway_url, demo_agent_token,
                                              valid_action_data):
        """
        Submit a request for a resource owned by a different tenant.
        Expected: 403 RESOURCE_OWNERSHIP_FAILED
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_admin_role_in_body_does_not_elevate(self, gateway_url, demo_agent_token,
                                                   valid_action_data):
        """
        Submitting role='admin' in request body must not grant elevated permissions.
        Expected: field is rejected as unknown (422) or ignored.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")
