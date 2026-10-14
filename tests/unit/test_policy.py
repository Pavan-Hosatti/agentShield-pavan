"""
AgentShield V2 — OPA Policy Logic Unit Tests

Tests the policy decision rules WITHOUT running the OPA server.
We test the Rego logic by simulating the inputs and checking expected outputs.
These tests validate that the policy spec (SECURITY_PROTOCOL.md §6) is correct.

For integration tests against the live OPA server, see tests/integration/test_opa_integration.py

Owner: Pavan
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Policy decision helper
# We replicate the OPA decision logic in Python to unit-test the rules
# independently before OPA is running.
# Alok's OPA integration must produce the same results for these inputs.
# ---------------------------------------------------------------------------

def simulate_policy_decision(
    action: dict,
    agent: dict,
    resource: dict | None = None,
    approval: dict | None = None,
) -> dict:
    """
    Simulate the OPA policy decision.

    This mirrors the Rego logic in policy/agentshield.rego.
    Used to verify the policy specification is self-consistent.

    Args:
        action: Action envelope fields (tool, arguments, tenant_id, etc.)
        agent: Agent record (registered, revoked, tenant_id, permitted_tools)
        resource: Resource ownership (owner_tenant_id)
        approval: Approval record for needs_approval cases

    Returns:
        dict with 'result': 'allow' | 'deny' | 'needs_approval'
        and 'reason': string
    """
    hard_denies = []

    # --- Hard deny checks (mirror Rego hard_deny rules) ---

    if not agent.get("registered", False):
        hard_denies.append("AGENT_NOT_REGISTERED")

    if agent.get("revoked", False):
        hard_denies.append("AGENT_REVOKED")

    if action.get("tenant_id") != agent.get("tenant_id"):
        hard_denies.append("CROSS_TENANT_ACCESS")

    permitted_tools = agent.get("permitted_tools", [])
    if action.get("tool") not in permitted_tools:
        hard_denies.append("TOOL_NOT_PERMITTED")

    valid_envs = {"demo", "staging", "production"}
    if action.get("environment") not in valid_envs:
        hard_denies.append("INVALID_ENVIRONMENT")

    if action.get("policy_version", 0) < 2:
        hard_denies.append("POLICY_VERSION_STALE")

    # Hard max for refund (no approval can override)
    if action.get("tool") == "issue_refund":
        amount = action.get("arguments", {}).get("amount_minor", 0)
        if amount > 1_000_000:
            hard_denies.append("AMOUNT_EXCEEDS_HARD_MAXIMUM")

    if hard_denies:
        return {"result": "deny", "reason": ", ".join(hard_denies)}

    # --- Needs approval check ---
    if action.get("tool") == "issue_refund":
        amount = action.get("arguments", {}).get("amount_minor", 0)
        if 30_000 <= amount <= 1_000_000:
            # Check if a valid approval is provided
            if approval and approval.get("valid") and \
               approval.get("action_digest") == action.get("action_digest") and \
               approval.get("tenant_id") == action.get("tenant_id") and \
               not approval.get("consumed") and \
               approval.get("decision") == "approved":
                # Approval present and valid — proceed to allow check
                pass
            else:
                return {
                    "result": "needs_approval",
                    "approval_type": "manager_approval",
                    "reason": "APPROVAL_REQUIRED_FOR_AMOUNT",
                }

    # --- Resource ownership check ---
    if resource and resource.get("owner_tenant_id") != action.get("tenant_id"):
        return {"result": "deny", "reason": "RESOURCE_OWNERSHIP_FAILED"}

    # --- Allow ---
    if action.get("tool") == "issue_refund":
        amount = action.get("arguments", {}).get("amount_minor", 0)
        if amount > 0:
            return {"result": "allow", "reason": "POLICY_ALLOW"}

    return {"result": "deny", "reason": "DEFAULT_DENY"}


# ---------------------------------------------------------------------------
# Default fixtures used across tests
# ---------------------------------------------------------------------------

def make_agent(registered=True, revoked=False, tenant_id="tenant-demo",
               permitted_tools=None) -> dict:
    return {
        "registered": registered,
        "revoked": revoked,
        "tenant_id": tenant_id,
        "permitted_tools": permitted_tools or ["issue_refund"],
    }


def make_action(tool="issue_refund", amount=50000, tenant_id="tenant-demo",
                environment="demo", policy_version=3,
                action_digest="abc123") -> dict:
    return {
        "tool": tool,
        "tenant_id": tenant_id,
        "environment": environment,
        "policy_version": policy_version,
        "action_digest": action_digest,
        "arguments": {"amount_minor": amount},
    }


def make_resource(owner_tenant_id="tenant-demo") -> dict:
    return {"owner_tenant_id": owner_tenant_id}


# ---------------------------------------------------------------------------
# Test: Allow rules
# ---------------------------------------------------------------------------

class TestAllowRules:
    def test_valid_small_refund_allowed(self):
        """A valid refund under 30000 paise is allowed without approval."""
        result = simulate_policy_decision(
            action=make_action(amount=29999),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "allow", result

    def test_minimum_amount_allowed(self):
        """1 paise is the minimum valid amount."""
        result = simulate_policy_decision(
            action=make_action(amount=1),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "allow"

    def test_exactly_29999_allowed_without_approval(self):
        """29999 is just below the approval threshold."""
        result = simulate_policy_decision(
            action=make_action(amount=29999),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "allow"


# ---------------------------------------------------------------------------
# Test: Needs approval rules
# ---------------------------------------------------------------------------

class TestNeedsApprovalRules:
    def test_exactly_30000_needs_approval(self):
        """30000 paise is the approval threshold."""
        result = simulate_policy_decision(
            action=make_action(amount=30000),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "needs_approval"
        assert result["reason"] == "APPROVAL_REQUIRED_FOR_AMOUNT"

    def test_40000_needs_approval(self):
        """Standard approval-required test case (₹400)."""
        result = simulate_policy_decision(
            action=make_action(amount=40000),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "needs_approval"

    def test_1000000_needs_approval(self):
        """At the hard maximum boundary, approval is still required (not hard-deny)."""
        result = simulate_policy_decision(
            action=make_action(amount=1_000_000),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "needs_approval"

    def test_approval_required_with_valid_approval_allows(self):
        """With a valid approval, an amount ≥ 30000 should be allowed."""
        digest = "test-digest-abc"
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest=digest),
            agent=make_agent(),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": digest,
                "tenant_id": "tenant-demo",
                "consumed": False,
                "decision": "approved",
            },
        )
        assert result["result"] == "allow", result

    def test_approval_wrong_digest_still_needs_approval(self):
        """Approval with wrong action digest does not unlock execution."""
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest="correct-digest"),
            agent=make_agent(),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": "WRONG-digest",  # mismatch
                "tenant_id": "tenant-demo",
                "consumed": False,
                "decision": "approved",
            },
        )
        assert result["result"] == "needs_approval"

    def test_consumed_approval_still_needs_approval(self):
        """A consumed approval cannot be reused."""
        digest = "test-digest-abc"
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest=digest),
            agent=make_agent(),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": digest,
                "tenant_id": "tenant-demo",
                "consumed": True,  # already consumed
                "decision": "approved",
            },
        )
        assert result["result"] == "needs_approval"

    def test_rejected_approval_still_needs_approval(self):
        """A rejected approval cannot authorize execution."""
        digest = "test-digest-abc"
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest=digest),
            agent=make_agent(),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": digest,
                "tenant_id": "tenant-demo",
                "consumed": False,
                "decision": "rejected",  # rejected
            },
        )
        assert result["result"] == "needs_approval"

    def test_wrong_tenant_approval_still_needs_approval(self):
        """Approval from another tenant does not authorize this tenant's action."""
        digest = "test-digest-abc"
        result = simulate_policy_decision(
            action=make_action(amount=40000, action_digest=digest, tenant_id="tenant-demo"),
            agent=make_agent(),
            resource=make_resource(),
            approval={
                "valid": True,
                "action_digest": digest,
                "tenant_id": "tenant-evil",  # wrong tenant
                "consumed": False,
                "decision": "approved",
            },
        )
        assert result["result"] == "needs_approval"


# ---------------------------------------------------------------------------
# Test: Hard deny rules
# ---------------------------------------------------------------------------

class TestHardDenyRules:
    def test_unregistered_agent_denied(self):
        """Unregistered agent must be hard-denied."""
        result = simulate_policy_decision(
            action=make_action(),
            agent=make_agent(registered=False),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "AGENT_NOT_REGISTERED" in result["reason"]

    def test_revoked_agent_denied(self):
        """Revoked agent must be hard-denied regardless of other conditions."""
        result = simulate_policy_decision(
            action=make_action(),
            agent=make_agent(revoked=True),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "AGENT_REVOKED" in result["reason"]

    def test_cross_tenant_action_denied(self):
        """Action tenant_id != agent tenant_id must be denied."""
        result = simulate_policy_decision(
            action=make_action(tenant_id="tenant-evil"),
            agent=make_agent(tenant_id="tenant-demo"),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "CROSS_TENANT_ACCESS" in result["reason"]

    def test_unpermitted_tool_denied(self):
        """Tool not in agent's permitted_tools must be denied."""
        result = simulate_policy_decision(
            action=make_action(tool="wire_transfer"),
            agent=make_agent(permitted_tools=["issue_refund"]),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "TOOL_NOT_PERMITTED" in result["reason"]

    def test_invalid_environment_denied(self):
        """Unknown environment must be hard-denied."""
        result = simulate_policy_decision(
            action=make_action(environment="local"),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "INVALID_ENVIRONMENT" in result["reason"]

    def test_stale_policy_version_denied(self):
        """Policy version < 2 must be hard-denied."""
        result = simulate_policy_decision(
            action=make_action(policy_version=1),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "POLICY_VERSION_STALE" in result["reason"]

    def test_amount_exceeds_hard_maximum_denied(self):
        """Amount > 1,000,000 paise is hard-denied. No approval can override."""
        result = simulate_policy_decision(
            action=make_action(amount=2_000_000),
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "deny"
        assert "AMOUNT_EXCEEDS_HARD_MAXIMUM" in result["reason"]

    def test_hard_deny_not_overridden_by_approval(self):
        """
        CRITICAL (I3): A hard-denied action must not receive an executable capability
        even when a valid approval is provided.
        """
        digest = "test-digest-hard-deny"
        result = simulate_policy_decision(
            action=make_action(amount=2_000_000, action_digest=digest),
            agent=make_agent(),
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
        assert "AMOUNT_EXCEEDS_HARD_MAXIMUM" in result["reason"]

    def test_revoked_agent_not_overridden_by_approval(self):
        """Revocation is a hard-deny. Approval cannot override it."""
        digest = "test-digest-revoked"
        result = simulate_policy_decision(
            action=make_action(action_digest=digest),
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
# Test: Resource ownership
# ---------------------------------------------------------------------------

class TestResourceOwnership:
    def test_correct_tenant_resource_allowed(self):
        # Use amount < 30000 to stay below the approval threshold and reach the allow path
        result = simulate_policy_decision(
            action=make_action(tenant_id="tenant-demo", amount=10000),
            agent=make_agent(tenant_id="tenant-demo"),
            resource=make_resource(owner_tenant_id="tenant-demo"),
        )
        assert result["result"] == "allow"

    def test_cross_tenant_resource_denied(self):
        """Tenant-A agent requesting tenant-B resource must be denied."""
        # Use amount < 30000 to reach the resource check (no early needs_approval)
        result = simulate_policy_decision(
            action=make_action(tenant_id="tenant-demo", amount=10000),
            agent=make_agent(tenant_id="tenant-demo"),
            resource=make_resource(owner_tenant_id="tenant-evil"),
        )
        assert result["result"] == "deny"
        assert "RESOURCE_OWNERSHIP_FAILED" in result["reason"]


# ---------------------------------------------------------------------------
# Test: Default deny
# ---------------------------------------------------------------------------

class TestDefaultDeny:
    def test_no_matching_rule_denies(self):
        """
        With a tool that doesn't match any allow rule and no hard_deny,
        result must be deny (default-deny).
        The simulate_policy_decision returns DEFAULT_DENY in this path.
        """
        # Tool is in permitted_tools but has no allow rule in policy
        result = simulate_policy_decision(
            action={
                "tool": "issue_refund",
                "tenant_id": "tenant-demo",
                "environment": "demo",
                "policy_version": 3,
                "action_digest": "x",
                "arguments": {"amount_minor": 0},  # 0 → no allow rule fires
            },
            agent=make_agent(),
            resource=make_resource(),
        )
        assert result["result"] == "deny"


# ---------------------------------------------------------------------------
# Test: Policy invariant I3 — comprehensive
# ---------------------------------------------------------------------------

class TestInvariantI3:
    """
    I3: No hard-denied action receives an executable capability.
    Tests all hard-deny conditions.
    """

    @pytest.mark.parametrize("setup,expected_reason", [
        ({"agent": make_agent(registered=False)}, "AGENT_NOT_REGISTERED"),
        ({"agent": make_agent(revoked=True)}, "AGENT_REVOKED"),
        ({"action_overrides": {"environment": "local"}}, "INVALID_ENVIRONMENT"),
        ({"action_overrides": {"policy_version": 1}}, "POLICY_VERSION_STALE"),
        ({"action_overrides": {"arguments": {"amount_minor": 9_999_999}}}, "AMOUNT_EXCEEDS_HARD_MAXIMUM"),
    ])
    def test_hard_deny_conditions(self, setup, expected_reason):
        agent = setup.get("agent", make_agent())
        action_overrides = setup.get("action_overrides", {})
        action = {**make_action(), **action_overrides}
        # Merge arguments properly
        if "arguments" in action_overrides:
            action["arguments"] = action_overrides["arguments"]

        result = simulate_policy_decision(
            action=action,
            agent=agent,
            resource=make_resource(),
        )
        assert result["result"] == "deny", f"Expected deny, got {result}"
        assert expected_reason in result["reason"], \
            f"Expected {expected_reason!r} in {result['reason']!r}"
