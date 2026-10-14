"""
AgentShield V3 — Delegation Rule Tests
Owner: Pavan

Every delegation attack vector has a test.
"""
import time
import pytest
from core.delegation import (
    Scope, validate_delegation, MAX_DELEGATION_DEPTH, print_delegation_rules,
)


def make_parent(**overrides) -> Scope:
    now = time.time()
    defaults = dict(
        tools=["issue_refund"],
        max_amount_minor=50000,
        environments=["demo"],
        tenant_id="tenant-demo",
        policy_version=3,
        expires_at=now + 300,
        delegation_depth=0,
    )
    defaults.update(overrides)
    return Scope(**defaults)


def make_child(parent: Scope, **overrides) -> Scope:
    now = time.time()
    defaults = dict(
        tools=list(parent.tools),
        max_amount_minor=parent.max_amount_minor - 1,
        environments=list(parent.environments),
        tenant_id=parent.tenant_id,
        policy_version=parent.policy_version,
        expires_at=now + 120,
        delegation_depth=0,
    )
    defaults.update(overrides)
    return Scope(**defaults)


class TestValidDelegation:
    def test_valid_subset_allowed(self):
        parent = make_parent()
        child = make_child(parent)
        result = validate_delegation(parent, child)
        assert result.allowed
        assert result.child_scope is not None

    def test_child_scope_clamped_to_parent(self):
        parent = make_parent(max_amount_minor=50000)
        child = make_child(parent, max_amount_minor=29999)
        result = validate_delegation(parent, child)
        assert result.allowed
        assert result.child_scope is not None
        assert result.child_scope.max_amount_minor <= parent.max_amount_minor

    def test_child_depth_incremented(self):
        parent = make_parent(delegation_depth=0)
        child = make_child(parent)
        result = validate_delegation(parent, child)
        assert result.child_scope is not None
        assert result.child_scope.delegation_depth == 1


class TestToolEscalation:
    def test_extra_tool_denied(self):
        parent = make_parent(tools=["issue_refund"])
        child = make_child(parent, tools=["issue_refund", "wire_transfer"])
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R1" in v for v in result.violations)

    def test_same_tools_allowed(self):
        parent = make_parent(tools=["issue_refund"])
        child = make_child(parent, tools=["issue_refund"])
        result = validate_delegation(parent, child)
        assert result.allowed

    def test_subset_tools_allowed(self):
        parent = make_parent(tools=["issue_refund", "get_order"])
        child = make_child(parent, tools=["issue_refund"])  # subset
        result = validate_delegation(parent, child)
        assert result.allowed


class TestAmountEscalation:
    def test_higher_amount_denied(self):
        parent = make_parent(max_amount_minor=50000)
        child = make_child(parent, max_amount_minor=999999)
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R2" in v for v in result.violations)

    def test_equal_amount_allowed(self):
        parent = make_parent(max_amount_minor=50000)
        child = make_child(parent, max_amount_minor=50000)
        result = validate_delegation(parent, child)
        assert result.allowed

    def test_lower_amount_allowed(self):
        parent = make_parent(max_amount_minor=50000)
        child = make_child(parent, max_amount_minor=1000)
        result = validate_delegation(parent, child)
        assert result.allowed


class TestTenantBinding:
    def test_different_tenant_denied(self):
        parent = make_parent(tenant_id="tenant-demo")
        child = make_child(parent, tenant_id="tenant-evil")
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R4" in v for v in result.violations)


class TestTTLEscalation:
    def test_longer_ttl_denied(self):
        parent = make_parent()
        child = make_child(parent, expires_at=time.time() + 99999)  # way longer
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R3" in v for v in result.violations)


class TestEnvironmentEscalation:
    def test_extra_environment_denied(self):
        parent = make_parent(environments=["demo"])
        child = make_child(parent, environments=["demo", "production"])
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R5" in v for v in result.violations)


class TestPolicyVersionDowngrade:
    def test_older_policy_version_denied(self):
        parent = make_parent(policy_version=3)
        child = make_child(parent, policy_version=1)
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R6" in v for v in result.violations)


class TestDepthLimit:
    def test_depth_at_max_denied(self):
        parent = make_parent(delegation_depth=MAX_DELEGATION_DEPTH)
        child = make_child(parent)
        result = validate_delegation(parent, child)
        assert not result.allowed
        assert any("R7" in v for v in result.violations)

    def test_depth_just_below_max_allowed(self):
        parent = make_parent(delegation_depth=MAX_DELEGATION_DEPTH - 1)
        child = make_child(parent)
        result = validate_delegation(parent, child)
        assert result.allowed


class TestMultipleViolations:
    def test_all_violations_reported(self):
        """Escalating on multiple axes — all violations should be reported."""
        parent = make_parent(tools=["issue_refund"], max_amount_minor=50000, tenant_id="tenant-demo")
        child = make_child(parent,
            tools=["issue_refund", "wire_transfer"],  # R1
            max_amount_minor=999999,                   # R2
            tenant_id="tenant-evil",                   # R4
            environments=["demo", "production"],       # R5
            policy_version=1,                          # R6
        )
        result = validate_delegation(parent, child)
        assert not result.allowed
        # Should have at least 4 violations
        assert len(result.violations) >= 4

    def test_print_rules_runs(self):
        print_delegation_rules()  # just confirm it doesn't crash
