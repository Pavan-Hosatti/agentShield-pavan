"""
AgentShield V3 — Security Invariant Tests
Owner: Pavan

Tests ALL 11 invariants. Each test verifies:
  1. The invariant holds under correct conditions
  2. The invariant is violated under attack conditions
  3. The violation is detected and labeled correctly
"""
import pytest
from core.invariants import (
    check_i1_no_unauthorized_effect,
    check_i2_digest_binding,
    check_i3_hard_deny_not_overridable,
    check_i4_single_use,
    check_i5_approval_binding,
    check_i6_revocation_at_execution,
    check_i7_delegation_scope,
    check_i8_policy_version,
    check_i9_executor_is_final_boundary,
    check_i10_audit_chain,
    check_i11_fail_closed,
    InvariantReport,
)


class TestI1NoUnauthorizedEffect:
    def test_holds_when_all_checks_pass(self):
        r = check_i1_no_unauthorized_effect(
            execution_succeeded=True,
            capability_was_valid=True,
            policy_decision="allow",
            digest_matched=True,
            agent_revoked=False,
        )
        assert r.holds

    def test_holds_when_no_execution(self):
        r = check_i1_no_unauthorized_effect(
            execution_succeeded=False,
            capability_was_valid=False,
            policy_decision="deny",
            digest_matched=False,
            agent_revoked=True,
        )
        assert r.holds  # No execution = no violation

    def test_violated_when_revoked_agent_executes(self):
        r = check_i1_no_unauthorized_effect(
            execution_succeeded=True,
            capability_was_valid=True,
            policy_decision="allow",
            digest_matched=True,
            agent_revoked=True,   # REVOKED
        )
        assert not r.holds
        assert "revoked" in r.reason.lower()

    def test_violated_when_digest_mismatch_executes(self):
        r = check_i1_no_unauthorized_effect(
            execution_succeeded=True,
            capability_was_valid=True,
            policy_decision="allow",
            digest_matched=False,  # MISMATCH
            agent_revoked=False,
        )
        assert not r.holds

    def test_violated_when_denied_action_executes(self):
        r = check_i1_no_unauthorized_effect(
            execution_succeeded=True,
            capability_was_valid=False,
            policy_decision="deny",
            digest_matched=False,
            agent_revoked=False,
        )
        assert not r.holds


class TestI2DigestBinding:
    def test_holds_when_digests_differ(self):
        r = check_i2_digest_binding(
            original_digest="7b10052fc753b4b4",
            tampered_digest="ae72f0c9106d392e",
        )
        assert r.holds

    def test_violated_when_digests_same(self):
        """If same digest for different data — substitution undetectable."""
        r = check_i2_digest_binding(
            original_digest="aabbccdd",
            tampered_digest="aabbccdd",
        )
        assert not r.holds
        assert "VIOLATION" in r.reason


class TestI3HardDenyNotOverridable:
    def test_holds_when_hard_deny_produces_deny(self):
        r = check_i3_hard_deny_not_overridable(
            hard_deny_reasons=["AMOUNT_EXCEEDS_HARD_MAXIMUM"],
            approval_present=True,
            final_decision="deny",
        )
        assert r.holds

    def test_holds_trivially_when_no_hard_deny(self):
        r = check_i3_hard_deny_not_overridable(
            hard_deny_reasons=[],
            approval_present=True,
            final_decision="allow",
        )
        assert r.holds

    def test_violated_when_hard_deny_bypassed_by_approval(self):
        r = check_i3_hard_deny_not_overridable(
            hard_deny_reasons=["AGENT_REVOKED"],
            approval_present=True,
            final_decision="allow",   # WRONG — should be deny
        )
        assert not r.holds
        assert "VIOLATION" in r.reason

    def test_all_hard_deny_types_blocked(self):
        hard_deny_types = [
            "AGENT_NOT_REGISTERED",
            "AGENT_REVOKED",
            "CROSS_TENANT_ACCESS",
            "TOOL_NOT_PERMITTED",
            "INVALID_ENVIRONMENT",
            "POLICY_VERSION_STALE",
            "AMOUNT_EXCEEDS_HARD_MAXIMUM",
        ]
        for hd in hard_deny_types:
            r = check_i3_hard_deny_not_overridable(
                hard_deny_reasons=[hd],
                approval_present=True,
                final_decision="deny",
            )
            assert r.holds, f"Hard deny {hd} should hold"


class TestI4SingleUse:
    def test_holds_when_executed_once(self):
        r = check_i4_single_use(jti="cap-001", execution_count=1)
        assert r.holds

    def test_holds_when_not_executed(self):
        r = check_i4_single_use(jti="cap-001", execution_count=0)
        assert r.holds

    def test_violated_when_replayed(self):
        r = check_i4_single_use(jti="cap-001", execution_count=2)
        assert not r.holds
        assert "REPLAY" in r.reason

    def test_violated_for_100_replays(self):
        r = check_i4_single_use(jti="cap-001", execution_count=100)
        assert not r.holds


class TestI5ApprovalBinding:
    def test_holds_when_digest_matches_and_single_use(self):
        r = check_i5_approval_binding(
            approval_action_digest="abc123",
            execution_action_digest="abc123",
            approval_consumed=False,
            times_approval_used=1,
        )
        assert r.holds

    def test_violated_when_digest_mismatch(self):
        r = check_i5_approval_binding(
            approval_action_digest="abc123",
            execution_action_digest="xyz999",  # different
            approval_consumed=False,
            times_approval_used=1,
        )
        assert not r.holds
        assert "mismatch" in r.reason

    def test_violated_when_approval_reused(self):
        r = check_i5_approval_binding(
            approval_action_digest="abc123",
            execution_action_digest="abc123",
            approval_consumed=True,
            times_approval_used=2,
        )
        assert not r.holds
        assert "reused" in r.reason


class TestI6RevocationAtExecution:
    def test_holds_when_agent_active(self):
        r = check_i6_revocation_at_execution(
            agent_revoked_before_execution=False,
            execution_succeeded=True,
        )
        assert r.holds

    def test_holds_when_revoked_agent_blocked(self):
        r = check_i6_revocation_at_execution(
            agent_revoked_before_execution=True,
            execution_succeeded=False,   # correctly blocked
        )
        assert r.holds

    def test_violated_when_revoked_agent_executes(self):
        r = check_i6_revocation_at_execution(
            agent_revoked_before_execution=True,
            execution_succeeded=True,    # WRONG
        )
        assert not r.holds
        assert "VIOLATION" in r.reason


class TestI7DelegationScope:
    def test_holds_for_valid_subset(self):
        r = check_i7_delegation_scope(
            parent_max_amount=50000,
            child_requested_amount=29999,
            parent_tools=["issue_refund"],
            child_tools=["issue_refund"],
        )
        assert r.holds

    def test_violated_on_amount_escalation(self):
        r = check_i7_delegation_scope(
            parent_max_amount=50000,
            child_requested_amount=999999,   # exceeds parent
            parent_tools=["issue_refund"],
            child_tools=["issue_refund"],
        )
        assert not r.holds

    def test_violated_on_tool_escalation(self):
        r = check_i7_delegation_scope(
            parent_max_amount=50000,
            child_requested_amount=10000,
            parent_tools=["issue_refund"],
            child_tools=["issue_refund", "wire_transfer"],   # adds tool
        )
        assert not r.holds
        assert "tool" in r.reason.lower()


class TestI8PolicyVersion:
    def test_holds_when_version_current(self):
        r = check_i8_policy_version(capability_policy_version=3, minimum_enforced_version=2)
        assert r.holds

    def test_holds_at_exact_minimum(self):
        r = check_i8_policy_version(capability_policy_version=2, minimum_enforced_version=2)
        assert r.holds

    def test_violated_when_version_too_old(self):
        r = check_i8_policy_version(capability_policy_version=1, minimum_enforced_version=2)
        assert not r.holds
        assert "VIOLATION" in r.reason


class TestI9ExecutorFinalBoundary:
    def test_holds_when_executor_verified(self):
        r = check_i9_executor_is_final_boundary(
            gateway_said_allow=True,
            executor_verified_independently=True,
            execution_succeeded=True,
        )
        assert r.holds

    def test_violated_when_executor_trusts_gateway_blindly(self):
        r = check_i9_executor_is_final_boundary(
            gateway_said_allow=True,
            executor_verified_independently=False,   # skipped verification
            execution_succeeded=True,
        )
        assert not r.holds
        assert "VIOLATION" in r.reason


class TestI10AuditChain:
    def test_holds_when_chain_valid(self):
        r = check_i10_audit_chain(chain_verified=True, tamper_attempted=False, tamper_detected=False)
        assert r.holds

    def test_holds_when_tamper_detected(self):
        r = check_i10_audit_chain(chain_verified=False, tamper_attempted=True, tamper_detected=True)
        assert r.holds

    def test_violated_when_tamper_undetected(self):
        r = check_i10_audit_chain(chain_verified=True, tamper_attempted=True, tamper_detected=False)
        assert not r.holds
        assert "VIOLATION" in r.reason


class TestI11FailClosed:
    def test_holds_when_dep_available(self):
        r = check_i11_fail_closed(dependency="OPA", dependency_available=True, system_response="allow")
        assert r.holds

    def test_holds_when_unavailable_and_rejected(self):
        r = check_i11_fail_closed(dependency="OPA", dependency_available=False, system_response="reject")
        assert r.holds

    def test_violated_when_unavailable_but_allowed(self):
        r = check_i11_fail_closed(dependency="OPA", dependency_available=False, system_response="allow")
        assert not r.holds
        assert "FAIL-OPEN" in r.reason

    @pytest.mark.parametrize("dep", ["OPA", "Redis", "PostgreSQL"])
    def test_fail_closed_for_all_critical_deps(self, dep):
        r = check_i11_fail_closed(dependency=dep, dependency_available=False, system_response="reject")
        assert r.holds


class TestInvariantReport:
    def test_all_hold_true_when_all_pass(self):
        results = [
            check_i2_digest_binding(original_digest="aaa", tampered_digest="bbb"),
            check_i4_single_use(jti="jti-1", execution_count=1),
            check_i8_policy_version(capability_policy_version=3, minimum_enforced_version=2),
        ]
        report = InvariantReport(results=results)
        assert report.all_hold
        assert report.violations == []

    def test_violations_listed_correctly(self):
        results = [
            check_i4_single_use(jti="jti-1", execution_count=1),    # holds
            check_i4_single_use(jti="jti-2", execution_count=50),   # violated
        ]
        report = InvariantReport(results=results)
        assert not report.all_hold
        assert len(report.violations) == 1
