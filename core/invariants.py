"""
AgentShield V3 — Security Invariants
Owner: Pavan (Architecture & Threat Modeling)

These are not aspirational — they are checkable properties.
Each function returns True/False and a reason string.
If any invariant returns False, the system is in a violation state.

Invariants:
  I1  — No unauthorized side effect executes
  I2  — Action digest binds parameters exactly
  I3  — Hard-deny cannot be overridden by approval
  I4  — Single-use: jti consumed exactly once
  I5  — Approval bound to exact action digest (single-use)
  I6  — Revocation is enforced at execution, not only at authorization
  I7  — Child capability scope cannot exceed parent scope
  I8  — Policy version cannot be downgraded at execution
  I9  — Executor is the final enforcement boundary (gateway ALLOW is not sufficient)
  I10 — Audit chain alteration is detectable
  I11 — Fail-closed: unavailable dependency → reject, never allow
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class InvariantResult:
    invariant_id: str
    description: str
    holds: bool
    reason: str
    evidence: dict[str, Any] | None = None

    def __bool__(self) -> bool:
        return self.holds

    def __str__(self) -> str:
        status = "HOLDS" if self.holds else "VIOLATED"
        return f"[{status}] {self.invariant_id}: {self.description} — {self.reason}"


# ─────────────────────────────────────────────────────────────
# I1 — No unauthorized side effect executes
# ─────────────────────────────────────────────────────────────

def check_i1_no_unauthorized_effect(
    *,
    execution_succeeded: bool,
    capability_was_valid: bool,
    policy_decision: str,
    digest_matched: bool,
    agent_revoked: bool,
) -> InvariantResult:
    """
    I1: A side effect only executes when ALL of:
      - Capability signature is valid
      - Policy decision was ALLOW
      - Digest matched at execution time
      - Agent was not revoked at execution time
    """
    if not execution_succeeded:
        return InvariantResult(
            "I1", "No unauthorized side effect executes",
            holds=True, reason="No execution occurred — trivially holds",
        )

    violations = []
    if not capability_was_valid:
        violations.append("capability invalid")
    if policy_decision != "allow":
        violations.append(f"policy={policy_decision}")
    if not digest_matched:
        violations.append("digest mismatch")
    if agent_revoked:
        violations.append("agent revoked")

    holds = len(violations) == 0
    return InvariantResult(
        "I1", "No unauthorized side effect executes",
        holds=holds,
        reason="All preconditions met" if holds else f"VIOLATION: execution despite {', '.join(violations)}",
        evidence={"capability_valid": capability_was_valid, "policy": policy_decision,
                  "digest_matched": digest_matched, "agent_revoked": agent_revoked},
    )


# ─────────────────────────────────────────────────────────────
# I2 — Action digest binds parameters exactly
# ─────────────────────────────────────────────────────────────

def check_i2_digest_binding(
    *,
    original_digest: str,
    tampered_digest: str,
) -> InvariantResult:
    """
    I2: Any change to action parameters produces a different digest.
    If original == tampered, a substitution attack could succeed undetected.
    """
    holds = original_digest != tampered_digest
    return InvariantResult(
        "I2", "Action digest binds parameters exactly",
        holds=holds,
        reason=(
            f"Digests differ: {original_digest[:16]}... != {tampered_digest[:16]}..."
            if holds
            else "VIOLATION: same digest for different parameters — substitution undetectable"
        ),
        evidence={"original": original_digest, "tampered": tampered_digest},
    )


# ─────────────────────────────────────────────────────────────
# I3 — Hard-deny cannot be overridden by approval
# ─────────────────────────────────────────────────────────────

def check_i3_hard_deny_not_overridable(
    *,
    hard_deny_reasons: list[str],
    approval_present: bool,
    final_decision: str,
) -> InvariantResult:
    """
    I3: If hard_deny fired, final decision must be DENY regardless of approval.
    """
    if not hard_deny_reasons:
        return InvariantResult(
            "I3", "Hard-deny not overridable by approval",
            holds=True, reason="No hard-deny fired — invariant trivially holds",
        )

    holds = final_decision == "deny"
    return InvariantResult(
        "I3", "Hard-deny not overridable by approval",
        holds=holds,
        reason=(
            f"Hard-deny {hard_deny_reasons} correctly produced DENY"
            if holds
            else f"VIOLATION: hard-deny {hard_deny_reasons} but decision={final_decision} (approval_present={approval_present})"
        ),
        evidence={"hard_denies": hard_deny_reasons, "approval_present": approval_present,
                  "decision": final_decision},
    )


# ─────────────────────────────────────────────────────────────
# I4 — Single-use: jti consumed exactly once
# ─────────────────────────────────────────────────────────────

def check_i4_single_use(
    *,
    jti: str,
    execution_count: int,
) -> InvariantResult:
    """
    I4: A capability identified by jti may cause at most one side effect.
    execution_count is the number of times this jti resulted in a successful execution.
    """
    holds = execution_count <= 1
    return InvariantResult(
        "I4", "Single-use: jti consumed exactly once",
        holds=holds,
        reason=(
            f"jti={jti[:16]}... executed {execution_count} time(s) — within limit"
            if holds
            else f"VIOLATION: jti={jti[:16]}... executed {execution_count} times — REPLAY SUCCEEDED"
        ),
        evidence={"jti": jti, "execution_count": execution_count},
    )


# ─────────────────────────────────────────────────────────────
# I5 — Approval bound to exact action digest (single-use)
# ─────────────────────────────────────────────────────────────

def check_i5_approval_binding(
    *,
    approval_action_digest: str,
    execution_action_digest: str,
    approval_consumed: bool,
    times_approval_used: int,
) -> InvariantResult:
    """
    I5: Approval is valid only for the exact action it was issued for,
    and only once.
    """
    violations = []
    if approval_action_digest != execution_action_digest:
        violations.append(
            f"digest mismatch (approval={approval_action_digest[:12]}... "
            f"!= execution={execution_action_digest[:12]}...)"
        )
    if times_approval_used > 1:
        violations.append(f"approval reused {times_approval_used} times")

    holds = len(violations) == 0
    return InvariantResult(
        "I5", "Approval bound to exact digest, single-use",
        holds=holds,
        reason="Approval correctly bound and single-use" if holds else f"VIOLATION: {'; '.join(violations)}",
        evidence={"approval_digest": approval_action_digest,
                  "execution_digest": execution_action_digest,
                  "times_used": times_approval_used},
    )


# ─────────────────────────────────────────────────────────────
# I6 — Revocation enforced at execution time
# ─────────────────────────────────────────────────────────────

def check_i6_revocation_at_execution(
    *,
    agent_revoked_before_execution: bool,
    execution_succeeded: bool,
) -> InvariantResult:
    """
    I6: A revoked agent must never achieve a successful execution,
    even if the capability was issued before revocation.
    """
    holds = not (agent_revoked_before_execution and execution_succeeded)
    return InvariantResult(
        "I6", "Revocation enforced at execution time",
        holds=holds,
        reason=(
            "Revoked agent correctly blocked at execution"
            if holds and agent_revoked_before_execution
            else "Agent not revoked — holds trivially"
            if not agent_revoked_before_execution
            else "VIOLATION: revoked agent executed successfully"
        ),
        evidence={"revoked": agent_revoked_before_execution, "executed": execution_succeeded},
    )


# ─────────────────────────────────────────────────────────────
# I7 — Child scope cannot exceed parent scope
# ─────────────────────────────────────────────────────────────

def check_i7_delegation_scope(
    *,
    parent_max_amount: int,
    child_requested_amount: int,
    parent_tools: list[str],
    child_tools: list[str],
) -> InvariantResult:
    """
    I7: Delegation cannot escalate privileges.
    Child scope must be a strict subset of parent scope.
    """
    violations = []
    if child_requested_amount > parent_max_amount:
        violations.append(
            f"amount escalation: child={child_requested_amount} > parent={parent_max_amount}"
        )

    extra_tools = set(child_tools) - set(parent_tools)
    if extra_tools:
        violations.append(f"tool escalation: child adds {extra_tools}")

    holds = len(violations) == 0
    return InvariantResult(
        "I7", "Child scope does not exceed parent scope",
        holds=holds,
        reason="Child scope is valid subset of parent" if holds else f"VIOLATION: {'; '.join(violations)}",
        evidence={"parent_amount": parent_max_amount, "child_amount": child_requested_amount,
                  "parent_tools": parent_tools, "child_tools": child_tools},
    )


# ─────────────────────────────────────────────────────────────
# I8 — Policy version cannot be downgraded
# ─────────────────────────────────────────────────────────────

def check_i8_policy_version(
    *,
    capability_policy_version: int,
    minimum_enforced_version: int,
) -> InvariantResult:
    """
    I8: Execution is rejected if the capability was issued under
    a policy version below the current minimum.
    """
    holds = capability_policy_version >= minimum_enforced_version
    return InvariantResult(
        "I8", "Policy version cannot be downgraded at execution",
        holds=holds,
        reason=(
            f"policy_version={capability_policy_version} >= minimum={minimum_enforced_version}"
            if holds
            else f"VIOLATION: policy_version={capability_policy_version} < minimum={minimum_enforced_version}"
        ),
        evidence={"cap_version": capability_policy_version, "min_version": minimum_enforced_version},
    )


# ─────────────────────────────────────────────────────────────
# I9 — Executor is the final enforcement boundary
# ─────────────────────────────────────────────────────────────

def check_i9_executor_is_final_boundary(
    *,
    gateway_said_allow: bool,
    executor_verified_independently: bool,
    execution_succeeded: bool,
) -> InvariantResult:
    """
    I9: Execution must NOT proceed based solely on gateway_said_allow.
    The executor must perform its own verification.
    Gateway ALLOW is a necessary but not sufficient condition.
    """
    if execution_succeeded and gateway_said_allow and not executor_verified_independently:
        return InvariantResult(
            "I9", "Executor is the final enforcement boundary",
            holds=False,
            reason="VIOLATION: execution succeeded based only on gateway decision — executor did not verify independently",
            evidence={"gateway_allow": gateway_said_allow,
                      "executor_verified": executor_verified_independently},
        )
    return InvariantResult(
        "I9", "Executor is the final enforcement boundary",
        holds=True,
        reason="Executor performed independent verification before execution",
        evidence={"gateway_allow": gateway_said_allow,
                  "executor_verified": executor_verified_independently},
    )


# ─────────────────────────────────────────────────────────────
# I10 — Audit chain alteration is detectable
# ─────────────────────────────────────────────────────────────

def check_i10_audit_chain(
    *,
    chain_verified: bool,
    tamper_attempted: bool,
    tamper_detected: bool,
) -> InvariantResult:
    """
    I10: If any audit record is tampered with, the independent verifier
    must detect it (broken hash chain).
    """
    if tamper_attempted and not tamper_detected:
        return InvariantResult(
            "I10", "Audit chain alteration is detectable",
            holds=False,
            reason="VIOLATION: tampering occurred but was NOT detected by the verifier",
        )
    if tamper_attempted and tamper_detected:
        return InvariantResult(
            "I10", "Audit chain alteration is detectable",
            holds=True,
            reason="Tampering detected correctly — hash chain broken at first modified record",
        )
    return InvariantResult(
        "I10", "Audit chain alteration is detectable",
        holds=chain_verified,
        reason="Audit chain intact" if chain_verified else "VIOLATION: chain verification failed with no known tamper",
    )


# ─────────────────────────────────────────────────────────────
# I11 — Fail-closed: unavailable dependency → reject
# ─────────────────────────────────────────────────────────────

def check_i11_fail_closed(
    *,
    dependency: str,
    dependency_available: bool,
    system_response: str,  # "reject" | "allow" | "degrade"
) -> InvariantResult:
    """
    I11: When a critical dependency (OPA, Redis, PostgreSQL) is unavailable,
    the system must reject the request. It must NEVER default to allow.
    """
    if not dependency_available and system_response == "allow":
        return InvariantResult(
            "I11", "Fail-closed when dependency unavailable",
            holds=False,
            reason=f"VIOLATION: {dependency} unavailable but system responded '{system_response}' — FAIL-OPEN",
            evidence={"dependency": dependency, "response": system_response},
        )
    holds = dependency_available or system_response == "reject"
    return InvariantResult(
        "I11", "Fail-closed when dependency unavailable",
        holds=holds,
        reason=(
            f"{dependency} available — normal operation"
            if dependency_available
            else f"{dependency} unavailable — correctly rejected (fail-closed)"
        ),
        evidence={"dependency": dependency, "available": dependency_available, "response": system_response},
    )


# ─────────────────────────────────────────────────────────────
# Composite checker — run all provable invariants
# ─────────────────────────────────────────────────────────────

@dataclass
class InvariantReport:
    results: list[InvariantResult]

    @property
    def all_hold(self) -> bool:
        return all(r.holds for r in self.results)

    @property
    def violations(self) -> list[InvariantResult]:
        return [r for r in self.results if not r.holds]

    def print_report(self) -> None:
        print("=" * 64)
        print("AgentShield V3 — Security Invariant Check")
        print("=" * 64)
        for r in self.results:
            icon = "✅" if r.holds else "❌"
            print(f"  {icon} {r}")
        print("-" * 64)
        if self.violations:
            print(f"  VIOLATIONS: {len(self.violations)}/{len(self.results)}")
            for v in self.violations:
                print(f"    ↳ {v.invariant_id}: {v.reason}")
        else:
            print(f"  All {len(self.results)} invariants hold ✓")
        print("=" * 64)


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    # Demo: check all invariants with sample data
    results = [
        check_i1_no_unauthorized_effect(
            execution_succeeded=True,
            capability_was_valid=True,
            policy_decision="allow",
            digest_matched=True,
            agent_revoked=False,
        ),
        check_i2_digest_binding(
            original_digest="7b10052fc753b4b4",
            tampered_digest="ae72f0c9106d392e",
        ),
        check_i3_hard_deny_not_overridable(
            hard_deny_reasons=["AMOUNT_EXCEEDS_HARD_MAXIMUM"],
            approval_present=True,
            final_decision="deny",
        ),
        check_i4_single_use(jti="cap-jti-001", execution_count=1),
        check_i5_approval_binding(
            approval_action_digest="abc123",
            execution_action_digest="abc123",
            approval_consumed=False,
            times_approval_used=1,
        ),
        check_i6_revocation_at_execution(
            agent_revoked_before_execution=False,
            execution_succeeded=True,
        ),
        check_i7_delegation_scope(
            parent_max_amount=50000,
            child_requested_amount=29999,
            parent_tools=["issue_refund"],
            child_tools=["issue_refund"],
        ),
        check_i8_policy_version(capability_policy_version=3, minimum_enforced_version=2),
        check_i9_executor_is_final_boundary(
            gateway_said_allow=True,
            executor_verified_independently=True,
            execution_succeeded=True,
        ),
        check_i10_audit_chain(chain_verified=True, tamper_attempted=True, tamper_detected=True),
        check_i11_fail_closed(dependency="OPA", dependency_available=False, system_response="reject"),
    ]

    report = InvariantReport(results=results)
    report.print_report()
