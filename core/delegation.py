"""
AgentShield V3 — Delegation Rules & Scope Boundaries
Owner: Pavan (Architecture & Threat Modeling)

Delegation = a parent capability grants a child capability a sub-scope.
The core constraint: child scope MUST be a strict subset of parent scope.
A child can NEVER expand permissions — only narrow them.

This prevents delegation escalation attacks (T16 in the threat model).

Rules:
  R1 — Child tools ⊆ parent tools
  R2 — Child max_amount ≤ parent max_amount
  R3 — Child TTL ≤ parent remaining TTL
  R4 — Child tenant_id == parent tenant_id (no cross-tenant delegation)
  R5 — Child environment ⊆ parent environments
  R6 — Child policy_version ≥ parent policy_version (cannot downgrade)
  R7 — Delegation depth ≤ MAX_DELEGATION_DEPTH (prevents infinite chains)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

MAX_DELEGATION_DEPTH = 3   # parent → child → grandchild → stop


@dataclass
class Scope:
    """
    The permissions associated with a capability.
    Used at both parent and child level.
    """
    tools: list[str]                   # allowed tool names
    max_amount_minor: int              # max monetary amount (paise)
    environments: list[str]            # allowed environments
    tenant_id: str                     # owner tenant — MUST match parent
    policy_version: int                # minimum policy version
    expires_at: float                  # Unix timestamp (UTC)
    delegation_depth: int = 0          # incremented at each delegation


@dataclass
class DelegationResult:
    allowed: bool
    violations: list[str]
    child_scope: Optional[Scope] = None

    def __bool__(self) -> bool:
        return self.allowed

    def summary(self) -> str:
        if self.allowed:
            return f"DELEGATION ALLOWED — child scope is valid subset of parent"
        return f"DELEGATION DENIED — {len(self.violations)} violation(s): {'; '.join(self.violations)}"


def validate_delegation(parent: Scope, requested_child: Scope) -> DelegationResult:
    """
    Validate that a requested child scope is a valid subset of the parent scope.
    Returns the clamped child scope if allowed, or a rejection with reasons.

    This is called by the Capability Issuer when an agent requests
    a sub-capability for a sub-task (delegation).
    """
    violations: list[str] = []

    # R1 — tool subset
    extra_tools = set(requested_child.tools) - set(parent.tools)
    if extra_tools:
        violations.append(f"R1-TOOL_ESCALATION: child requests tools not in parent: {extra_tools}")

    # R2 — amount bound
    if requested_child.max_amount_minor > parent.max_amount_minor:
        violations.append(
            f"R2-AMOUNT_ESCALATION: child.max={requested_child.max_amount_minor} "
            f"> parent.max={parent.max_amount_minor}"
        )

    # R3 — TTL bound
    now = time.time()
    parent_remaining = parent.expires_at - now
    child_ttl = requested_child.expires_at - now
    if child_ttl > parent_remaining + 1:   # 1s tolerance
        violations.append(
            f"R3-TTL_ESCALATION: child_ttl={child_ttl:.0f}s > parent_remaining={parent_remaining:.0f}s"
        )

    # R4 — tenant binding
    if requested_child.tenant_id != parent.tenant_id:
        violations.append(
            f"R4-TENANT_MISMATCH: child.tenant={requested_child.tenant_id} "
            f"!= parent.tenant={parent.tenant_id}"
        )

    # R5 — environment subset
    extra_envs = set(requested_child.environments) - set(parent.environments)
    if extra_envs:
        violations.append(f"R5-ENV_ESCALATION: child adds environments not in parent: {extra_envs}")

    # R6 — policy version (cannot downgrade)
    if requested_child.policy_version < parent.policy_version:
        violations.append(
            f"R6-VERSION_DOWNGRADE: child.policy_version={requested_child.policy_version} "
            f"< parent.policy_version={parent.policy_version}"
        )

    # R7 — depth limit
    child_depth = parent.delegation_depth + 1
    if child_depth > MAX_DELEGATION_DEPTH:
        violations.append(
            f"R7-DEPTH_EXCEEDED: depth={child_depth} > MAX_DELEGATION_DEPTH={MAX_DELEGATION_DEPTH}"
        )

    if violations:
        return DelegationResult(allowed=False, violations=violations)

    # Build the clamped child scope (enforce parent limits even if request was within bounds)
    child_scope = Scope(
        tools=list(set(requested_child.tools) & set(parent.tools)),
        max_amount_minor=min(requested_child.max_amount_minor, parent.max_amount_minor),
        environments=list(set(requested_child.environments) & set(parent.environments)),
        tenant_id=parent.tenant_id,
        policy_version=max(requested_child.policy_version, parent.policy_version),
        expires_at=min(requested_child.expires_at, parent.expires_at),
        delegation_depth=child_depth,
    )

    return DelegationResult(allowed=True, violations=[], child_scope=child_scope)


def print_delegation_rules() -> None:
    rules = [
        ("R1", "TOOL_ESCALATION",       "Child tools ⊆ parent tools"),
        ("R2", "AMOUNT_ESCALATION",     "Child max_amount ≤ parent max_amount"),
        ("R3", "TTL_ESCALATION",        "Child TTL ≤ parent remaining TTL"),
        ("R4", "TENANT_MISMATCH",       "Child tenant_id == parent tenant_id"),
        ("R5", "ENV_ESCALATION",        "Child environments ⊆ parent environments"),
        ("R6", "VERSION_DOWNGRADE",     "Child policy_version ≥ parent policy_version"),
        ("R7", "DEPTH_EXCEEDED",        f"Delegation depth ≤ {MAX_DELEGATION_DEPTH}"),
    ]
    print("=" * 60)
    print("AgentShield V3 — Delegation Rules (T16 mitigation)")
    print("=" * 60)
    for rule_id, violation, desc in rules:
        print(f"  [{rule_id}] {desc}")
        print(f"       Violation code: {violation}")
    print("=" * 60)
    print(f"  Delegation depth limit: {MAX_DELEGATION_DEPTH}")
    print("  Principle: child scope is ALWAYS a strict subset of parent scope")
    print("=" * 60)


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    now = time.time()

    # Parent: full scope
    parent = Scope(
        tools=["issue_refund"],
        max_amount_minor=50000,
        environments=["demo"],
        tenant_id="tenant-demo",
        policy_version=3,
        expires_at=now + 300,
        delegation_depth=0,
    )

    # Valid child request
    valid_child = Scope(
        tools=["issue_refund"],
        max_amount_minor=29999,         # less than parent
        environments=["demo"],
        tenant_id="tenant-demo",
        policy_version=3,
        expires_at=now + 120,           # shorter TTL
        delegation_depth=0,
    )

    # Invalid: amount escalation
    escalating_child = Scope(
        tools=["issue_refund", "wire_transfer"],  # adds tool
        max_amount_minor=999999,                   # way above parent
        environments=["demo", "production"],       # adds env
        tenant_id="tenant-evil",                   # wrong tenant
        policy_version=1,                          # downgrades version
        expires_at=now + 9999,                     # longer TTL
        delegation_depth=0,
    )

    print("=== Valid delegation ===")
    r1 = validate_delegation(parent, valid_child)
    print(r1.summary())

    print()
    print("=== Escalation attempt ===")
    r2 = validate_delegation(parent, escalating_child)
    print(r2.summary())
    if not r2.allowed:
        for v in r2.violations:
            print(f"  ↳ {v}")

    print()
    print_delegation_rules()
