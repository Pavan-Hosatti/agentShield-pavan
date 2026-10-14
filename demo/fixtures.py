"""
AgentShield V2 — Demo Fixtures

Deterministic synthetic data for demonstrations and testing.
No real credentials. No real orders. No real money.

Owner: Pavan (fixture design) | Alok (demo reset endpoint uses these)
"""

from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# Synthetic agents
# ---------------------------------------------------------------------------

DEMO_AGENTS: list[dict[str, Any]] = [
    {
        "agent_id": "agent-support-01",
        "tenant_id": "tenant-demo",
        "display_name": "Support Agent 01",
        "permitted_tools": ["issue_refund"],
        "max_amount_minor": 1_000_000,
        "environment": "demo",
        "registered": True,
        "revoked": False,
        "api_key_hash": "DEMO_HASH_REPLACE_WITH_BCRYPT",  # Never a real key in source
    },
    {
        "agent_id": "agent-support-02",
        "tenant_id": "tenant-demo",
        "display_name": "Support Agent 02 (approval test)",
        "permitted_tools": ["issue_refund"],
        "max_amount_minor": 1_000_000,
        "environment": "demo",
        "registered": True,
        "revoked": False,
        "api_key_hash": "DEMO_HASH_REPLACE_WITH_BCRYPT",
    },
    {
        "agent_id": "agent-revoke-test",
        "tenant_id": "tenant-demo",
        "display_name": "Revocation Test Agent",
        "permitted_tools": ["issue_refund"],
        "max_amount_minor": 100_000,
        "environment": "demo",
        "registered": True,
        "revoked": False,
        "api_key_hash": "DEMO_HASH_REPLACE_WITH_BCRYPT",
    },
]


# ---------------------------------------------------------------------------
# Synthetic tenants
# ---------------------------------------------------------------------------

DEMO_TENANTS: list[dict[str, Any]] = [
    {
        "tenant_id": "tenant-demo",
        "display_name": "Demo Tenant",
        "environment": "demo",
    },
]


# ---------------------------------------------------------------------------
# Synthetic orders (mock protected tool state)
# ---------------------------------------------------------------------------

DEMO_ORDERS: list[dict[str, Any]] = [
    {
        "order_id": "ORDER-123",
        "tenant_id": "tenant-demo",
        "customer_name": "Demo Customer A",
        "total_amount_minor": 150_000,
        "refund_issued": False,
        "refund_amount_minor": 0,
    },
    {
        "order_id": "ORDER-456",
        "tenant_id": "tenant-demo",
        "customer_name": "Demo Customer B",
        "total_amount_minor": 80_000,
        "refund_issued": False,
        "refund_amount_minor": 0,
    },
    {
        "order_id": "ORDER-APPROVAL-001",
        "tenant_id": "tenant-demo",
        "customer_name": "Demo Customer C (requires approval)",
        "total_amount_minor": 200_000,
        "refund_issued": False,
        "refund_amount_minor": 0,
    },
]


# ---------------------------------------------------------------------------
# Synthetic approvers
# ---------------------------------------------------------------------------

DEMO_APPROVERS: list[dict[str, Any]] = [
    {
        "approver_id": "approver-manager-01",
        "tenant_id": "tenant-demo",
        "display_name": "Demo Manager",
        "approval_limit_minor": 1_000_000,
    },
]


# ---------------------------------------------------------------------------
# Demo action scenarios (used in demo scripts and attack lab)
# ---------------------------------------------------------------------------

DEMO_SCENARIOS: list[dict[str, Any]] = [
    {
        "scenario_id": "B1",
        "name": "Valid small refund (no approval)",
        "action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": "orders/ORDER-123",
            "arguments": {"order_id": "ORDER-123", "amount_minor": 29999},
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-b1-001",
        },
        "expected_result": "allow",
        "requires_approval": False,
    },
    {
        "scenario_id": "B2",
        "name": "Approval-required refund",
        "action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-02",
            "tool": "issue_refund",
            "resource": "orders/ORDER-APPROVAL-001",
            "arguments": {"order_id": "ORDER-APPROVAL-001", "amount_minor": 40000},
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-b2-001",
        },
        "expected_result": "needs_approval",
        "requires_approval": True,
    },
    {
        "scenario_id": "A2",
        "name": "Action substitution attack",
        "authorized_action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": "orders/ORDER-123",
            "arguments": {"order_id": "ORDER-123", "amount_minor": 50000},
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-a2-001",
        },
        "tampered_action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": "orders/ORDER-123",
            "arguments": {"order_id": "ORDER-123", "amount_minor": 500000},  # 10× larger
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-a2-001",
        },
        "expected_result": "DIGEST_MISMATCH",
    },
    {
        "scenario_id": "A6",
        "name": "Revocation race",
        "action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-revoke-test",
            "tool": "issue_refund",
            "resource": "orders/ORDER-456",
            "arguments": {"order_id": "ORDER-456", "amount_minor": 10000},
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-a6-001",
        },
        "expected_result": "AGENT_REVOKED",
        "revoke_before_execution": True,
    },
]


# ---------------------------------------------------------------------------
# Reset state (what POST /v1/demo/reset restores)
# ---------------------------------------------------------------------------

RESET_STATE = {
    "agents": DEMO_AGENTS,
    "tenants": DEMO_TENANTS,
    "orders": DEMO_ORDERS,
    "approvers": DEMO_APPROVERS,
    "clear_executions": True,
    "clear_audit_log": True,
    "clear_approvals": True,
    "clear_revocations": True,
    "clear_redis_claims": True,
}
