"""
AgentShield V2 — Shared pytest fixtures

Owner: Pavan (fixture design) | All teammates use these

These fixtures provide deterministic synthetic data for all test suites.
No real credentials, no real money, no production data.

Usage:
    pytest tests/unit/                      # unit tests only (no services needed)
    pytest tests/integration/ -m integration  # requires docker-compose up
    pytest tests/adversarial/ -m adversarial  # requires docker-compose up
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

import pytest

# Make the backend module importable from tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))


# ---------------------------------------------------------------------------
# Synthetic identity fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_id() -> str:
    return "tenant-demo"


@pytest.fixture
def principal_id() -> str:
    return "agent-support-01"


@pytest.fixture
def evil_tenant_id() -> str:
    return "tenant-evil"


@pytest.fixture
def evil_principal_id() -> str:
    return "agent-evil-99"


@pytest.fixture
def approver_id() -> str:
    return "approver-manager-01"


# ---------------------------------------------------------------------------
# Action envelope fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_action_data() -> dict:
    """
    Canonical valid action for a ₹500 refund (50000 paise).
    This is the standard test action. All teammates use it.
    """
    return {
        "schema_version": 1,
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "arguments": {
            "order_id": "ORDER-123",
            "amount_minor": 50000,
        },
        "environment": "demo",
        "policy_version": 3,
        "intent_id": "intent-demo-001",
    }


@pytest.fixture
def valid_action(valid_action_data):
    """Parsed ActionEnvelope from the valid action data."""
    from app.security.schemas import ActionEnvelope
    return ActionEnvelope(**valid_action_data)


@pytest.fixture
def tampered_action_data(valid_action_data) -> dict:
    """
    Action with amount substituted from 50000 to 500000 (10× larger).
    Used to test A2 — action substitution.
    """
    data = {**valid_action_data}
    data["arguments"] = {**valid_action_data["arguments"], "amount_minor": 500000}
    return data


@pytest.fixture
def tampered_action(tampered_action_data):
    from app.security.schemas import ActionEnvelope
    return ActionEnvelope(**tampered_action_data)


@pytest.fixture
def cross_tenant_action_data(valid_action_data) -> dict:
    """Action targeting a resource owned by a different tenant."""
    data = {**valid_action_data}
    data["tenant_id"] = "tenant-evil"
    data["resource"] = "orders/ORDER-EVIL-999"
    return data


@pytest.fixture
def approval_required_action_data(valid_action_data) -> dict:
    """
    Action with amount ≥ 30000 that requires human approval per OPA policy.
    Uses 40000 paise = ₹400.
    """
    data = {**valid_action_data}
    data["arguments"] = {**valid_action_data["arguments"], "amount_minor": 40000}
    data["intent_id"] = "intent-demo-approval-001"
    return data


@pytest.fixture
def hard_deny_action_data(valid_action_data) -> dict:
    """
    Action with amount > 1000000 that is hard-denied and cannot be approved.
    """
    data = {**valid_action_data}
    data["arguments"] = {**valid_action_data["arguments"], "amount_minor": 2000000}
    data["intent_id"] = "intent-demo-hardeny-001"
    return data


# ---------------------------------------------------------------------------
# Digest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_action_digest(valid_action) -> str:
    """Authoritative digest for the standard valid action."""
    from app.security.canonicalization import calculate_action_digest
    return calculate_action_digest(valid_action)


@pytest.fixture
def tampered_action_digest(tampered_action) -> str:
    """Digest for the tampered action (must differ from valid_action_digest)."""
    from app.security.canonicalization import calculate_action_digest
    return calculate_action_digest(tampered_action)


@pytest.fixture
def authoritative_digest_v1() -> str:
    """
    The authoritative digest for Vector 1.
    Computed once and used as the cross-component reference.
    Gururaj verifies this matches his own computation.
    """
    return "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"


# ---------------------------------------------------------------------------
# Approval record fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_approval_id() -> str:
    return "approval-demo-001"


@pytest.fixture
def valid_approval_record(valid_action_digest, valid_approval_id) -> dict:
    """
    A valid unconsumed approval for the standard action.
    Bound to the exact action digest.
    """
    now = datetime.now(timezone.utc)
    return {
        "approval_id": valid_approval_id,
        "tenant_id": "tenant-demo",
        "intent_id": "intent-demo-001",
        "action_digest": valid_action_digest,
        "approver_identity": "approver-manager-01",
        "decision": "approved",
        "consumed": False,
        "approval_policy_version": 3,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }


@pytest.fixture
def consumed_approval_record(valid_approval_record) -> dict:
    """An approval that has already been consumed."""
    return {**valid_approval_record, "consumed": True}


@pytest.fixture
def expired_approval_record(valid_approval_record) -> dict:
    """An approval that has expired."""
    now = datetime.now(timezone.utc)
    return {
        **valid_approval_record,
        "expires_at": (now - timedelta(hours=1)).isoformat(),
    }


@pytest.fixture
def rejected_approval_record(valid_approval_record) -> dict:
    """An approval with decision = rejected."""
    return {**valid_approval_record, "decision": "rejected"}


@pytest.fixture
def wrong_digest_approval_record(valid_approval_record, tampered_action_digest) -> dict:
    """
    An approval issued for the tampered action digest.
    Presenting this for the valid action must be rejected.
    """
    return {**valid_approval_record, "action_digest": tampered_action_digest}


# ---------------------------------------------------------------------------
# Capability token fixtures (used by Girish's tests and Gururaj's tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def capability_jti() -> str:
    """A stable jti for tests that need a predictable capability ID."""
    return "cap-demo-jti-001"


@pytest.fixture
def valid_capability_claims(
    valid_action_digest, capability_jti, valid_action
) -> dict:
    """
    Valid capability claims for the standard action.
    Girish signs this; Gururaj tests replay with it.
    """
    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "iss": "agentshield-capability-issuer-v1",
        "aud": "agentshield-protected-executor-v1",
        "sub": "agent-support-01",
        "tenant_id": "tenant-demo",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "action_digest": valid_action_digest,
        "jti": capability_jti,
        "iat": now,
        "exp": now + 300,
        "policy_version": 3,
        "environment": "demo",
        "intent_id": "intent-demo-001",
        "approval_id": None,
        "kid": "key-v1",
    }


# ---------------------------------------------------------------------------
# Execution record fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def execution_id() -> str:
    return "exec-demo-001"


@pytest.fixture
def claimed_execution_record(
    execution_id, capability_jti, valid_action_digest
) -> dict:
    """An execution record in CLAIMED state."""
    return {
        "execution_id": execution_id,
        "jti": capability_jti,
        "principal_id": "agent-support-01",
        "tenant_id": "tenant-demo",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "action_digest": valid_action_digest,
        "state": "CLAIMED",
        "idempotency_key": capability_jti,
        "result": None,
        "error": None,
        "receipt_id": None,
    }


# ---------------------------------------------------------------------------
# Audit event fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_audit_events(valid_action_digest, capability_jti, execution_id) -> list[dict]:
    """
    A minimal valid audit chain of 3 events for testing.
    Girish's module signs these; Gururaj's tests tamper with them.
    """
    import hashlib, json

    def _hash(data: dict) -> str:
        return hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    e1 = {
        "seq": 1,
        "event_id": "evt-001",
        "timestamp": "2026-10-13T00:00:01Z",
        "event_type": "ACTION_AUTHORIZED",
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "action_digest": valid_action_digest,
        "jti": capability_jti,
        "execution_id": None,
        "approval_id": None,
        "prev_hash": "0" * 64,
    }
    e1["record_hash"] = _hash(e1)

    e2 = {
        "seq": 2,
        "event_id": "evt-002",
        "timestamp": "2026-10-13T00:00:02Z",
        "event_type": "CAPABILITY_ISSUED",
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "action_digest": valid_action_digest,
        "jti": capability_jti,
        "execution_id": None,
        "approval_id": None,
        "prev_hash": e1["record_hash"],
    }
    e2["record_hash"] = _hash(e2)

    e3 = {
        "seq": 3,
        "event_id": "evt-003",
        "timestamp": "2026-10-13T00:00:03Z",
        "event_type": "EXECUTION_SUCCEEDED",
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "action_digest": valid_action_digest,
        "jti": capability_jti,
        "execution_id": execution_id,
        "approval_id": None,
        "prev_hash": e2["record_hash"],
    }
    e3["record_hash"] = _hash(e3)

    return [e1, e2, e3]


# ---------------------------------------------------------------------------
# HTTP client fixtures (for integration tests — require docker-compose up)
# ---------------------------------------------------------------------------

@pytest.fixture
def gateway_url() -> str:
    return os.getenv("GATEWAY_URL", "http://localhost:8000")


@pytest.fixture
def executor_url() -> str:
    return os.getenv("EXECUTOR_URL", "http://localhost:8001")


@pytest.fixture
def mock_tool_url() -> str:
    return os.getenv("MOCK_TOOL_URL", "http://localhost:8002")


@pytest.fixture
def demo_agent_token() -> str:
    """
    A pre-issued JWT for the demo agent.
    In integration tests this must be a real token from POST /v1/agents.
    For unit tests it is a placeholder.
    """
    return os.getenv("DEMO_AGENT_TOKEN", "PLACEHOLDER_REPLACE_IN_INTEGRATION_TESTS")

# ---------------------------------------------------------------------------
# Mock Redis fixture (for replay_guard unit tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """A mock Redis client for unit tests (no live Redis needed)."""
    class _MockRedis:
        def __init__(self):
            self._store: dict = {}
            self._fail = False

        def set(self, key, value, nx=False, ex=None):
            if self._fail:
                raise ConnectionError("Mock Redis unavailable")
            if nx:
                if key in self._store:
                    return None
                self._store[key] = value
                return True
            self._store[key] = value
            return True

        def exists(self, key):
            if self._fail:
                raise ConnectionError("Mock Redis unavailable")
            return 1 if key in self._store else 0

        def delete(self, key):
            return 1 if self._store.pop(key, None) is not None else 0

        def simulate_failure(self):
            self._fail = True

        def restore(self):
            self._fail = False

    return _MockRedis()
