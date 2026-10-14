"""
AgentShield V2 — Audit Pipeline Tests

Owner: Pavan

Tests that every event builder produces valid, chain-linked audit records.
"""
from __future__ import annotations

import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.audit_chain import (
    GENESIS_PREV_HASH,
    verify_audit_chain,
    compute_record_hash,
)
from app.audit.pipeline import (
    make_action_authorized_event,
    make_capability_issued_event,
    make_execution_claimed_event,
    make_execution_succeeded_event,
    make_execution_denied_event,
    make_agent_revoked_event,
    make_approval_consumed_event,
    make_execution_unknown_event,
)

DIGEST  = "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"
TENANT  = "tenant-demo"
AGENT   = "agent-support-01"
JTI     = "cap-jti-001"
EXEC_ID = "exec-001"
APPR_ID = "approval-001"


def make_full_chain() -> list[dict]:
    """Build a realistic chain of events for a complete execution flow."""
    chain = []

    e1 = make_action_authorized_event(
        seq=1, prev_hash=GENESIS_PREV_HASH,
        tenant_id=TENANT, principal_id=AGENT,
        action_digest=DIGEST, jti=JTI,
    )
    chain.append(e1)

    e2 = make_capability_issued_event(
        seq=2, prev_hash=e1["record_hash"],
        tenant_id=TENANT, principal_id=AGENT,
        action_digest=DIGEST, jti=JTI,
    )
    chain.append(e2)

    e3 = make_execution_claimed_event(
        seq=3, prev_hash=e2["record_hash"],
        tenant_id=TENANT, principal_id=AGENT,
        action_digest=DIGEST, jti=JTI, execution_id=EXEC_ID,
    )
    chain.append(e3)

    e4 = make_execution_succeeded_event(
        seq=4, prev_hash=e3["record_hash"],
        tenant_id=TENANT, principal_id=AGENT,
        action_digest=DIGEST, jti=JTI, execution_id=EXEC_ID,
    )
    chain.append(e4)

    return chain


class TestEventBuilders:
    def test_all_events_have_required_fields(self):
        required = {"seq", "event_id", "timestamp", "event_type",
                    "tenant_id", "prev_hash", "record_hash"}
        for event in make_full_chain():
            missing = required - set(event.keys())
            assert not missing, f"Event missing fields: {missing}"

    def test_full_chain_passes_verification(self):
        chain = make_full_chain()
        report = verify_audit_chain(chain)
        assert report.valid, f"Chain invalid: {report.issues}"

    def test_event_types_are_correct(self):
        chain = make_full_chain()
        types = [e["event_type"] for e in chain]
        assert types == [
            "ACTION_AUTHORIZED", "CAPABILITY_ISSUED",
            "EXECUTION_CLAIMED", "EXECUTION_SUCCEEDED",
        ]

    def test_chain_is_linked(self):
        chain = make_full_chain()
        for i in range(1, len(chain)):
            assert chain[i]["prev_hash"] == chain[i-1]["record_hash"], \
                f"Chain break between event {i-1} and {i}"

    def test_execution_denied_event(self):
        e = make_execution_denied_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            action_digest=DIGEST, reason="DIGEST_MISMATCH",
        )
        assert e["event_type"] == "EXECUTION_DENIED"
        assert e["extra"]["denial_reason"] == "DIGEST_MISMATCH"
        assert compute_record_hash(e) == e["record_hash"]

    def test_agent_revoked_event(self):
        e = make_agent_revoked_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            revoked_by="admin-01", reason="Compromised",
        )
        assert e["event_type"] == "AGENT_REVOKED"
        assert e["extra"]["revoked_by"] == "admin-01"

    def test_approval_consumed_event(self):
        e = make_approval_consumed_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            action_digest=DIGEST, approval_id=APPR_ID, jti=JTI,
        )
        assert e["event_type"] == "APPROVAL_CONSUMED"
        assert e["approval_id"] == APPR_ID

    def test_execution_unknown_event(self):
        e = make_execution_unknown_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            action_digest=DIGEST, jti=JTI, execution_id=EXEC_ID,
            error="timeout after 30s",
        )
        assert e["event_type"] == "EXECUTION_UNKNOWN"
        assert "timeout" in e["extra"]["error"]

    def test_record_hash_deterministic(self):
        e1 = make_action_authorized_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            action_digest=DIGEST,
        )
        # Same record hash each time it's computed
        assert compute_record_hash(e1) == e1["record_hash"]

    def test_denial_event_does_not_affect_mock_state(self):
        """A denied event must have no execution_id (tool was not invoked)."""
        e = make_execution_denied_event(
            seq=1, prev_hash=GENESIS_PREV_HASH,
            tenant_id=TENANT, principal_id=AGENT,
            action_digest=DIGEST, reason="DIGEST_MISMATCH",
        )
        assert e.get("execution_id") is None


class TestChainFromPipeline:
    def test_complete_happy_path_chain_is_valid(self):
        chain = make_full_chain()
        assert len(chain) == 4
        report = verify_audit_chain(chain)
        assert report.valid
        assert report.records_checked == 4
