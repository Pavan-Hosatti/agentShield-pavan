"""
AgentShield V2 — Audit Chain Tests

Owner: Pavan

Comprehensive tests for the hash-chain audit log.
These cover build_audit_record, compute_record_hash, and verify_audit_chain.
All tamper detection scenarios from ATTACK_MATRIX A10 are covered here
at the unit level.
"""
from __future__ import annotations

import copy
import json
import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.audit_chain import (
    build_audit_record,
    compute_record_hash,
    verify_audit_chain,
    get_chain_head_hash,
    GENESIS_PREV_HASH,
    AuditEventType,
    AuditVerificationReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DIGEST = "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"


def make_chain(n: int = 3) -> list[dict]:
    """Build a valid chain of n records."""
    records = []
    prev = GENESIS_PREV_HASH
    for i in range(1, n + 1):
        rec = build_audit_record(
            seq=i,
            event_type=AuditEventType.ACTION_AUTHORIZED if i == 1
                       else AuditEventType.CAPABILITY_ISSUED if i == 2
                       else AuditEventType.EXECUTION_SUCCEEDED,
            tenant_id="tenant-demo",
            principal_id="agent-support-01",
            action_digest=DIGEST,
            jti=f"jti-{i:03d}",
            prev_hash=prev,
        )
        prev = rec["record_hash"]
        records.append(rec)
    return records


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

class TestBuildAuditRecord:
    def test_genesis_record_uses_zero_prev_hash(self):
        rec = build_audit_record(
            seq=1, event_type=AuditEventType.ACTION_AUTHORIZED,
            tenant_id="tenant-demo", prev_hash=GENESIS_PREV_HASH,
        )
        assert rec["prev_hash"] == GENESIS_PREV_HASH

    def test_record_has_all_required_fields(self):
        rec = build_audit_record(
            seq=1, event_type="TEST_EVENT",
            tenant_id="tenant-demo", prev_hash=GENESIS_PREV_HASH,
        )
        for f in ("seq", "event_id", "timestamp", "event_type",
                  "tenant_id", "prev_hash", "record_hash"):
            assert f in rec, f"Missing field: {f}"

    def test_record_hash_is_64_char_hex(self):
        rec = build_audit_record(
            seq=1, event_type="TEST",
            tenant_id="tenant-demo", prev_hash=GENESIS_PREV_HASH,
        )
        h = rec["record_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_unique_event_ids(self):
        r1 = build_audit_record(seq=1, event_type="T",
                                 tenant_id="t", prev_hash=GENESIS_PREV_HASH)
        r2 = build_audit_record(seq=2, event_type="T",
                                 tenant_id="t", prev_hash=r1["record_hash"])
        assert r1["event_id"] != r2["event_id"]

    def test_chain_links_correctly(self):
        chain = make_chain(3)
        assert chain[1]["prev_hash"] == chain[0]["record_hash"]
        assert chain[2]["prev_hash"] == chain[1]["record_hash"]


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

class TestComputeRecordHash:
    def test_deterministic(self):
        rec = make_chain(1)[0]
        h1 = compute_record_hash(rec)
        h2 = compute_record_hash(rec)
        assert h1 == h2

    def test_excludes_record_hash_from_input(self):
        """record_hash must not be included in the hash input."""
        rec = make_chain(1)[0]
        # Verify that removing record_hash and recomputing gives the stored value
        expected = compute_record_hash(rec)
        assert rec["record_hash"] == expected

    def test_any_field_change_changes_hash(self):
        rec = make_chain(1)[0]
        original_hash = compute_record_hash(rec)
        modified = copy.deepcopy(rec)
        modified["tenant_id"] = "tenant-evil"
        assert compute_record_hash(modified) != original_hash

    def test_event_type_change_changes_hash(self):
        rec = make_chain(1)[0]
        original = compute_record_hash(rec)
        modified = copy.deepcopy(rec)
        modified["event_type"] = "TAMPERED_EVENT"
        assert compute_record_hash(modified) != original

    def test_prev_hash_change_changes_hash(self):
        rec = make_chain(1)[0]
        original = compute_record_hash(rec)
        modified = copy.deepcopy(rec)
        modified["prev_hash"] = "a" * 64
        assert compute_record_hash(modified) != original


# ---------------------------------------------------------------------------
# Chain verification — happy path
# ---------------------------------------------------------------------------

class TestVerifyChainHappyPath:
    def test_valid_chain_passes(self):
        chain = make_chain(5)
        report = verify_audit_chain(chain)
        assert report.valid is True
        assert report.records_checked == 5
        assert len(report.issues) == 0
        assert report.first_broken_seq is None

    def test_empty_chain_passes(self):
        report = verify_audit_chain([])
        assert report.valid is True
        assert report.records_checked == 0

    def test_single_record_passes(self):
        chain = make_chain(1)
        report = verify_audit_chain(chain)
        assert report.valid is True

    def test_report_summary_valid(self):
        chain = make_chain(3)
        report = verify_audit_chain(chain)
        assert "VALID" in report.summary()


# ---------------------------------------------------------------------------
# Tamper detection — A10
# ---------------------------------------------------------------------------

class TestTamperDetection:
    """Every tamper scenario from ATTACK_MATRIX A10 must be caught."""

    def test_modified_field_detected_hash_mismatch(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[1]["event_type"] = "ATTACK_INJECTED"
        # Don't update record_hash — simulates real attacker

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert any(i.issue_type == "HASH_MISMATCH" for i in report.issues)
        assert report.first_broken_seq == 2

    def test_deleted_record_detected_seq_gap(self):
        chain = make_chain(4)
        tampered = copy.deepcopy(chain)
        del tampered[1]  # Remove record with seq=2

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert any(i.issue_type in ("SEQ_GAP", "CHAIN_BREAK") for i in report.issues)

    def test_reordered_records_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[1], tampered[2] = tampered[2], tampered[1]

        report = verify_audit_chain(tampered)
        assert report.valid is False

    def test_forged_hash_chain_break_detected(self):
        """
        Attacker modifies record AND recomputes its record_hash.
        The NEXT record's prev_hash still points to the original hash.
        Chain break is detected at the following record.
        """
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        # Modify record 1 (index 1) and recompute its hash
        tampered[1]["event_type"] = "FORGED_EVENT"
        tampered[1]["record_hash"] = compute_record_hash(tampered[1])
        # Record 2's prev_hash still points to original record 1 hash

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert any(i.issue_type == "CHAIN_BREAK" for i in report.issues)

    def test_first_broken_seq_correctly_identified(self):
        """first_broken_seq must identify the earliest problem."""
        chain = make_chain(5)
        tampered = copy.deepcopy(chain)
        # Tamper with record at index 2 (seq=3)
        tampered[2]["principal_id"] = "attacker"

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert report.first_broken_seq == 3

    def test_duplicate_seq_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[2]["seq"] = 2  # Duplicate of record[1]

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert any(i.issue_type == "DUPLICATE_SEQ" for i in report.issues)

    def test_modified_prev_hash_chain_break(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[2]["prev_hash"] = "b" * 64  # Wrong prev_hash

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert any(i.issue_type in ("CHAIN_BREAK", "HASH_MISMATCH") for i in report.issues)

    def test_action_digest_tamper_detected(self):
        """Changing the action_digest in a record must be detected."""
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[0]["action_digest"] = "a" * 64

        report = verify_audit_chain(tampered)
        assert report.valid is False
        assert report.first_broken_seq == 1

    def test_tenant_id_tamper_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[0]["tenant_id"] = "tenant-evil"

        report = verify_audit_chain(tampered)
        assert report.valid is False

    def test_timestamp_tamper_detected(self):
        chain = make_chain(2)
        tampered = copy.deepcopy(chain)
        tampered[0]["timestamp"] = "2000-01-01T00:00:00Z"  # Backdated

        report = verify_audit_chain(tampered)
        assert report.valid is False


# ---------------------------------------------------------------------------
# Invariant I10 comprehensive
# ---------------------------------------------------------------------------

class TestInvariantI10:
    """All scenarios from DESIGN_TEST_MATRIX I10."""

    def test_T_I10_A_modified_record_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[1]["event_type"] = "TAMPERED"
        report = verify_audit_chain(tampered)
        assert not report.valid
        assert any(i.issue_type == "HASH_MISMATCH" for i in report.issues)

    def test_T_I10_B_deleted_record_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        del tampered[1]
        report = verify_audit_chain(tampered)
        assert not report.valid

    def test_T_I10_C_reordered_records_detected(self):
        chain = make_chain(3)
        tampered = copy.deepcopy(chain)
        tampered[1], tampered[2] = tampered[2], tampered[1]
        report = verify_audit_chain(tampered)
        assert not report.valid


# ---------------------------------------------------------------------------
# Chain head
# ---------------------------------------------------------------------------

class TestChainHead:
    def test_chain_head_is_last_record_hash(self):
        chain = make_chain(3)
        head = get_chain_head_hash(chain)
        assert head == chain[-1]["record_hash"]

    def test_empty_chain_head_is_none(self):
        assert get_chain_head_hash([]) is None
