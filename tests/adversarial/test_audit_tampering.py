"""
AgentShield V2 — A10: Audit Tampering Tests

Invariant tested: I10 — Audit alteration is detected under documented integrity assumptions.

Attacks:
  - Modify a field in an audit record
  - Delete an audit record
  - Reorder audit records

Expected: Independent verifier detects the inconsistency.

Owner: Pavan (design) | Girish (verifier implementation) | Gururaj (attack execution)
"""

from __future__ import annotations
import hashlib
import json
import copy
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))


# ---------------------------------------------------------------------------
# Audit chain verification helpers (mirror Girish's verifier logic)
# ---------------------------------------------------------------------------

def compute_record_hash(record: dict) -> str:
    """
    Compute the SHA-256 hash of a canonical audit record.
    record_hash is NOT included in its own hash computation.
    prev_hash IS included.
    """
    # Remove record_hash from the dict before hashing (it's the result, not input)
    record_for_hashing = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(record_for_hashing, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_chain(records: list[dict]) -> dict:
    """
    Verify the integrity of an audit chain.
    Returns a verification report.

    This mirrors what Girish's independent verifier must produce.
    """
    if not records:
        return {"valid": True, "issues": [], "first_broken_seq": None}

    issues = []
    first_broken = None

    for i, record in enumerate(records):
        # 1. Verify record_hash matches computed hash
        expected_hash = compute_record_hash(record)
        if record.get("record_hash") != expected_hash:
            issue = {
                "type": "HASH_MISMATCH",
                "seq": record.get("seq"),
                "event_id": record.get("event_id"),
                "detail": f"record_hash does not match computed hash at seq={record.get('seq')}",
            }
            issues.append(issue)
            if first_broken is None:
                first_broken = record.get("seq")

        # 2. Verify prev_hash links to previous record
        if i > 0:
            prev_record = records[i - 1]
            if record.get("prev_hash") != prev_record.get("record_hash"):
                issue = {
                    "type": "CHAIN_BREAK",
                    "seq": record.get("seq"),
                    "event_id": record.get("event_id"),
                    "detail": f"prev_hash at seq={record.get('seq')} does not match hash of seq={prev_record.get('seq')}",
                }
                issues.append(issue)
                if first_broken is None:
                    first_broken = record.get("seq")

        # 3. Verify sequence continuity
        if i > 0:
            expected_seq = records[i - 1].get("seq", 0) + 1
            if record.get("seq") != expected_seq:
                issue = {
                    "type": "SEQ_GAP",
                    "expected_seq": expected_seq,
                    "actual_seq": record.get("seq"),
                    "detail": f"Expected seq={expected_seq}, got seq={record.get('seq')}",
                }
                issues.append(issue)
                if first_broken is None:
                    first_broken = record.get("seq")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "first_broken_seq": first_broken,
        "records_checked": len(records),
    }


# ---------------------------------------------------------------------------
# Unit-level: Audit chain construction and verification
# ---------------------------------------------------------------------------

class TestAuditChainIntegrity:
    """
    Unit tests for the audit hash chain.
    These run without any external services.
    """

    def test_valid_chain_passes_verification(self, sample_audit_events):
        """An unmodified audit chain must pass verification."""
        result = verify_audit_chain(sample_audit_events)
        assert result["valid"] is True, f"Unexpected issues: {result['issues']}"
        assert result["first_broken_seq"] is None

    def test_empty_chain_passes(self):
        """Empty audit chain is valid (nothing to verify)."""
        result = verify_audit_chain([])
        assert result["valid"] is True

    def test_single_record_chain_passes(self, sample_audit_events):
        """A single-record chain must pass (no prev_hash check possible)."""
        result = verify_audit_chain([sample_audit_events[0]])
        assert result["valid"] is True


class TestAuditTamperingDetection:
    """
    Test that the verifier detects tampering in all forms.
    These are the authoritative tests for invariant I10.
    """

    def test_modified_field_detected(self, sample_audit_events):
        """
        A10: Modifying a field in a record must be detected.
        The record_hash no longer matches the computed hash.
        """
        tampered = copy.deepcopy(sample_audit_events)
        # Modify the amount in event 1 (if it has it)
        # We'll modify the event_type to simulate tampering
        tampered[1]["event_type"] = "EXECUTION_SUCCEEDED"  # was CAPABILITY_ISSUED

        result = verify_audit_chain(tampered)
        assert result["valid"] is False, \
            "SECURITY FAILURE: Modified audit record was not detected"
        assert result["first_broken_seq"] == 2, \
            f"Expected first broken at seq=2, got {result['first_broken_seq']}"
        assert any(i["type"] == "HASH_MISMATCH" for i in result["issues"])

    def test_deleted_record_detected(self, sample_audit_events):
        """
        A10: Deleting a record must be detected (sequence gap).
        """
        tampered = copy.deepcopy(sample_audit_events)
        # Remove record at index 1 (seq=2)
        del tampered[1]

        result = verify_audit_chain(tampered)
        assert result["valid"] is False, \
            "SECURITY FAILURE: Deleted audit record was not detected"
        assert any(
            i["type"] in ("SEQ_GAP", "CHAIN_BREAK") for i in result["issues"]
        ), f"Expected SEQ_GAP or CHAIN_BREAK, got: {result['issues']}"

    def test_reordered_records_detected(self, sample_audit_events):
        """
        A10: Swapping the order of two records must be detected.
        """
        tampered = copy.deepcopy(sample_audit_events)
        # Swap records 1 and 2
        tampered[1], tampered[2] = tampered[2], tampered[1]

        result = verify_audit_chain(tampered)
        assert result["valid"] is False, \
            "SECURITY FAILURE: Reordered audit records were not detected"

    def test_record_hash_forged_but_prev_hash_chain_breaks(self, sample_audit_events):
        """
        If an attacker modifies a record AND updates its record_hash,
        the chain break is detected in the NEXT record's prev_hash check.
        """
        tampered = copy.deepcopy(sample_audit_events)
        # Modify record 1's content and recompute its hash (forgery attempt)
        tampered[1]["event_type"] = "ATTACK_INJECTED"
        # Attacker recomputes record_hash for the modified record
        tampered[1]["record_hash"] = compute_record_hash(tampered[1])
        # But record 2's prev_hash still points to the ORIGINAL record 1 hash
        # → chain break at record 2

        result = verify_audit_chain(tampered)
        assert result["valid"] is False, \
            "SECURITY FAILURE: Chain break after forged hash was not detected"
        # The break is detected at seq=3 (record 2 points to wrong prev_hash)
        assert any(i["type"] == "CHAIN_BREAK" for i in result["issues"])

    def test_first_broken_seq_correctly_identified(self, sample_audit_events):
        """
        The verifier must correctly identify the FIRST broken link,
        not just any broken link.
        """
        tampered = copy.deepcopy(sample_audit_events)
        # Tamper with the SECOND record
        tampered[1]["event_type"] = "TAMPERED"

        result = verify_audit_chain(tampered)
        assert result["valid"] is False
        assert result["first_broken_seq"] == 2, \
            f"Expected first broken at seq=2, got {result['first_broken_seq']}"

    def test_record_hash_recomputation_is_deterministic(self, sample_audit_events):
        """
        compute_record_hash must be deterministic — same record → same hash.
        """
        record = sample_audit_events[0]
        h1 = compute_record_hash(record)
        h2 = compute_record_hash(record)
        assert h1 == h2

    def test_any_field_change_invalidates_record_hash(self, sample_audit_events):
        """Changing any field in a record invalidates its hash."""
        record = copy.deepcopy(sample_audit_events[1])
        original_hash = compute_record_hash(record)

        modified = copy.deepcopy(record)
        modified["tenant_id"] = "tenant-evil"
        modified_hash = compute_record_hash(modified)

        assert original_hash != modified_hash


# ---------------------------------------------------------------------------
# Integration tests (Gururaj implements against live services)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
class TestAuditTamperingIntegration:
    """
    A10: Audit tampering against live PostgreSQL audit records.
    """

    def test_modified_database_record_detected(self, gateway_url, valid_action_data):
        """
        1. Complete a valid execution (creates audit events)
        2. Directly modify an audit record in PostgreSQL
        3. Call POST /v1/audit/verify
        Expected: Response shows CHAIN_BREAK or HASH_MISMATCH with affected seq
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up and DB access.")

    def test_deleted_database_record_detected(self, gateway_url, valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up and DB access.")

    def test_reordered_database_records_detected(self, gateway_url, valid_action_data):
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up and DB access.")
