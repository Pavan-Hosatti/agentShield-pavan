"""
AgentShield V2 — Tamper-Evident Audit Chain

Owner: Girish (signing integration) | Pavan (chain construction specification)

Each audit record includes SHA-256 of the previous record (hash-chain).
An independent verifier detects modification, deletion, and reordering.

Invariant I10: Audit alteration is detected under documented assumptions.

LIMITATION (documented in ADR-010 and THREAT_MODEL §T13):
  A hash chain alone cannot detect an attacker who rewrites the entire chain
  AND controls the signing key. External checkpointing mitigates this (optional).

Chain hash input:
  SHA256(sorted compact JSON of the record EXCLUDING the record_hash field)
"""
from __future__ import annotations

import hashlib
import json
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

# Sentinel for the genesis record's prev_hash
GENESIS_PREV_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Audit event types
# ---------------------------------------------------------------------------

class AuditEventType:
    ACTION_AUTHORIZED          = "ACTION_AUTHORIZED"
    CAPABILITY_ISSUED          = "CAPABILITY_ISSUED"
    EXECUTION_CLAIMED          = "EXECUTION_CLAIMED"
    EXECUTION_RUNNING          = "EXECUTION_RUNNING"
    EXECUTION_SUCCEEDED        = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED           = "EXECUTION_FAILED"
    EXECUTION_UNKNOWN          = "EXECUTION_UNKNOWN"
    EXECUTION_DENIED           = "EXECUTION_DENIED"
    AGENT_REVOKED              = "AGENT_REVOKED"
    APPROVAL_REQUESTED         = "APPROVAL_REQUESTED"
    APPROVAL_SUBMITTED         = "APPROVAL_SUBMITTED"
    APPROVAL_CONSUMED          = "APPROVAL_CONSUMED"
    AUDIT_CHAIN_VERIFIED       = "AUDIT_CHAIN_VERIFIED"
    AUDIT_TAMPERING_DETECTED   = "AUDIT_TAMPERING_DETECTED"


# ---------------------------------------------------------------------------
# Chain hash computation
# ---------------------------------------------------------------------------

def compute_record_hash(record: dict[str, Any]) -> str:
    """
    Compute the SHA-256 hash of an audit record.

    record_hash is excluded from the hash input (it is the result).
    prev_hash IS included (it chains to the previous record).

    Returns:
        64-character lowercase hex string.
    """
    record_for_hashing = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(record_for_hashing, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_audit_record(
    *,
    seq: int,
    event_type: str,
    tenant_id: str,
    principal_id: Optional[str] = None,
    action_digest: Optional[str] = None,
    jti: Optional[str] = None,
    execution_id: Optional[str] = None,
    approval_id: Optional[str] = None,
    prev_hash: str,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build a single audit record with hash chaining.

    Args:
        seq:        Monotonically increasing sequence number.
        prev_hash:  record_hash of the immediately preceding record.
                    Use GENESIS_PREV_HASH for the first record.

    Returns:
        Complete audit record dict with record_hash computed.
    """
    record: dict[str, Any] = {
        "seq": seq,
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "action_digest": action_digest,
        "jti": jti,
        "execution_id": execution_id,
        "approval_id": approval_id,
        "prev_hash": prev_hash,
    }
    if extra:
        record["extra"] = extra

    record["record_hash"] = compute_record_hash(record)
    return record


# ---------------------------------------------------------------------------
# Verification report
# ---------------------------------------------------------------------------

@dataclass
class AuditIssue:
    issue_type: str        # HASH_MISMATCH | CHAIN_BREAK | SEQ_GAP | DUPLICATE_SEQ
    seq: Optional[int]
    event_id: Optional[str]
    detail: str


@dataclass
class AuditVerificationReport:
    valid: bool
    records_checked: int
    issues: list[AuditIssue] = field(default_factory=list)
    first_broken_seq: Optional[int] = None

    def summary(self) -> str:
        if self.valid:
            return f"VALID — {self.records_checked} records verified, no issues"
        lines = [f"INVALID — {len(self.issues)} issue(s) in {self.records_checked} records"]
        for issue in self.issues[:10]:  # cap output
            lines.append(f"  [{issue.issue_type}] seq={issue.seq}: {issue.detail}")
        if len(self.issues) > 10:
            lines.append(f"  ... and {len(self.issues) - 10} more")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Independent verifier
# ---------------------------------------------------------------------------

def verify_audit_chain(records: list[dict[str, Any]]) -> AuditVerificationReport:
    """
    Independently verify the integrity of an audit chain.

    Checks:
      1. record_hash matches computed hash (detects field modification)
      2. prev_hash links to previous record (detects insertion/deletion)
      3. Sequence numbers are contiguous (detects missing records)
      4. No duplicate sequence numbers

    Args:
        records: List of audit records ordered by seq ascending.

    Returns:
        AuditVerificationReport — always structured, never raises.
    """
    if not records:
        return AuditVerificationReport(valid=True, records_checked=0)

    issues: list[AuditIssue] = []
    first_broken: Optional[int] = None

    def add_issue(issue_type: str, seq: Optional[int],
                  event_id: Optional[str], detail: str) -> None:
        nonlocal first_broken
        issues.append(AuditIssue(issue_type=issue_type, seq=seq,
                                 event_id=event_id, detail=detail))
        if first_broken is None and seq is not None:
            first_broken = seq

    seen_seqs: set[int] = set()

    for i, record in enumerate(records):
        seq = record.get("seq")
        event_id = record.get("event_id")

        # Duplicate sequence numbers
        if seq in seen_seqs:
            add_issue("DUPLICATE_SEQ", seq, event_id,
                      f"Duplicate sequence number seq={seq}")
        else:
            seen_seqs.add(seq)

        # 1. record_hash integrity
        expected_hash = compute_record_hash(record)
        if record.get("record_hash") != expected_hash:
            add_issue("HASH_MISMATCH", seq, event_id,
                      f"record_hash mismatch at seq={seq}: "
                      f"stored={record.get('record_hash', 'MISSING')[:16]}... "
                      f"computed={expected_hash[:16]}...")

        # 2. Chain link
        if i > 0:
            prev = records[i - 1]
            if record.get("prev_hash") != prev.get("record_hash"):
                add_issue("CHAIN_BREAK", seq, event_id,
                          f"prev_hash mismatch at seq={seq}: "
                          f"expected={prev.get('record_hash', 'MISSING')[:16]}... "
                          f"got={record.get('prev_hash', 'MISSING')[:16]}...")

        # 3. Sequence gap
        if i > 0:
            prev_seq = records[i - 1].get("seq", 0)
            if isinstance(seq, int) and isinstance(prev_seq, int):
                if seq != prev_seq + 1:
                    add_issue("SEQ_GAP", seq, event_id,
                              f"Expected seq={prev_seq + 1}, got seq={seq}")

    return AuditVerificationReport(
        valid=len(issues) == 0,
        records_checked=len(records),
        issues=issues,
        first_broken_seq=first_broken,
    )


def get_chain_head_hash(records: list[dict[str, Any]]) -> Optional[str]:
    """Return the record_hash of the last record (the chain head)."""
    if not records:
        return None
    return records[-1].get("record_hash")
