"""
AgentShield V2 — Canonical Action Representation and Action Digest

Owner: Girish (implementation) | Pavan (specification)

This is the ONLY canonicalization implementation in the codebase.
Both the gateway and the executor import from this module.
Do NOT create alternative implementations.

Canonicalization rules (from ACTION_CONTRACT.md):
1. All string values are UTF-8 encoded.
2. Top-level fields appear in alphabetical order (sort_keys=True).
3. Nested object fields are also sorted alphabetically.
4. Integers are represented without decimal points (50000, not 50000.0).
5. No leading/trailing whitespace in identifier fields.
6. Required fields must be present and non-null.
7. Unknown fields must be rejected before this function is called (Pydantic handles this).
8. Duplicate JSON keys must be rejected before this function is called.
9. Compact serialization: no extra whitespace, separators=(',', ':').
10. Null values for optional fields are excluded from canonical bytes.

Digest construction:
    action_digest = SHA256(b"AGENTSHIELD-ACTION-V1\x00" + canonical_bytes)
    Encoded as lowercase hex string (64 chars).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .schemas import ActionEnvelope


# The canonical prefix bytes — fixed, never changes.
_DIGEST_PREFIX: bytes = b"AGENTSHIELD-ACTION-V1\x00"


def _remove_none_values(obj: Any) -> Any:
    """
    Recursively remove None values from a dict.
    Optional fields that are None are excluded from canonical bytes.
    """
    if isinstance(obj, dict):
        return {k: _remove_none_values(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_remove_none_values(item) for item in obj]
    return obj


def canonicalize_action(action: ActionEnvelope) -> bytes:
    """
    Produce deterministic canonical bytes from a validated ActionEnvelope.

    Args:
        action: A fully validated ActionEnvelope instance.

    Returns:
        UTF-8 encoded canonical JSON bytes with sorted keys and compact separators.

    Raises:
        ValueError: If the action cannot be canonicalized.
    """
    # Build the canonical dict from the validated action.
    # We use model_dump to get the Python dict, then serialize it.
    # Using model_dump ensures Pydantic has already validated all fields.
    action_dict = action.model_dump(mode="python", exclude_none=True)

    # Convert environment enum to its string value
    if hasattr(action_dict.get("environment"), "value"):
        action_dict["environment"] = action_dict["environment"].value
    elif isinstance(action_dict.get("environment"), str):
        pass  # already a string

    # Remove None values recursively (optional fields)
    clean_dict = _remove_none_values(action_dict)

    # Serialize with sorted keys and compact separators
    # This is the canonical representation.
    canonical_bytes = json.dumps(
        clean_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,     # Allow non-ASCII UTF-8 characters
    ).encode("utf-8")

    return canonical_bytes


def calculate_action_digest(action: ActionEnvelope) -> str:
    """
    Calculate the SHA-256 action digest for a validated ActionEnvelope.

    digest = SHA256(b"AGENTSHIELD-ACTION-V1\\x00" + canonical_bytes)

    Args:
        action: A fully validated ActionEnvelope instance.

    Returns:
        Lowercase hex-encoded SHA-256 digest string (64 characters).
    """
    canonical_bytes = canonicalize_action(action)
    digest = hashlib.sha256(_DIGEST_PREFIX + canonical_bytes).hexdigest()
    return digest


def verify_digest_matches(action: ActionEnvelope, expected_digest: str) -> bool:
    """
    Verify that the action's computed digest matches the expected digest.

    Used by the executor to verify that the execution-time action
    matches the capability-bound digest.

    Args:
        action: The action submitted for execution.
        expected_digest: The action_digest embedded in the capability token.

    Returns:
        True if digests match exactly. False otherwise.
    """
    computed = calculate_action_digest(action)
    # Use constant-time comparison to avoid timing attacks on the digest comparison.
    # hmac.compare_digest is appropriate here.
    import hmac
    return hmac.compare_digest(computed, expected_digest.lower())


# ---------------------------------------------------------------------------
# Test Vectors
# ---------------------------------------------------------------------------
# These vectors are authoritative. Every component must produce these outputs.
# Gururaj runs these as part of the test suite.

def get_test_vector_1() -> tuple[ActionEnvelope, str]:
    """
    Test Vector 1 — Standard refund.

    canonical JSON (sorted keys, compact):
    {"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},
     "environment":"demo","intent_id":"intent-demo-001",
     "policy_version":3,"principal_id":"agent-support-01",
     "resource":"orders/ORDER-123","schema_version":1,
     "tenant_id":"tenant-demo","tool":"issue_refund"}
    """
    action = ActionEnvelope(
        schema_version=1,
        tenant_id="tenant-demo",
        principal_id="agent-support-01",
        tool="issue_refund",
        resource="orders/ORDER-123",
        arguments={"order_id": "ORDER-123", "amount_minor": 50000},
        environment="demo",
        policy_version=3,
        intent_id="intent-demo-001",
    )
    # The actual digest is computed — no hardcoding.
    digest = calculate_action_digest(action)
    return action, digest


def get_test_vector_2_tampered_amount() -> tuple[ActionEnvelope, str]:
    """
    Test Vector 2 — Tampered amount (500000 instead of 50000).
    Digest MUST differ from Vector 1.
    """
    action = ActionEnvelope(
        schema_version=1,
        tenant_id="tenant-demo",
        principal_id="agent-support-01",
        tool="issue_refund",
        resource="orders/ORDER-123",
        arguments={"order_id": "ORDER-123", "amount_minor": 500000},
        environment="demo",
        policy_version=3,
        intent_id="intent-demo-001",
    )
    digest = calculate_action_digest(action)
    return action, digest


def print_test_vectors() -> None:
    """Print all test vectors for cross-component verification."""
    action1, digest1 = get_test_vector_1()
    action2, digest2 = get_test_vector_2_tampered_amount()
    canonical1 = canonicalize_action(action1)

    print("=== AgentShield V2 — Canonical Action Test Vectors ===")
    print()
    print("Vector 1 — Standard refund:")
    print(f"  Canonical bytes: {canonical1.decode('utf-8')}")
    print(f"  Action digest:   {digest1}")
    print()
    print("Vector 2 — Tampered amount (500000):")
    print(f"  Action digest:   {digest2}")
    print()
    print(f"Digests differ: {digest1 != digest2}")


if __name__ == "__main__":
    print_test_vectors()
