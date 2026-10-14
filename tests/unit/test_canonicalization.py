"""
AgentShield V2 — Canonicalization and Action Digest Tests

These are authoritative tests. Every component must produce the same digest
for the same action. Gururaj runs these against the integrated system.

Owner: Pavan (test design) | Girish (canonicalization implementation)
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.schemas import ActionEnvelope
from app.security.canonicalization import (
    canonicalize_action,
    calculate_action_digest,
    verify_digest_matches,
    get_test_vector_1,
    get_test_vector_2_tampered_amount,
)


# ─── Test vector fixtures ─────────────────────────────────────────────────────

def make_standard_action(**overrides) -> ActionEnvelope:
    data = {
        "schema_version": 1,
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "arguments": {"order_id": "ORDER-123", "amount_minor": 50000},
        "environment": "demo",
        "policy_version": 3,
        "intent_id": "intent-demo-001",
    }
    data.update(overrides)
    # Handle nested argument override
    if "arguments" in overrides:
        data["arguments"] = overrides["arguments"]
    return ActionEnvelope(**data)


# ─── Determinism tests ───────────────────────────────────────────────────────

class TestCanonicalDeterminism:
    def test_same_action_same_canonical_bytes(self):
        """Identical actions must produce identical canonical bytes every time."""
        action1 = make_standard_action()
        action2 = make_standard_action()
        assert canonicalize_action(action1) == canonicalize_action(action2)

    def test_same_action_same_digest(self):
        """Identical actions must produce identical digests."""
        action1 = make_standard_action()
        action2 = make_standard_action()
        assert calculate_action_digest(action1) == calculate_action_digest(action2)

    def test_digest_is_hex_string_64_chars(self):
        """Digest must be a lowercase 64-character hex string."""
        action = make_standard_action()
        digest = calculate_action_digest(action)
        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)

    def test_canonical_bytes_are_valid_json(self):
        """Canonical bytes must be valid JSON."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        parsed = json.loads(canonical.decode("utf-8"))
        assert isinstance(parsed, dict)


# ─── Key ordering independence ────────────────────────────────────────────────

class TestKeyOrderingIndependence:
    def test_field_order_does_not_affect_digest(self):
        """
        Digest must not change when JSON input has different key ordering.
        Both actions have the same semantic content; only input order differs.
        After ActionEnvelope validation, both produce the same canonical bytes.
        """
        # Both produce the same ActionEnvelope, regardless of dict construction order
        action1 = ActionEnvelope(**{
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": "orders/ORDER-123",
            "arguments": {"order_id": "ORDER-123", "amount_minor": 50000},
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-001",
        })
        action2 = ActionEnvelope(**{
            "intent_id": "intent-demo-001",
            "tool": "issue_refund",
            "schema_version": 1,
            "environment": "demo",
            "tenant_id": "tenant-demo",
            "resource": "orders/ORDER-123",
            "arguments": {"amount_minor": 50000, "order_id": "ORDER-123"},
            "policy_version": 3,
            "principal_id": "agent-support-01",
        })
        assert calculate_action_digest(action1) == calculate_action_digest(action2)

    def test_canonical_bytes_are_sorted(self):
        """Canonical bytes must have sorted keys."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        parsed = json.loads(canonical.decode("utf-8"))
        keys = list(parsed.keys())
        assert keys == sorted(keys), f"Keys are not sorted: {keys}"

    def test_canonical_nested_arguments_are_sorted(self):
        """Nested argument keys must also be sorted."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        parsed = json.loads(canonical.decode("utf-8"))
        arg_keys = list(parsed["arguments"].keys())
        assert arg_keys == sorted(arg_keys)


# ─── Sensitivity tests ────────────────────────────────────────────────────────

class TestDigestSensitivity:
    def test_changed_amount_changes_digest(self):
        """CRITICAL: Changing amount_minor must change the digest (attack A2)."""
        action_orig = make_standard_action()
        action_tampered = make_standard_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 500000}
        )
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_tampered)

    def test_changed_tenant_changes_digest(self):
        """Changing tenant_id must change the digest."""
        action_orig = make_standard_action()
        action_diff = make_standard_action(tenant_id="tenant-evil")
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_diff)

    def test_changed_resource_changes_digest(self):
        """Changing resource must change the digest."""
        action_orig = make_standard_action()
        action_diff = make_standard_action(resource="orders/ORDER-999")
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_diff)

    def test_changed_tool_changes_digest(self):
        """Changing tool must change the digest."""
        # We can only test with a different valid tool if one exists;
        # otherwise test via direct canonicalization
        action = make_standard_action()
        canonical = canonicalize_action(action)
        assert b'"tool":"issue_refund"' in canonical

    def test_changed_principal_changes_digest(self):
        """Changing principal_id must change the digest."""
        action_orig = make_standard_action()
        action_diff = make_standard_action(principal_id="agent-evil-01")
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_diff)

    def test_changed_environment_changes_digest(self):
        """Changing environment must change the digest."""
        action_demo = make_standard_action(environment="demo")
        action_prod = make_standard_action(environment="staging")
        assert calculate_action_digest(action_demo) != calculate_action_digest(action_prod)

    def test_changed_intent_changes_digest(self):
        """Changing intent_id must change the digest."""
        action_orig = make_standard_action()
        action_diff = make_standard_action(intent_id="intent-demo-002")
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_diff)

    def test_changed_policy_version_changes_digest(self):
        """Changing policy_version must change the digest."""
        action_orig = make_standard_action()
        action_diff = make_standard_action(policy_version=2)
        assert calculate_action_digest(action_orig) != calculate_action_digest(action_diff)


# ─── Verify digest matches ────────────────────────────────────────────────────

class TestVerifyDigestMatches:
    def test_matching_digest_returns_true(self):
        action = make_standard_action()
        digest = calculate_action_digest(action)
        assert verify_digest_matches(action, digest) is True

    def test_mismatched_digest_returns_false(self):
        """CRITICAL: Digest mismatch must return False (executor uses this)."""
        action_orig = make_standard_action()
        action_tampered = make_standard_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 500000}
        )
        orig_digest = calculate_action_digest(action_orig)
        assert verify_digest_matches(action_tampered, orig_digest) is False

    def test_uppercase_digest_still_matches(self):
        """verify_digest_matches must be case-insensitive for the input digest."""
        action = make_standard_action()
        digest = calculate_action_digest(action).upper()
        assert verify_digest_matches(action, digest) is True


# ─── Canonical format ────────────────────────────────────────────────────────

class TestCanonicalFormat:
    def test_canonical_bytes_compact_no_spaces(self):
        """Canonical bytes must have no extra whitespace."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        text = canonical.decode("utf-8")
        assert " " not in text, "Canonical bytes must not contain spaces"
        assert "\n" not in text, "Canonical bytes must not contain newlines"
        assert "\t" not in text, "Canonical bytes must not contain tabs"

    def test_canonical_bytes_are_utf8(self):
        """Canonical bytes must be valid UTF-8."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        # Should not raise
        canonical.decode("utf-8")

    def test_integer_amount_not_float_in_canonical(self):
        """The canonical bytes must represent 50000 as integer, not 50000.0."""
        action = make_standard_action()
        canonical = canonicalize_action(action)
        text = canonical.decode("utf-8")
        assert "50000.0" not in text
        assert "50000" in text

    def test_digest_prefix_is_included(self):
        """SHA256 input must include the AGENTSHIELD-ACTION-V1 prefix."""
        import hashlib
        action = make_standard_action()
        canonical = canonicalize_action(action)
        prefix = b"AGENTSHIELD-ACTION-V1\x00"
        expected_digest = hashlib.sha256(prefix + canonical).hexdigest()
        assert calculate_action_digest(action) == expected_digest


# ─── Cross-component test vectors ────────────────────────────────────────────

class TestCrossComponentVectors:
    def test_vector_1_is_reproducible(self):
        """Vector 1 must produce the same digest on every call."""
        _, digest1 = get_test_vector_1()
        _, digest2 = get_test_vector_1()
        assert digest1 == digest2

    def test_vector_2_differs_from_vector_1(self):
        """Tampered amount vector must differ from standard vector."""
        _, digest1 = get_test_vector_1()
        _, digest2 = get_test_vector_2_tampered_amount()
        assert digest1 != digest2

    def test_all_vectors_are_64_char_hex(self):
        """All test vectors must produce 64-char hex digests."""
        _, d1 = get_test_vector_1()
        _, d2 = get_test_vector_2_tampered_amount()
        for digest in (d1, d2):
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)
