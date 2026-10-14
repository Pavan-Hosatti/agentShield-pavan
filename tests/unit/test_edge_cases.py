"""
AgentShield V2 — Edge Case Tests

Owner: Pavan

Tests all edge cases from ATTACK_MATRIX §Additional Edge Cases (E1-E12).
These are schema-level and canonicalization-level rejections that must
happen BEFORE any policy evaluation or capability issuance.

E1  — Float amount
E2  — Duplicate JSON key
E3  — Unknown field
E4  — Expired capability (documented; integration test needed)
E5  — Invalid signature (documented; Girish's test)
E6  — Unknown key_id (documented; Girish's test)
E7  — Cross-tenant resource (policy test)
E8  — Unknown tool
E9  — Policy version below minimum
E10 — Rejected approval (approval_binding test)
E11 — Expired approval (approval_binding test)
E12 — Null amount_minor
"""
from __future__ import annotations

import json
import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from pydantic import ValidationError
from app.security.schemas import ActionEnvelope
from app.security.canonicalization import calculate_action_digest, canonicalize_action


def base_action(**overrides) -> dict:
    d = {
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
    d.update(overrides)
    return d


# ---------------------------------------------------------------------------
# E1 — Float amount (422 expected)
# ---------------------------------------------------------------------------

class TestE1FloatAmount:
    def test_float_amount_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 500.0}
            ))
        assert "float" in str(exc.value).lower() or "integer" in str(exc.value).lower()

    def test_float_amount_as_string_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123", "amount_minor": "500.00"}
            ))

    def test_scientific_notation_amount_rejected(self):
        """5e4 = 50000.0 but is a float — must be rejected."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 5e4}
            ))

    def test_integer_amount_accepted(self):
        """Control: integer amount is accepted."""
        a = ActionEnvelope(**base_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 50000}
        ))
        assert a.arguments["amount_minor"] == 50000


# ---------------------------------------------------------------------------
# E2 — Duplicate JSON keys
# ---------------------------------------------------------------------------

class TestE2DuplicateKeys:
    def test_pydantic_last_key_wins_warning(self):
        """
        Standard Python dicts deduplicate keys silently.
        The real protection is at JSON parsing level (before Pydantic).
        This test documents what Pydantic does: last value wins.
        Alok must implement duplicate-key detection in the JSON parser middleware.
        """
        # In Python dict literals, last key wins — Pydantic will see amount=999999
        data = base_action()
        data["arguments"] = {"order_id": "ORDER-123",
                              "amount_minor": 50000,
                              "amount_minor": 999999}  # noqa: F601
        action = ActionEnvelope(**data)
        # Python dict deduplication: last value = 999999
        assert action.arguments["amount_minor"] == 999999

    def test_json_with_duplicate_keys_must_be_caught_at_parse(self):
        """
        Alok: the API endpoint must parse JSON with duplicate-key rejection.
        Use a custom JSON parser that raises on duplicates.
        This test documents the requirement; the enforcement is in the HTTP layer.
        """
        import json

        def parse_strict(s: str) -> dict:
            """Example strict parser that rejects duplicate keys."""
            seen = {}
            def object_pairs_hook(pairs):
                result = {}
                for k, v in pairs:
                    if k in result:
                        raise ValueError(f"Duplicate JSON key: {k!r}")
                    result[k] = v
                return result
            return json.loads(s, object_pairs_hook=object_pairs_hook)

        # Normal JSON: OK
        normal = '{"amount_minor": 50000, "order_id": "ORDER-123"}'
        assert parse_strict(normal)["amount_minor"] == 50000

        # Duplicate key: must raise
        dup = '{"amount_minor": 50000, "amount_minor": 999999}'
        with pytest.raises(ValueError, match="Duplicate"):
            parse_strict(dup)


# ---------------------------------------------------------------------------
# E3 — Unknown field
# ---------------------------------------------------------------------------

class TestE3UnknownField:
    def test_unknown_top_level_field_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(injected_extra_field="malicious"))

    def test_unknown_nested_argument_field_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123", "amount_minor": 50000,
                           "bypass_check": True}
            ))

    def test_sql_injection_in_tenant_id(self):
        """SQL injection in tenant_id: schema passes, but identity check in gateway blocks it."""
        # Pydantic accepts any string — the gateway must validate against registered identity.
        # This test ensures we don't accidentally strip/sanitize and allow a bypass.
        action = ActionEnvelope(**base_action(tenant_id="tenant-demo'; DROP TABLE agents;--"))
        # The value is preserved as-is (not sanitized by schema).
        # The gateway must reject it because it won't match any registered tenant.
        assert "DROP TABLE" in action.tenant_id


# ---------------------------------------------------------------------------
# E8 — Unknown tool
# ---------------------------------------------------------------------------

class TestE8UnknownTool:
    def test_unknown_tool_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ActionEnvelope(**base_action(tool="wire_transfer"))
        assert "wire_transfer" in str(exc.value) or "unknown tool" in str(exc.value).lower()

    def test_empty_tool_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(tool=""))

    def test_sql_injection_tool_rejected(self):
        """SQL injection in tool name: rejected as unknown tool."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(tool="issue_refund; DROP TABLE agents"))

    def test_known_tool_accepted(self):
        action = ActionEnvelope(**base_action(tool="issue_refund"))
        assert action.tool == "issue_refund"


# ---------------------------------------------------------------------------
# E9 — Policy version below minimum
# ---------------------------------------------------------------------------

class TestE9PolicyVersion:
    def test_policy_version_zero_rejected_by_schema(self):
        """policy_version must be >= 1 at schema level."""
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(policy_version=0))

    def test_policy_version_negative_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(policy_version=-1))

    def test_policy_version_1_accepted_by_schema_rejected_by_policy(self):
        """
        policy_version=1 passes schema validation (ge=1) but is rejected
        by the OPA policy (minimum is 2).
        """
        action = ActionEnvelope(**base_action(policy_version=1))
        assert action.policy_version == 1
        # The policy check happens at OPA, not at schema level.
        # test_policy.py covers the OPA rejection of stale versions.

    def test_policy_version_3_accepted(self):
        action = ActionEnvelope(**base_action(policy_version=3))
        assert action.policy_version == 3


# ---------------------------------------------------------------------------
# E12 — Null amount_minor
# ---------------------------------------------------------------------------

class TestE12NullAmount:
    def test_null_amount_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123", "amount_minor": None}
            ))

    def test_missing_amount_rejected(self):
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(
                arguments={"order_id": "ORDER-123"}  # amount_minor missing
            ))


# ---------------------------------------------------------------------------
# Canonicalization edge cases
# ---------------------------------------------------------------------------

class TestCanonicalizationEdgeCases:
    def test_unicode_in_order_id_preserved(self):
        """Unicode characters in string fields must be preserved in canonical bytes."""
        action = ActionEnvelope(**base_action(
            arguments={"order_id": "ORDER-\u00e9-123", "amount_minor": 50000}
        ))
        canonical = canonicalize_action(action)
        assert "\u00e9".encode("utf-8") in canonical

    def test_long_intent_id_accepted(self):
        """Intent IDs up to max_length are accepted."""
        long_id = "intent-" + "x" * 121  # max 128
        action = ActionEnvelope(**base_action(intent_id=long_id))
        assert len(action.intent_id) <= 128

    def test_oversized_intent_id_rejected(self):
        """Intent IDs above 128 chars are rejected."""
        too_long = "intent-" + "x" * 200
        with pytest.raises(ValidationError):
            ActionEnvelope(**base_action(intent_id=too_long))

    def test_all_supported_environments_produce_different_digests(self):
        """Each environment value must produce a distinct digest."""
        envs = ["demo", "staging", "production"]
        digests = set()
        for env in envs:
            a = ActionEnvelope(**base_action(environment=env))
            digests.add(calculate_action_digest(a))
        assert len(digests) == 3, "Some environments produced identical digests"

    def test_canonical_bytes_match_spec_format(self):
        """Canonical bytes must be compact JSON with sorted keys."""
        action = ActionEnvelope(**base_action())
        canonical = canonicalize_action(action)
        text = canonical.decode("utf-8")
        # Must start with { and end with }
        assert text.startswith("{") and text.endswith("}")
        # No pretty-printing
        assert "\n" not in text and "  " not in text
        # Parse and verify sorted keys
        parsed = json.loads(text)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_amount_boundary_values_produce_different_digests(self):
        """Adjacent amount values must produce different digests."""
        d1 = calculate_action_digest(ActionEnvelope(**base_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 29999}
        )))
        d2 = calculate_action_digest(ActionEnvelope(**base_action(
            arguments={"order_id": "ORDER-123", "amount_minor": 30000}
        )))
        assert d1 != d2

    def test_schema_version_in_canonical_bytes(self):
        """schema_version must appear in canonical bytes."""
        action = ActionEnvelope(**base_action())
        canonical = canonicalize_action(action)
        assert b'"schema_version":1' in canonical

    def test_policy_version_in_canonical_bytes(self):
        action = ActionEnvelope(**base_action(policy_version=3))
        canonical = canonicalize_action(action)
        assert b'"policy_version":3' in canonical
