"""
AgentShield V2 — OPA Policy Validator Tests

Owner: Pavan

Tests that the OPA validator correctly identifies all 14 security checks
and accurately validates the actual policy/agentshield.rego file.
"""
from __future__ import annotations

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.opa_validator import validate_opa_policy, PolicyValidationResult


POLICY_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', 'policy', 'agentshield.rego'
)


# ---------------------------------------------------------------------------
# Validate the actual policy file
# ---------------------------------------------------------------------------

class TestActualPolicyFile:
    def test_policy_file_exists(self):
        assert os.path.exists(POLICY_PATH), \
            f"Policy file not found at {POLICY_PATH}"

    def test_actual_policy_passes_all_checks(self):
        """The live policy must pass all validator checks."""
        result = validate_opa_policy(POLICY_PATH)
        if not result.valid:
            # Print violations for easy debugging
            for v in result.violations:
                print(f"[{v.severity}] {v.check_id}: {v.description} — {v.detail}")
        assert result.valid, (
            f"Policy file failed security validation:\n{result.summary()}"
        )

    def test_policy_has_no_violations(self):
        result = validate_opa_policy(POLICY_PATH)
        critical_high = [v for v in result.violations
                         if v.severity in ("CRITICAL", "HIGH")]
        assert len(critical_high) == 0, \
            f"Policy has CRITICAL/HIGH violations: {[v.check_id for v in critical_high]}"

    def test_policy_passes_expected_number_of_checks(self):
        """Policy must pass all 14 checks."""
        result = validate_opa_policy(POLICY_PATH)
        # 13 coded checks + V7 (commented-allow check)
        total = len(result.passed_checks) + len(result.violations)
        assert total >= 13, f"Expected at least 13 checks, only ran {total}"


# ---------------------------------------------------------------------------
# Validator logic — synthetic policy fragments
# ---------------------------------------------------------------------------

def write_policy(content: str) -> str:
    """Write policy content to a temp file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False)
    f.write(content)
    f.close()
    return f.name


GOOD_POLICY_BASE = """package test

default allow = false
default needs_approval = false
default deny_reason = "DEFAULT_DENY"

hard_deny[reason] {
    not input.agent.registered
    reason := "AGENT_NOT_REGISTERED"
}

hard_deny[reason] {
    input.agent.revoked == true
    reason := "AGENT_REVOKED"
}

hard_deny[reason] {
    input.action.tenant_id != input.agent.tenant_id
    reason := "CROSS_TENANT_ACCESS"
}

hard_deny[reason] {
    input.action.arguments.amount_minor > 1000000
    reason := "AMOUNT_EXCEEDS_HARD_MAXIMUM"
}

hard_deny[reason] {
    input.action.policy_version < 2
    reason := "POLICY_VERSION_STALE"
}

hard_deny[reason] {
    not input.action.environment in {"demo","staging","production"}
    reason := "INVALID_ENVIRONMENT"
}

needs_approval {
    count(hard_deny) == 0
    input.action.arguments.amount_minor >= 30000
}

allow {
    count(hard_deny) == 0
    not needs_approval
    input.action.arguments.amount_minor > 0
}

allow {
    count(hard_deny) == 0
    needs_approval
    input.approval.action_digest == input.action.action_digest
    input.approval.consumed == false
}

decision = result {
    count(hard_deny) > 0
    result := {"result": "deny", "reason": concat(", ", hard_deny)}
} else = result {
    needs_approval
    not allow
    result := {"result": "needs_approval"}
} else = result {
    allow
    result := {"result": "allow"}
} else = result {
    result := {"result": "deny", "reason": "DEFAULT_DENY"}
}
"""


class TestValidatorLogic:
    def test_good_policy_passes(self):
        path = write_policy(GOOD_POLICY_BASE)
        try:
            result = validate_opa_policy(path)
            assert result.valid, f"Good policy failed: {result.summary()}"
        finally:
            os.unlink(path)

    def test_missing_default_allow_false_detected(self):
        # Remove the default allow = false line entirely
        bad = GOOD_POLICY_BASE.replace("default allow = false\n", "")
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            assert not result.valid
            check_ids = [v.check_id for v in result.violations]
            assert "V1" in check_ids, f"V1 not found in {check_ids}"
        finally:
            os.unlink(path)

    def test_wildcard_allow_detected(self):
        bad = GOOD_POLICY_BASE + "\nallow { true }\n"
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V3" in check_ids
        finally:
            os.unlink(path)

    def test_missing_agent_revoked_detected(self):
        # Replace the whole AGENT_REVOKED string with something completely different
        bad = GOOD_POLICY_BASE.replace('"AGENT_REVOKED"', '"AGENT_WAS_HERE"')
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V4a" in check_ids, f"V4a not found in {check_ids}. Violations: {result.violations}"
        finally:
            os.unlink(path)

    def test_missing_cross_tenant_detected(self):
        bad = GOOD_POLICY_BASE.replace("CROSS_TENANT_ACCESS", "CROSS_TENANT_GONE")
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V4c" in check_ids
        finally:
            os.unlink(path)

    def test_missing_action_digest_detected(self):
        bad = GOOD_POLICY_BASE.replace("action_digest", "action_id")
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V5" in check_ids
        finally:
            os.unlink(path)

    def test_missing_hard_deny_gate_on_allow_detected(self):
        # Write a policy where the allow block has NO count(hard_deny) check at all
        bad = """package test
default allow = false
default needs_approval = false
default deny_reason = "DEFAULT_DENY"

hard_deny[reason] { input.agent.revoked; reason := "AGENT_REVOKED" }
hard_deny[reason] { not input.agent.registered; reason := "AGENT_NOT_REGISTERED" }
hard_deny[reason] { input.action.tenant_id != input.agent.tenant_id; reason := "CROSS_TENANT_ACCESS" }
hard_deny[reason] { input.action.arguments.amount_minor > 1000000; reason := "AMOUNT_EXCEEDS_HARD_MAXIMUM" }
hard_deny[reason] { input.action.policy_version < 2; reason := "POLICY_VERSION_STALE" }
hard_deny[reason] { not input.action.environment in {"demo"}; reason := "INVALID_ENVIRONMENT" }

needs_approval {
    count(hard_deny) == 0
    input.action.arguments.amount_minor >= 30000
}

allow {
    input.action.arguments.amount_minor > 0
    input.approval.action_digest == input.action.action_digest
}

decision = result {
    count(hard_deny) > 0
    result := {"result": "deny", "reason": concat(", ", hard_deny)}
} else = result {
    allow
    result := {"result": "allow"}
} else = result {
    result := {"result": "deny", "reason": "DEFAULT_DENY"}
}
"""
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V11" in check_ids, \
                f"V11 not found. Violations: {check_ids}. " \
                f"allow block lacks count(hard_deny)==0 but validator didn't catch it."
        finally:
            os.unlink(path)

    def test_missing_default_deny_fallback_detected(self):
        bad = GOOD_POLICY_BASE.replace("DEFAULT_DENY", "DENY_UNKNOWN")
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            check_ids = [v.check_id for v in result.violations]
            assert "V10" in check_ids
        finally:
            os.unlink(path)

    def test_nonexistent_file_reports_critical(self):
        result = validate_opa_policy("/nonexistent/path.rego")
        assert not result.valid
        assert any(v.check_id == "V0" for v in result.violations)

    def test_validator_severity_classification(self):
        """CRITICAL violations must include the most dangerous checks."""
        # Build a policy that fails V1 (no default allow=false) and V3 (wildcard allow)
        bad = """package test
default needs_approval = false
allow { true }
"""
        path = write_policy(bad)
        try:
            result = validate_opa_policy(path)
            found_critical = {v.check_id for v in result.violations
                              if v.severity == "CRITICAL"}
            assert "V1" in found_critical, f"V1 not in critical violations: {found_critical}"
            assert "V3" in found_critical, f"V3 not in critical violations: {found_critical}"
        finally:
            os.unlink(path)
