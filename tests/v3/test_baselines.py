"""
AgentShield V3 — Baseline Configuration Tests
Owner: Pavan

Verifies that Config A, B, C have the correct enforcement flags.
These tests are the specification — if they pass, the configs are correct.
"""
import pytest
from core.baselines import (
    Baseline, CONFIG_A, CONFIG_B, CONFIG_C, CONFIGS,
    analyse_attack_surface, compare_baselines,
)


class TestConfigA:
    """Config A is deliberately weak — verify it IS weak (for contrast)."""

    def test_config_a_no_digest_recompute(self):
        """Config A doesn't recompute digest — action substitution succeeds."""
        assert CONFIG_A.digest_recompute is False

    def test_config_a_no_replay_prevention(self):
        """Config A has no replay prevention."""
        assert CONFIG_A.replay_prevention is False

    def test_config_a_no_revocation_recheck(self):
        """Config A doesn't re-check revocation at execution."""
        assert CONFIG_A.revocation_recheck is False

    def test_config_a_no_opa(self):
        """Config A has no OPA policy evaluation."""
        assert CONFIG_A.opa_policy_evaluation is False

    def test_config_a_no_audit_chain(self):
        """Config A has no hash-chained audit."""
        assert CONFIG_A.audit_hash_chain is False

    def test_config_a_protection_score_low(self):
        report = analyse_attack_surface(Baseline.A)
        assert report.protection_score < 0.4, \
            f"Config A should be low protection, got {report.protection_score:.0%}"


class TestConfigB:
    """Config B catches the perimeter but misses executor-side attacks."""

    def test_config_b_has_opa(self):
        assert CONFIG_B.opa_policy_evaluation is True

    def test_config_b_has_schema_validation(self):
        assert CONFIG_B.schema_validation is True

    def test_config_b_has_identity_from_credentials(self):
        assert CONFIG_B.identity_from_credentials is True

    def test_config_b_no_digest_recompute(self):
        """B doesn't recompute digest at executor — substitution still works post-gateway."""
        assert CONFIG_B.digest_recompute is False

    def test_config_b_no_revocation_recheck(self):
        """B doesn't re-check revocation at executor — race window exists."""
        assert CONFIG_B.revocation_recheck is False

    def test_config_b_no_executor_opa(self):
        """B doesn't re-query OPA at executor — policy drift undetected."""
        assert CONFIG_B.opa_recheck_executor is False

    def test_config_b_mid_range_protection(self):
        report = analyse_attack_surface(Baseline.B)
        assert 0.4 <= report.protection_score < 0.85, \
            f"Config B should be mid-range, got {report.protection_score:.0%}"


class TestConfigC:
    """Config C must have ALL enforcement flags active."""

    def test_config_c_all_executor_checks(self):
        assert CONFIG_C.digest_recompute is True
        assert CONFIG_C.revocation_recheck is True
        assert CONFIG_C.replay_prevention is True
        assert CONFIG_C.approval_recheck is True
        assert CONFIG_C.opa_recheck_executor is True
        assert CONFIG_C.atomic_state_claim is True

    def test_config_c_all_gateway_checks(self):
        assert CONFIG_C.schema_validation is True
        assert CONFIG_C.identity_from_credentials is True
        assert CONFIG_C.resource_ownership_check is True
        assert CONFIG_C.opa_policy_evaluation is True

    def test_config_c_full_audit(self):
        assert CONFIG_C.audit_hash_chain is True
        assert CONFIG_C.receipt_signing is True
        assert CONFIG_C.independent_verifier is True
        assert CONFIG_C.drift_detection is True

    def test_config_c_delegation_controls(self):
        assert CONFIG_C.delegation_scope_bound is True
        assert CONFIG_C.policy_version_enforce is True

    def test_config_c_full_protection(self):
        report = analyse_attack_surface(Baseline.C)
        assert report.protection_score == 1.0, \
            f"Config C must have 100% protection score, got {report.protection_score:.0%}"
        assert len(report.open_attack_surfaces) == 0

    def test_config_c_no_open_surfaces(self):
        report = analyse_attack_surface(Baseline.C)
        assert report.open_attack_surfaces == [], \
            f"Config C should have no open surfaces: {report.open_attack_surfaces}"


class TestBaselineOrdering:
    """Verify protection scores are ordered A < B < C."""

    def test_protection_score_ordering(self):
        score_a = analyse_attack_surface(Baseline.A).protection_score
        score_b = analyse_attack_surface(Baseline.B).protection_score
        score_c = analyse_attack_surface(Baseline.C).protection_score
        assert score_a < score_b < score_c, \
            f"Expected A < B < C, got A={score_a:.2f} B={score_b:.2f} C={score_c:.2f}"

    def test_compare_baselines_runs(self):
        output = compare_baselines()
        assert "Config A" in output
        assert "Config B" in output
        assert "Config C" in output

    def test_all_baselines_present_in_configs(self):
        assert Baseline.A in CONFIGS
        assert Baseline.B in CONFIGS
        assert Baseline.C in CONFIGS
