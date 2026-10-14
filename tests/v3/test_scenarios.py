"""
AgentShield V3 — Attacker B Scenario Tests
Owner: Pavan
"""
import pytest
from core.scenarios.replay_scenarios import run_scenario, list_scenarios, run_all_scenarios


class TestScenarioInterface:
    def test_list_scenarios_returns_8(self):
        scenarios = list_scenarios()
        assert len(scenarios) == 8

    def test_all_scenarios_have_required_fields(self):
        for s in list_scenarios():
            assert 'id' in s
            assert 'name' in s
            assert 'category' in s
            assert 'invariant_ref' in s

    def test_run_all_returns_8_results(self):
        results = run_all_scenarios()
        assert len(results) == 8

    def test_unknown_scenario_raises(self):
        with pytest.raises(KeyError):
            run_scenario("S99")

    def test_to_dict_is_json_serialisable(self):
        import json
        result = run_scenario("S1")
        d = result.to_dict()
        json.dumps(d)  # Should not raise


class TestAllAttacksBlocked:
    """ALL 8 attack scenarios must be blocked (attack_succeeded=False)."""

    @pytest.mark.parametrize("sid", ["S1","S2","S3","S4","S5","S6","S7","S8"])
    def test_attack_blocked(self, sid):
        result = run_scenario(sid)
        assert not result.attack_succeeded, \
            f"[{sid}] {result.scenario_name} — attack succeeded! result_code={result.result_code}"

    def test_all_have_invariant_reference(self):
        for result in run_all_scenarios():
            assert result.invariant_reference, f"{result.scenario_id} missing invariant_reference"

    def test_all_have_evidence(self):
        for result in run_all_scenarios():
            assert len(result.evidence) > 0, f"{result.scenario_id} has no evidence"


class TestConfigCBlocksEverything:
    def test_every_scenario_blocked_in_c(self):
        for result in run_all_scenarios():
            assert 'C' in result.blocked_in, \
                f"{result.scenario_id} not in blocked_in=['C'] — Config C should block all"


class TestConfigAAllowsMost:
    def test_most_scenarios_allowed_in_a(self):
        allowed_in_a = [r for r in run_all_scenarios() if 'A' in r.allowed_in]
        assert len(allowed_in_a) >= 5, \
            f"Config A should allow most attacks — only {len(allowed_in_a)}/8 allowed"


class TestIndividualScenarios:
    def test_s1_replay_evidence_has_attempts(self):
        r = run_scenario("S1")
        assert r.result_code == "JTI_ALREADY_CLAIMED"
        assert r.http_status == 409
        assert r.evidence["attempts"] == 5
        assert r.evidence["executions_succeeded"] == 1
        assert r.evidence["executions_rejected"] == 4

    def test_s2_expired_has_timing_evidence(self):
        r = run_scenario("S2")
        assert r.result_code == "CAPABILITY_EXPIRED"
        assert r.http_status == 401
        assert r.evidence["expired_by_seconds"] > 0

    def test_s3_revoked_blocked_in_c_only(self):
        """S3 is the key differentiator — B misses it, C catches it."""
        r = run_scenario("S3")
        assert r.result_code == "AGENT_REVOKED"
        assert 'C' in r.blocked_in
        assert 'B' in r.allowed_in   # Config B misses this attack
        assert 'A' in r.allowed_in

    def test_s5_policy_downgrade_blocked_in_c_only(self):
        """S5 is another B vs C differentiator."""
        r = run_scenario("S5")
        assert r.result_code == "POLICY_VERSION_STALE"
        assert 'C' in r.blocked_in
        assert 'B' in r.allowed_in

    def test_s8_fail_open_returns_503(self):
        r = run_scenario("S8")
        assert r.http_status == 503
        assert r.result_code == "POLICY_CHECK_UNAVAILABLE"
        assert r.evidence["default_to_allow"] is False
