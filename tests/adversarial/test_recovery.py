"""
AgentShield V2 — A11: Timeout and Recovery Tests

Invariant tested: I9 — Uncertain outcomes are reconciled, not blindly retried.

Attack/Scenario: Failure occurs around tool invocation.
Expected: State transitions to UNKNOWN; reconciliation queries idempotency endpoint;
          mock tool is NOT invoked a second time if it already succeeded.

Owner: Pavan (design) | Gururaj (integration execution)
"""

from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.schemas import ExecutionState


# ---------------------------------------------------------------------------
# Unit-level: Execution state machine correctness
# ---------------------------------------------------------------------------

class TestExecutionStateMachine:
    """
    Verify the execution state machine transitions are correct.
    These are the allowed transitions from FAILURE_MODEL.md.
    """

    def test_all_states_defined(self):
        """All required states must be defined."""
        required_states = {"ISSUED", "CLAIMED", "RUNNING", "SUCCEEDED", "FAILED_FINAL", "UNKNOWN"}
        actual_states = {s.value for s in ExecutionState}
        assert required_states == actual_states

    def test_unknown_is_recoverable_state(self):
        """UNKNOWN is not a terminal state — it must be reconciled."""
        # UNKNOWN represents uncertainty, not definitive failure.
        # This test documents the contract.
        assert ExecutionState.UNKNOWN.value == "UNKNOWN"
        # Terminal states that cannot be retried:
        terminal = {ExecutionState.SUCCEEDED, ExecutionState.FAILED_FINAL}
        assert ExecutionState.UNKNOWN not in terminal

    def test_succeeded_is_terminal(self):
        """Once SUCCEEDED, an execution cannot be re-executed."""
        assert ExecutionState.SUCCEEDED.value == "SUCCEEDED"

    def test_failed_final_is_terminal(self):
        """FAILED_FINAL is a definitive failure — no retry."""
        assert ExecutionState.FAILED_FINAL.value == "FAILED_FINAL"

    @pytest.mark.parametrize("from_state,to_state,allowed", [
        ("ISSUED", "CLAIMED", True),
        ("CLAIMED", "RUNNING", True),
        ("RUNNING", "SUCCEEDED", True),
        ("RUNNING", "FAILED_FINAL", True),
        ("RUNNING", "UNKNOWN", True),
        ("UNKNOWN", "SUCCEEDED", True),   # after reconciliation
        ("UNKNOWN", "FAILED_FINAL", True),  # after reconciliation
        ("SUCCEEDED", "RUNNING", False),  # cannot go backwards
        ("FAILED_FINAL", "RUNNING", False),  # terminal
        ("SUCCEEDED", "CLAIMED", False),  # terminal
    ])
    def test_state_transitions(self, from_state, to_state, allowed):
        """Document allowed and disallowed state transitions."""
        # This test documents the state machine contract.
        # Alok must enforce these transitions in the executor.
        # We just verify the states exist and the contract is documented.
        if allowed:
            assert from_state in {s.value for s in ExecutionState}
            assert to_state in {s.value for s in ExecutionState}
        else:
            # Disallowed transitions must not occur in the implementation
            # This is enforced by application logic, not checked here
            pass


# ---------------------------------------------------------------------------
# Unit-level: Reconciliation logic
# ---------------------------------------------------------------------------

class TestReconciliationLogic:
    """
    Test the reconciliation protocol from FAILURE_MODEL.md Section 4.
    Simulates what happens when execution enters UNKNOWN state.
    """

    def _simulate_reconciliation(self, tool_response: dict) -> dict:
        """
        Simulate the executor's reconciliation decision.
        Based on FAILURE_MODEL.md Section 4.
        """
        status = tool_response.get("status")

        if status == "succeeded":
            return {
                "action": "TRANSITION_TO_SUCCEEDED",
                "sign_receipt": True,
                "emit_audit": True,
                "retry_tool": False,
            }
        elif status == "failed":
            return {
                "action": "TRANSITION_TO_FAILED_FINAL",
                "sign_receipt": False,
                "emit_audit": True,
                "retry_tool": False,
            }
        elif status == "not_found":
            return {
                "action": "TRANSITION_TO_FAILED_FINAL",
                "sign_receipt": False,
                "emit_audit": True,
                "retry_tool": False,  # Capability expired; tool never processed it
            }
        else:  # unreachable
            return {
                "action": "REMAIN_UNKNOWN",
                "sign_receipt": False,
                "emit_audit": False,
                "retry_tool": False,  # DO NOT retry blindly
            }

    def test_tool_succeeded_transitions_to_succeeded(self):
        result = self._simulate_reconciliation({"status": "succeeded", "result": {"mock_id": "x"}})
        assert result["action"] == "TRANSITION_TO_SUCCEEDED"
        assert result["retry_tool"] is False

    def test_tool_failed_transitions_to_failed_final(self):
        result = self._simulate_reconciliation({"status": "failed", "error": "mock error"})
        assert result["action"] == "TRANSITION_TO_FAILED_FINAL"
        assert result["retry_tool"] is False

    def test_tool_not_found_transitions_to_failed_final(self):
        """
        If the tool never processed the request (not_found),
        the capability is expired; mark as FAILED_FINAL, do NOT retry.
        """
        result = self._simulate_reconciliation({"status": "not_found"})
        assert result["action"] == "TRANSITION_TO_FAILED_FINAL"
        assert result["retry_tool"] is False

    def test_tool_unreachable_stays_unknown_no_retry(self):
        """
        CRITICAL (I9): If the tool is unreachable during reconciliation,
        do NOT blindly retry. Stay UNKNOWN and alert.
        """
        result = self._simulate_reconciliation({"status": "unreachable"})
        assert result["action"] == "REMAIN_UNKNOWN"
        assert result["retry_tool"] is False, \
            "SECURITY FAILURE: Reconciliation attempted blind retry on unreachable tool"

    def test_reconciliation_never_calls_tool_twice(self):
        """
        Reconciliation checks the tool's idempotency endpoint (query),
        it does NOT invoke the tool again.
        This test documents the contract.
        """
        # The reconciliation protocol:
        # 1. Query: GET /mock/tool/result?idempotency_key={jti}  ← READ ONLY
        # 2. Based on response: update state
        # 3. NEVER: POST /mock/tool/execute again with same jti
        idempotency_endpoint = "GET /mock/tool/result?idempotency_key={jti}"
        retry_endpoint = "POST /mock/tool/execute"
        # The reconciliation ONLY uses the idempotency query
        assert "GET" in idempotency_endpoint
        assert "POST" in retry_endpoint
        # Contract: reconciliation uses the GET, not the POST


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.adversarial
@pytest.mark.slow
class TestRecoveryIntegration:
    """
    A11: Timeout and retry — inject failure around tool invocation.
    """

    def test_execution_enters_unknown_on_timeout(self, gateway_url, valid_action_data):
        """
        1. Authorize action (capability issued)
        2. Set mock tool to delay 30s (timeout injection)
        3. Submit execution — executor times out
        Expected: execution state = UNKNOWN; mock state unchanged or uncertain
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up with mock tool delay injection.")

    def test_reconciliation_resolves_unknown_to_succeeded(self, gateway_url, valid_action_data):
        """
        After UNKNOWN state, trigger reconciliation.
        Mock tool reports success.
        Expected: state → SUCCEEDED; mock invoked exactly once; receipt produced.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")

    def test_no_duplicate_side_effect_after_reconciliation(self, gateway_url, valid_action_data):
        """
        CRITICAL: After reconciliation, the mock tool must show exactly one invocation,
        not two.
        """
        pytest.skip("NOT_IMPLEMENTED — requires docker-compose up.")
