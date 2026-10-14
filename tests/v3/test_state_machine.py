"""
AgentShield V3 — State Machine Tests
Owner: Pavan

Verifies the fail-closed execution state machine.
"""
import pytest
from core.state_machine import (
    ExecutionStateMachine, ExecState, VALID_TRANSITIONS,
    TERMINAL_STATES, FAILURE_MODES, print_failure_modes,
)


class TestValidTransitions:
    def test_full_happy_path(self):
        sm = ExecutionStateMachine("exec-happy-001")
        assert sm.transition(ExecState.EVALUATING,   "gateway", "")
        assert sm.transition(ExecState.AUTHORIZED,   "opa_allow", "")
        assert sm.transition(ExecState.CLAIMING,     "executor", "")
        assert sm.transition(ExecState.EXECUTING,    "jti_claimed", "")
        assert sm.transition(ExecState.SUCCEEDED,    "mock_tool", "")
        assert sm.current_state == ExecState.SUCCEEDED
        assert sm.succeeded
        assert sm.is_terminal

    def test_needs_approval_path(self):
        sm = ExecutionStateMachine("exec-approval-001")
        sm.transition(ExecState.EVALUATING,  "gateway", "")
        sm.transition(ExecState.NEEDS_APPR,  "opa_needs_approval", "")
        sm.transition(ExecState.APPROVED,    "manager_approved", "")
        sm.transition(ExecState.AUTHORIZED,  "capability_issued", "")
        assert sm.current_state == ExecState.AUTHORIZED

    def test_denied_is_terminal(self):
        sm = ExecutionStateMachine("exec-denied-001")
        sm.transition(ExecState.EVALUATING, "gateway", "")
        sm.transition(ExecState.DENIED,     "opa_deny", "")
        assert sm.is_terminal
        assert not sm.succeeded
        # Cannot transition out of DENIED
        result = sm.transition(ExecState.AUTHORIZED, "attempt_bypass", "")
        assert not result
        assert sm.current_state == ExecState.REJECTED  # fail-closed


class TestFailClosedBehavior:
    def test_invalid_transition_produces_rejected(self):
        """Any invalid transition → REJECTED, not silent ignore."""
        sm = ExecutionStateMachine("exec-attack-001")
        sm.transition(ExecState.EVALUATING, "gateway", "")
        # Try to skip CLAIMING and go straight to EXECUTING
        result = sm.transition(ExecState.EXECUTING, "skip_claim_attack", "")
        assert not result
        assert sm.current_state == ExecState.REJECTED
        assert sm.was_rejected

    def test_cannot_execute_from_pending(self):
        """No path from PENDING directly to EXECUTING."""
        sm = ExecutionStateMachine("exec-attack-002")
        result = sm.transition(ExecState.EXECUTING, "direct_attack", "")
        assert not result
        assert sm.current_state == ExecState.REJECTED

    def test_terminal_state_cannot_transition(self):
        """Once in a terminal state, no transitions are allowed."""
        for terminal in TERMINAL_STATES:
            sm = ExecutionStateMachine(f"exec-terminal-{terminal.value}")
            sm.current_state = terminal
            result = sm.transition(ExecState.EXECUTING, "attempt_after_terminal", "")
            assert not result, f"Terminal state {terminal} should block all transitions"

    def test_unknown_state_transitions_to_rejected(self):
        """UNKNOWN requires reconciliation — can only go to REJECTED."""
        sm = ExecutionStateMachine("exec-unknown-001")
        sm.current_state = ExecState.UNKNOWN
        # Invalid transition
        result = sm.transition(ExecState.EXECUTING, "blind_retry", "")
        assert not result
        assert sm.current_state == ExecState.REJECTED

    def test_unknown_can_go_to_rejected_explicitly(self):
        sm = ExecutionStateMachine("exec-unknown-002")
        sm.current_state = ExecState.UNKNOWN
        result = sm.transition(ExecState.REJECTED, "reconciliation_failed", "")
        assert result
        assert sm.current_state == ExecState.REJECTED


class TestHistoryRecording:
    def test_all_transitions_recorded(self):
        sm = ExecutionStateMachine("exec-history-001")
        sm.transition(ExecState.EVALUATING, "t1", "")
        sm.transition(ExecState.AUTHORIZED, "t2", "")
        assert len(sm.history) == 2

    def test_invalid_transition_recorded_in_history(self):
        sm = ExecutionStateMachine("exec-history-002")
        sm.transition(ExecState.EXECUTING, "attack", "")  # invalid
        # Both the attempt and the REJECTED transition are recorded
        assert len(sm.history) >= 1
        triggers = [e.trigger for e in sm.history]
        assert "INVALID_TRANSITION" in triggers

    def test_path_summary_contains_states(self):
        sm = ExecutionStateMachine("exec-path-001")
        sm.transition(ExecState.EVALUATING, "", "")
        sm.transition(ExecState.DENIED, "", "")
        path = sm.path_summary()
        assert "PENDING" in path
        assert "DENIED" in path


class TestFailureModes:
    def test_all_failure_modes_present(self):
        ids = [f.id for f in FAILURE_MODES]
        for expected in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"]:
            assert expected in ids

    def test_most_failure_modes_are_fail_closed(self):
        """At least 7 out of 8 failure modes must be fail-closed."""
        closed = [f for f in FAILURE_MODES if f.is_fail_closed]
        assert len(closed) >= 7, f"Only {len(closed)} fail-closed modes — expected ≥7"

    def test_f4_executor_crash_is_unknown_not_rejected(self):
        """F4 is the only mode that results in UNKNOWN — requires reconciliation."""
        f4 = next(f for f in FAILURE_MODES if f.id == "F4")
        assert f4.state_after == ExecState.UNKNOWN
        assert not f4.is_fail_closed

    def test_opa_failure_is_fail_closed(self):
        f1 = next(f for f in FAILURE_MODES if f.id == "F1")
        assert f1.is_fail_closed
        assert f1.state_after == ExecState.REJECTED


class TestValidTransitionGraph:
    def test_no_path_from_executing_to_pending(self):
        """Can never go backwards to PENDING."""
        reachable_from_executing = VALID_TRANSITIONS.get(ExecState.EXECUTING, set())
        assert ExecState.PENDING not in reachable_from_executing

    def test_succeeded_has_no_outgoing(self):
        assert VALID_TRANSITIONS[ExecState.SUCCEEDED] == set()

    def test_denied_has_no_outgoing(self):
        assert VALID_TRANSITIONS[ExecState.DENIED] == set()
