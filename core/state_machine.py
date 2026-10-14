"""
AgentShield V3 — Fail-Closed Execution State Machine
Owner: Pavan (Architecture & Threat Modeling)

Every execution goes through a defined state sequence.
At each state, dependencies are checked. If any check fails,
the machine transitions to REJECTED or UNKNOWN — never to EXECUTING.

States:
  PENDING      → Action received, not yet evaluated
  EVALUATING   → OPA policy evaluation in progress
  DENIED       → Hard-denied. Terminal. No capability issued.
  NEEDS_APPR   → Awaiting human approval
  APPROVED     → Approval verified. Capability being issued.
  AUTHORIZED   → Capability issued. Ready for executor.
  CLAIMING     → Executor atomically claiming jti
  EXECUTING    → Side effect in progress
  SUCCEEDED    → Completed successfully. Receipt signed.
  FAILED_FINAL → Executor-side failure. Terminal.
  UNKNOWN      → Executor crashed mid-execution. Needs reconciliation.
  REJECTED     → Any pre-execution check failed. Safe terminal state.

Fail-closed rule:
  Any unexpected transition → REJECTED
  Any dependency failure → REJECTED (not EXECUTING)
  UNKNOWN → requires explicit reconciliation before retry
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ExecState(str, Enum):
    PENDING      = "PENDING"
    EVALUATING   = "EVALUATING"
    DENIED       = "DENIED"
    NEEDS_APPR   = "NEEDS_APPROVAL"
    APPROVED     = "APPROVED"
    AUTHORIZED   = "AUTHORIZED"
    CLAIMING     = "CLAIMING"
    EXECUTING    = "EXECUTING"
    SUCCEEDED    = "SUCCEEDED"
    FAILED_FINAL = "FAILED_FINAL"
    UNKNOWN      = "UNKNOWN"
    REJECTED     = "REJECTED"


# Terminal states — no further transitions allowed
TERMINAL_STATES = {
    ExecState.DENIED,
    ExecState.SUCCEEDED,
    ExecState.FAILED_FINAL,
    ExecState.REJECTED,
}

# States that represent a security violation if reached improperly
VIOLATION_IF_SKIPPED = {
    ExecState.CLAIMING,   # jti claim must happen before EXECUTING
    ExecState.EXECUTING,  # must have gone through CLAIMING
}

# Valid transitions — the only allowed state moves
VALID_TRANSITIONS: dict[ExecState, set[ExecState]] = {
    ExecState.PENDING:      {ExecState.EVALUATING, ExecState.REJECTED},
    ExecState.EVALUATING:   {ExecState.DENIED, ExecState.NEEDS_APPR, ExecState.AUTHORIZED, ExecState.REJECTED},
    ExecState.DENIED:       set(),  # terminal
    ExecState.NEEDS_APPR:   {ExecState.APPROVED, ExecState.DENIED, ExecState.REJECTED},
    ExecState.APPROVED:     {ExecState.AUTHORIZED, ExecState.REJECTED},
    ExecState.AUTHORIZED:   {ExecState.CLAIMING, ExecState.REJECTED},
    ExecState.CLAIMING:     {ExecState.EXECUTING, ExecState.REJECTED},
    ExecState.EXECUTING:    {ExecState.SUCCEEDED, ExecState.FAILED_FINAL, ExecState.UNKNOWN},
    ExecState.SUCCEEDED:    set(),  # terminal
    ExecState.FAILED_FINAL: set(),  # terminal
    ExecState.UNKNOWN:      {ExecState.REJECTED},  # requires reconciliation — not retry
    ExecState.REJECTED:     set(),  # terminal
}


@dataclass
class StateTransitionEvent:
    from_state: ExecState
    to_state: ExecState
    trigger: str
    detail: str
    allowed: bool


@dataclass
class ExecutionStateMachine:
    """
    Tracks the state of a single execution attempt.
    All transitions are validated against VALID_TRANSITIONS.
    An invalid transition is itself a security event — recorded and rejected.
    """
    execution_id: str
    current_state: ExecState = ExecState.PENDING
    history: list[StateTransitionEvent] = field(default_factory=list)

    def transition(self, to: ExecState, trigger: str, detail: str = "") -> bool:
        """
        Attempt a state transition. Returns True if allowed.
        ALWAYS records the attempt (even invalid ones).
        Invalid transitions → current state becomes REJECTED.
        """
        allowed = to in VALID_TRANSITIONS.get(self.current_state, set())

        event = StateTransitionEvent(
            from_state=self.current_state,
            to_state=to,
            trigger=trigger,
            detail=detail,
            allowed=allowed,
        )
        self.history.append(event)

        if allowed:
            self.current_state = to
        else:
            # Fail-closed: invalid transition → REJECTED
            # Record rejection event too
            reject_event = StateTransitionEvent(
                from_state=self.current_state,
                to_state=ExecState.REJECTED,
                trigger="INVALID_TRANSITION",
                detail=f"Attempted {self.current_state}→{to} (not in valid transitions) — fail-closed REJECTED",
                allowed=True,
            )
            self.history.append(reject_event)
            self.current_state = ExecState.REJECTED

        return allowed

    @property
    def is_terminal(self) -> bool:
        return self.current_state in TERMINAL_STATES

    @property
    def succeeded(self) -> bool:
        return self.current_state == ExecState.SUCCEEDED

    @property
    def was_rejected(self) -> bool:
        return self.current_state == ExecState.REJECTED

    def path_summary(self) -> str:
        """Return the state path this execution took."""
        states = [self.history[0].from_state.value] if self.history else [self.current_state.value]
        for e in self.history:
            states.append(f"{'→' if e.allowed else '⚡'}{e.to_state.value}")
        return " ".join(states)

    def print_history(self) -> None:
        print(f"\nExecution {self.execution_id} — State History")
        print("-" * 56)
        for e in self.history:
            icon = "✓" if e.allowed else "✗"
            print(f"  {icon} {e.from_state.value:14} → {e.to_state.value:14}  [{e.trigger}] {e.detail}")
        print(f"  Final state: {self.current_state.value}")
        print("-" * 56)


# ─────────────────────────────────────────────────────────────
# Failure mode definitions — what breaks what
# ─────────────────────────────────────────────────────────────

@dataclass
class FailureMode:
    id: str
    trigger: str
    description: str
    system_response: str
    state_after: ExecState
    is_fail_closed: bool
    recovery: str


FAILURE_MODES: list[FailureMode] = [
    FailureMode(
        id="F1", trigger="OPA_UNAVAILABLE",
        description="OPA policy engine unreachable during evaluation",
        system_response="503 POLICY_CHECK_UNAVAILABLE — reject immediately",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="OPA service restored — agent retries",
    ),
    FailureMode(
        id="F2", trigger="REDIS_UNAVAILABLE_AT_CLAIM",
        description="Redis unreachable when executor attempts atomic jti claim",
        system_response="503 — cannot guarantee single-use — reject",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="Redis restored — agent retries with same capability if not expired",
    ),
    FailureMode(
        id="F3", trigger="DB_UNAVAILABLE_AT_RECORD",
        description="PostgreSQL unavailable when recording CLAIMED state",
        system_response="503 — cannot create durable execution record — reject",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="DB restored — retry with fresh capability",
    ),
    FailureMode(
        id="F4", trigger="EXECUTOR_CRASH_MID_EXECUTION",
        description="Executor process crashes after mock tool invoked but before receipt",
        system_response="State left as UNKNOWN — blind retry prohibited",
        state_after=ExecState.UNKNOWN,
        is_fail_closed=False,
        recovery="Reconciler checks mock tool idempotency key — confirm result before state update",
    ),
    FailureMode(
        id="F5", trigger="CAPABILITY_EXPIRED",
        description="Capability TTL expired before executor processes it",
        system_response="401 CAPABILITY_EXPIRED — reject",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="Agent re-authorizes via gateway for fresh capability",
    ),
    FailureMode(
        id="F6", trigger="REVOCATION_CHECK_UNAVAILABLE",
        description="Revocation state (Redis + DB) both unavailable at executor",
        system_response="503 — cannot confirm agent not revoked — fail-closed reject",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="Service restored — agent retries",
    ),
    FailureMode(
        id="F7", trigger="DIGEST_MISMATCH_AT_EXECUTOR",
        description="Execution-time action digest differs from capability-bound digest",
        system_response="403 DIGEST_MISMATCH — action substitution detected — reject",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="Agent submits correct (unmodified) action",
    ),
    FailureMode(
        id="F8", trigger="APPROVAL_CONSUMED_RACE",
        description="Two concurrent requests both pass approval check; one wins the atomic consume",
        system_response="403 APPROVAL_ALREADY_CONSUMED for the loser",
        state_after=ExecState.REJECTED,
        is_fail_closed=True,
        recovery="New approval required for the rejected request",
    ),
]


def print_failure_modes() -> None:
    print("=" * 72)
    print("AgentShield V3 — Fail-Closed State Machine — Failure Modes")
    print("=" * 72)
    for f in FAILURE_MODES:
        closed = "✅ FAIL-CLOSED" if f.is_fail_closed else "⚠️  UNKNOWN STATE"
        print(f"  [{f.id}] {f.trigger}")
        print(f"       Trigger : {f.description}")
        print(f"       Response: {f.system_response}")
        print(f"       State   : {f.state_after.value}  {closed}")
        print(f"       Recovery: {f.recovery}")
        print()
    print("=" * 72)


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    # Demo: simulate a legitimate execution path
    sm = ExecutionStateMachine("exec-demo-001")
    sm.transition(ExecState.EVALUATING,   "GATEWAY_RECEIVED",   "Schema validated, identity resolved")
    sm.transition(ExecState.AUTHORIZED,   "OPA_ALLOW",          "Policy: ALLOW — amount < 30000")
    sm.transition(ExecState.CLAIMING,     "EXECUTOR_RECEIVED",  "Capability signature verified, digest matched")
    sm.transition(ExecState.EXECUTING,    "JTI_CLAIMED",        "Redis SET NX success — atomic claim")
    sm.transition(ExecState.SUCCEEDED,    "MOCK_TOOL_SUCCESS",  "Mock tool returned result, receipt signed")
    sm.print_history()

    print()

    # Demo: attack attempt — invalid transition (trying to skip CLAIMING)
    sm2 = ExecutionStateMachine("exec-attack-001")
    sm2.transition(ExecState.EVALUATING, "GATEWAY_RECEIVED", "")
    sm2.transition(ExecState.AUTHORIZED, "OPA_ALLOW", "")
    sm2.transition(ExecState.EXECUTING,  "SKIP_CLAIM_ATTACK", "Attacker tries to skip jti claim")
    sm2.print_history()

    print()
    print_failure_modes()
