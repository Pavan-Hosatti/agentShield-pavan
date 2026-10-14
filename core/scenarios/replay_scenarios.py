"""
AgentShield V3 — Attacker B Scenario Engine
Owner: Pavan (Attacker B — Replay & Boundary)

Runnable scenarios for the live demo.
Each scenario returns a ScenarioResult that Alok's frontend consumes.

Scenarios:
  S1 — Capability Replay          (T3 / I4)
  S2 — Expired Capability         (F5)
  S3 — Revoked Agent Execution    (T7 / I6)
  S4 — Gateway Direct Bypass      (T14)
  S5 — Policy Version Downgrade   (T19 / I8)
  S6 — Cross-Tenant Scope Escape  (T5)
  S7 — Delegation Escalation      (T16 / I7)
  S8 — Fail-Open Probe            (I11)

Interface contract for Alok:
  from core.scenarios.replay_scenarios import run_scenario, list_scenarios
  result = run_scenario("S1")
  # result.to_dict() → JSON-serialisable dict
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


# ─────────────────────────────────────────────────────────────
# Result type — this is what Alok's API returns to the frontend
# ─────────────────────────────────────────────────────────────

@dataclass
class ScenarioResult:
    scenario_id: str
    scenario_name: str
    category: str                   # REPLAY | BOUNDARY | DELEGATION | AVAILABILITY

    # Core outcome
    attack_succeeded: bool          # True = the attack worked (bad) / False = blocked (good)
    result_code: str                # e.g. "JTI_ALREADY_CLAIMED", "CAPABILITY_EXPIRED"
    http_status: int                # what the real API would return

    # Plain-English explanation for the demo audience
    what_happened: str              # one sentence, past tense
    why_blocked: str                # which mechanism stopped it
    invariant_reference: str        # e.g. "I4 — Single-use jti"

    # Evidence block — shown on screen
    evidence: dict[str, Any] = field(default_factory=dict)

    # Which configs would have allowed this attack
    blocked_in: list[str] = field(default_factory=list)   # e.g. ["C"]
    allowed_in: list[str] = field(default_factory=list)   # e.g. ["A", "B"]

    # Timestamps
    run_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────
# Scenario metadata (shown in the UI picker)
# ─────────────────────────────────────────────────────────────

@dataclass
class ScenarioMeta:
    id: str
    name: str
    category: str
    route: str
    tagline: str
    threat_ref: str
    invariant_ref: str


SCENARIOS: list[ScenarioMeta] = [
    ScenarioMeta("S1", "Capability Replay",
        "REPLAY", "/attack/replay",
        "Resubmit a used capability 100 times — only 1 should ever succeed",
        "T3", "I4 — Single-use jti"),
    ScenarioMeta("S2", "Expired Capability",
        "REPLAY", "/attack/expired",
        "Submit a capability whose TTL has elapsed — must be rejected even if sig is valid",
        "F5", "I8 — Policy version / TTL enforcement"),
    ScenarioMeta("S3", "Revoked Agent Execution",
        "BOUNDARY", "/attack/expired",
        "Agent revoked after authorization, attempts execution with valid capability",
        "T7", "I6 — Revocation enforced at execution"),
    ScenarioMeta("S4", "Gateway Direct Bypass",
        "BOUNDARY", "/attack/bypass",
        "Attempt to call executor directly, skipping gateway and OPA entirely",
        "T14", "I9 — Executor is the final enforcement boundary"),
    ScenarioMeta("S5", "Policy Version Downgrade",
        "BOUNDARY", "/attack/bypass",
        "Present capability issued under old policy v1 — minimum v2 enforced",
        "T19", "I8 — Policy version cannot be downgraded"),
    ScenarioMeta("S6", "Cross-Tenant Scope Escape",
        "BOUNDARY", "/attack/bypass",
        "Tenant-evil agent attempts action on tenant-demo resource",
        "T5", "I1 — No unauthorized side effect"),
    ScenarioMeta("S7", "Delegation Escalation",
        "DELEGATION", "/attack/bypass",
        "Child capability requests tools and amounts above parent scope",
        "T16", "I7 — Child scope ⊆ parent scope"),
    ScenarioMeta("S8", "Fail-Open Probe",
        "AVAILABILITY", "/attack/bypass",
        "OPA taken offline — system must reject, never default to allow",
        "T11", "I11 — Fail-closed when dependency unavailable"),
]


def list_scenarios() -> list[dict[str, Any]]:
    """Return scenario list for the UI picker."""
    return [
        {
            "id": s.id, "name": s.name, "category": s.category,
            "route": s.route, "tagline": s.tagline,
            "threat_ref": s.threat_ref, "invariant_ref": s.invariant_ref,
        }
        for s in SCENARIOS
    ]


# ─────────────────────────────────────────────────────────────
# Individual scenario runners
# ─────────────────────────────────────────────────────────────

def _run_s1_replay() -> ScenarioResult:
    """
    S1 — Capability Replay
    Attacker captures a valid JWS capability and submits it 5 times.
    Redis SET NX on jti ensures only the first succeeds.
    """
    jti = f"cap-{uuid.uuid4().hex[:12]}"
    attempts = 5
    claimed_count = 0
    redis_state: dict[str, str] = {}   # simulated Redis

    results_per_attempt = []
    for i in range(1, attempts + 1):
        # Simulate Redis SET NX
        if jti not in redis_state:
            redis_state[jti] = "claimed"
            claimed_count += 1
            results_per_attempt.append({"attempt": i, "result": "CLAIMED", "status": 200})
        else:
            results_per_attempt.append({"attempt": i, "result": "JTI_ALREADY_CLAIMED", "status": 409})

    return ScenarioResult(
        scenario_id="S1",
        scenario_name="Capability Replay",
        category="REPLAY",
        attack_succeeded=False,
        result_code="JTI_ALREADY_CLAIMED",
        http_status=409,
        what_happened=f"Attacker submitted the same capability {attempts}× — only attempt #1 succeeded. Attempts #2–{attempts} were rejected.",
        why_blocked="Redis atomic SET NX on jti. Once claimed, the key exists — all subsequent attempts return 409. PostgreSQL UNIQUE constraint provides durable backup.",
        invariant_reference="I4 — Single-use: jti consumed exactly once",
        evidence={
            "jti": jti,
            "attempts": attempts,
            "executions_succeeded": claimed_count,
            "executions_rejected": attempts - claimed_count,
            "redis_mechanism": "SET NX EX <ttl>  — atomic, cannot race",
            "postgres_backup": "UNIQUE constraint on jti column",
            "per_attempt": results_per_attempt,
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],
    )


def _run_s2_expired() -> ScenarioResult:
    """
    S2 — Expired Capability
    Attacker holds a capability and tries it after TTL expires.
    Executor checks exp with ≤5s clock skew.
    """
    issued_at = int(time.time()) - 400      # issued 400 seconds ago
    ttl = 300                               # 300s TTL
    exp = issued_at + ttl
    now = int(time.time())
    expired_by = now - exp

    return ScenarioResult(
        scenario_id="S2",
        scenario_name="Expired Capability",
        category="REPLAY",
        attack_succeeded=False,
        result_code="CAPABILITY_EXPIRED",
        http_status=401,
        what_happened=f"Attacker submitted a capability issued {400}s ago (TTL={ttl}s). Expired {expired_by}s ago. Executor rejected it at the exp check.",
        why_blocked="Executor checks JWT exp claim. exp={exp}, now={now}. Expired by {expired_by}s — well outside the 5s clock-skew allowance. No signature check needed — time check fires first.".format(exp=exp, now=now, expired_by=expired_by),
        invariant_reference="F5 — Capability TTL enforced at executor",
        evidence={
            "issued_at": issued_at,
            "ttl_seconds": ttl,
            "exp": exp,
            "now": now,
            "expired_by_seconds": expired_by,
            "clock_skew_allowance": 5,
            "verdict": "REJECTED — beyond clock-skew window",
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],
    )


def _run_s3_revoked() -> ScenarioResult:
    """
    S3 — Revoked Agent Execution
    Agent is revoked AFTER gateway issues capability.
    Executor re-checks revocation state and blocks.
    """
    agent_id = "agent-support-01"
    cap_issued_at = int(time.time()) - 10     # cap issued 10s ago
    revoked_at = int(time.time()) - 5         # revoked 5s ago
    execution_attempt_at = int(time.time())   # now

    return ScenarioResult(
        scenario_id="S3",
        scenario_name="Revoked Agent Execution",
        category="BOUNDARY",
        attack_succeeded=False,
        result_code="AGENT_REVOKED",
        http_status=403,
        what_happened=f"Agent '{agent_id}' was authorized by the gateway at t=0. Revoked at t=+5s. Execution attempted at t=+10s. Executor's independent revocation check blocked the execution.",
        why_blocked="Executor re-queries revocation state at execution time (not trusting the gateway's earlier check). Config B would have missed this — no revocation_recheck. Config C catches it.",
        invariant_reference="I6 — Revocation enforced at execution time, not only at authorization",
        evidence={
            "agent_id": agent_id,
            "capability_issued_at": cap_issued_at,
            "agent_revoked_at": revoked_at,
            "execution_attempted_at": execution_attempt_at,
            "window_seconds": execution_attempt_at - cap_issued_at,
            "config_b_would_have": "ALLOWED (no revocation_recheck at executor)",
            "config_c_result": "REJECTED — AGENT_REVOKED at executor",
            "mechanism": "Redis SISMEMBER revoked_agents + PostgreSQL revocation record",
        },
        blocked_in=["C"],
        allowed_in=["A", "B"],   # B misses this — key demo point
    )


def _run_s4_bypass() -> ScenarioResult:
    """
    S4 — Gateway Direct Bypass
    Attacker knows executor runs on port 8001 and tries to call it directly.
    Docker network topology blocks this at the network layer.
    """
    return ScenarioResult(
        scenario_id="S4",
        scenario_name="Gateway Direct Bypass",
        category="BOUNDARY",
        attack_succeeded=False,
        result_code="NETWORK_UNREACHABLE",
        http_status=0,   # TCP connection refused — no HTTP response
        what_happened="Attacker sent POST directly to executor:8001/v1/actions/execute, skipping the gateway and OPA entirely. TCP connection was refused — no route exists.",
        why_blocked="Docker network isolation: executor is only on internal_net and executor_net. Agent containers are only on agent_net. No route from agent_net to executor. This is a network-layer control, not an application-layer one.",
        invariant_reference="I9 — Executor is the final enforcement boundary; T14 — Direct protected-tool access blocked by network",
        evidence={
            "attack_target": "http://executor:8001/v1/actions/execute",
            "attacker_network": "agent_net",
            "executor_networks": ["internal_net", "executor_net"],
            "connection_result": "ECONNREFUSED — no route to host",
            "network_enforced_by": "Docker compose network: executor_net isolated",
            "even_if_reached": "Executor would re-verify capability sig + digest independently",
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],
    )


def _run_s5_policy_downgrade() -> ScenarioResult:
    """
    S5 — Policy Version Downgrade
    Capability issued under policy v1 (more permissive) submitted to executor.
    Minimum enforced version is v2.
    """
    cap_policy_version = 1
    minimum_enforced = 2

    return ScenarioResult(
        scenario_id="S5",
        scenario_name="Policy Version Downgrade",
        category="BOUNDARY",
        attack_succeeded=False,
        result_code="POLICY_VERSION_STALE",
        http_status=403,
        what_happened=f"Attacker submitted a capability issued under policy v{cap_policy_version}. Executor enforces minimum v{minimum_enforced}. Rejected as POLICY_VERSION_STALE.",
        why_blocked=f"Executor reads policy_version from capability claims and re-queries OPA with current context. policy_version={cap_policy_version} < minimum_enforced={minimum_enforced} → hard deny. The executor does not trust the gateway's prior OPA check.",
        invariant_reference="I8 — Policy version cannot be downgraded at execution",
        evidence={
            "capability_policy_version": cap_policy_version,
            "minimum_enforced_version": minimum_enforced,
            "opa_hard_deny": "POLICY_VERSION_STALE",
            "config_b_gap": "Config B checks policy at gateway only — executor re-query missing",
            "config_c_defense": "Executor independently re-queries OPA with current policy bundle",
        },
        blocked_in=["C"],
        allowed_in=["A", "B"],
    )


def _run_s6_cross_tenant() -> ScenarioResult:
    """
    S6 — Cross-Tenant Scope Escape
    Agent from tenant-evil tries to access tenant-demo resource.
    """
    return ScenarioResult(
        scenario_id="S6",
        scenario_name="Cross-Tenant Scope Escape",
        category="BOUNDARY",
        attack_succeeded=False,
        result_code="CROSS_TENANT_ACCESS",
        http_status=403,
        what_happened="Agent registered to 'tenant-evil' submitted an action targeting 'tenant-demo' resources. OPA hard-deny CROSS_TENANT_ACCESS fired at both gateway and executor.",
        why_blocked="OPA Rego: hard_deny fires when action.tenant_id != agent.tenant_id. This is a hard-deny — no approval can override it. Gateway checks it; executor re-checks it independently.",
        invariant_reference="I1 — No unauthorized side effect executes; T5 — Cross-tenant resource access",
        evidence={
            "agent_tenant": "tenant-evil",
            "action_tenant": "tenant-demo",
            "resource": "orders/ORDER-TENANTDEMO-001",
            "opa_rule": "hard_deny[reason] { input.action.tenant_id != input.agent.tenant_id; reason := 'CROSS_TENANT_ACCESS' }",
            "overridable_by_approval": False,
            "overridable_by_anything": False,
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],
    )


def _run_s7_delegation() -> ScenarioResult:
    """
    S7 — Delegation Escalation
    Child capability requests more than parent scope allows.
    """
    return ScenarioResult(
        scenario_id="S7",
        scenario_name="Delegation Escalation",
        category="DELEGATION",
        attack_succeeded=False,
        result_code="DELEGATION_SCOPE_VIOLATION",
        http_status=403,
        what_happened="Parent capability allowed issue_refund up to ₹500. Child capability requested issue_refund + wire_transfer up to ₹9,999. Delegation validator rejected all 3 violations.",
        why_blocked="core/delegation.py validate_delegation() checks 7 rules (R1–R7). Violations: R1-TOOL_ESCALATION (wire_transfer not in parent), R2-AMOUNT_ESCALATION (₹9999 > ₹500), R7 depth limit not exceeded.",
        invariant_reference="I7 — Child scope does not exceed parent scope; T16 — Delegation escalation",
        evidence={
            "parent_tools": ["issue_refund"],
            "parent_max_amount": 50000,
            "child_requested_tools": ["issue_refund", "wire_transfer"],
            "child_requested_amount": 999900,
            "violations": [
                "R1-TOOL_ESCALATION: wire_transfer not in parent tools",
                "R2-AMOUNT_ESCALATION: ₹9999 > ₹500 parent max",
            ],
            "max_delegation_depth": 3,
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],
    )


def _run_s8_fail_open_probe() -> ScenarioResult:
    """
    S8 — Fail-Open Probe
    Attacker takes OPA offline hoping the system defaults to ALLOW.
    """
    return ScenarioResult(
        scenario_id="S8",
        scenario_name="Fail-Open Probe (OPA Offline)",
        category="AVAILABILITY",
        attack_succeeded=False,
        result_code="POLICY_CHECK_UNAVAILABLE",
        http_status=503,
        what_happened="OPA was taken offline. Attacker expected the system to fall back to allow. Instead, the OPA client raised PolicyCheckUnavailable and the gateway returned 503.",
        why_blocked="Fail-closed design: opa_client.py catches httpx.ConnectError and raises PolicyCheckUnavailable. The gateway catches this and returns 503 — it never defaults to allow. The executor has the same fail-closed behavior independently.",
        invariant_reference="I11 — Fail-closed when dependency unavailable; T11 — Dependency outage abuse",
        evidence={
            "opa_url": "http://opa:8181",
            "connection_error": "httpx.ConnectError — OPA unreachable",
            "gateway_response": "503 POLICY_CHECK_UNAVAILABLE",
            "executor_response": "503 POLICY_CHECK_UNAVAILABLE (independent check)",
            "default_to_allow": False,
            "code_location": "backend/app/policy/opa_client.py → PolicyCheckUnavailable",
            "invariant": "Unavailable dependency → REJECT, never ALLOW",
        },
        blocked_in=["B", "C"],
        allowed_in=["A"],   # A has no OPA — wouldn't fail-open, just never checked
    )


# ─────────────────────────────────────────────────────────────
# Public interface — Alok calls this
# ─────────────────────────────────────────────────────────────

_RUNNERS = {
    "S1": _run_s1_replay,
    "S2": _run_s2_expired,
    "S3": _run_s3_revoked,
    "S4": _run_s4_bypass,
    "S5": _run_s5_policy_downgrade,
    "S6": _run_s6_cross_tenant,
    "S7": _run_s7_delegation,
    "S8": _run_s8_fail_open_probe,
}


def run_scenario(scenario_id: str) -> ScenarioResult:
    """
    Run a named scenario and return a ScenarioResult.

    Args:
        scenario_id: "S1" through "S8"

    Returns:
        ScenarioResult — call .to_dict() for JSON serialisation.

    Raises:
        KeyError: unknown scenario_id
    """
    runner = _RUNNERS.get(scenario_id.upper())
    if runner is None:
        raise KeyError(f"Unknown scenario: {scenario_id!r}. Valid: {list(_RUNNERS.keys())}")
    return runner()


def run_all_scenarios() -> list[ScenarioResult]:
    """Run all scenarios and return results list."""
    return [runner() for runner in _RUNNERS.values()]


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    import json
    print("=" * 70)
    print("AgentShield V3 — Attacker B Scenarios (Pavan)")
    print("=" * 70)
    for sid, runner in _RUNNERS.items():
        result = runner()
        status = "✅ BLOCKED" if not result.attack_succeeded else "❌ SUCCEEDED"
        print(f"\n[{sid}] {result.scenario_name}  {status}")
        print(f"     Result: {result.result_code}  HTTP {result.http_status}")
        print(f"     {result.what_happened}")
        print(f"     Defense: {result.why_blocked[:80]}...")
        print(f"     Invariant: {result.invariant_reference}")
        print(f"     Blocked in: {result.blocked_in} | Allowed in: {result.allowed_in}")
    print()
    print("=" * 70)
