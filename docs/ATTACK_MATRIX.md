# AgentShield V2 — Attack Matrix

**Owner: Pavan (specification) | Gururaj (execution)**  
**Status: Every row must be tested. Results must reflect actual execution.**

---

## Attack Matrix

| ID | Attack Name | Setup | Attack Action | Expected System Behavior | Invariant Tested | Implementation Status |
|---|---|---|---|---|---|---|
| A1 | Direct Bypass | Register agent, obtain credential | Agent sends HTTP directly to mock_tool:8002 without going through executor | Connection refused / no route; mock state unchanged | I1 | TODO |
| A2 | Action Substitution | Issue capability for `amount_minor: 50000` | Submit execution with `amount_minor: 500000` | Executor returns 403 DIGEST_MISMATCH; mock state unchanged | I2 | TODO |
| A3 | Concurrent Replay | Issue one valid capability | 100 concurrent POST /v1/actions/execute with same capability | At most 1 success (200); 99 × 409 CAPABILITY_ALREADY_CLAIMED; mock invoked once | I4 | TODO |
| A4 | Approval Replay | Issue approval for action A | Present same approval_id for action B (different digest) | Executor returns 403 APPROVAL_INVALID (digest mismatch) | I5a | TODO |
| A5 | Identity Spoof | - | Submit request body with `principal_id: "admin"`, `tenant_id: "tenant-privileged"` | Gateway resolves identity from credential; body mismatch → 403 IDENTITY_MISMATCH | I8 | TODO |
| A6 | Revocation Race | Issue capability, then revoke agent before execution | Submit execution after revocation | Executor returns 403 AGENT_REVOKED; mock state unchanged | I6 | TODO |
| A7 | Agent-to-Agent Abuse | Register agent-A | Agent-A calls unregistered destination agent-X | Gateway returns 403; no capability issued | I1 | NOT_IMPLEMENTED |
| A8 | Delegation Escalation | Issue parent capability with scope limit=50000 | Child agent requests scope limit=500000 | Executor rejects scope escalation | - | NOT_IMPLEMENTED |
| A9 | Dependency Outage | Normal agent setup | Kill Redis → attempt execution; Kill OPA → attempt authorization | 503 REPLAY_CHECK_UNAVAILABLE / POLICY_CHECK_UNAVAILABLE; mock state unchanged | I7 | TODO |
| A10 | Audit Tampering | Complete one valid execution (audit chain has ≥2 events) | Edit one audit record's `amount_minor` field in PostgreSQL | Verifier returns chain break at modified record | I10 | TODO |
| A11 | Timeout and Retry | Normal setup | Inject 30s delay in mock tool response | State → UNKNOWN; reconciliation queries idempotency; no duplicate side effect | I9 | TODO |
| B1 | Benign Refund | All services running, agent registered, within policy | Submit valid refund `amount_minor: 50000` | 200 success; mock state changed; receipt produced; audit chain extended | I11 | TODO |
| B2 | Human Approval | Policy requires approval for `amount_minor ≥ 30000` | Submit for 40000; wait for approval; approve; execute | Blocked until approval; approved operation succeeds once; second attempt rejected | I5b | TODO |

---

## Additional Edge Cases (Gururaj to implement)

| ID | Description | Expected |
|---|---|---|
| E1 | Malformed schema — float amount | 422 SCHEMA_VALIDATION_FAILED |
| E2 | Malformed schema — duplicate JSON key | 422 SCHEMA_VALIDATION_FAILED |
| E3 | Unknown field in action envelope | 422 SCHEMA_VALIDATION_FAILED |
| E4 | Expired capability | 403 CAPABILITY_EXPIRED |
| E5 | Invalid signature (bit flip in capability) | 403 INVALID_CAPABILITY_SIGNATURE |
| E6 | Unknown key_id in capability | 403 INVALID_CAPABILITY_SIGNATURE |
| E7 | Cross-tenant resource access | 403 RESOURCE_OWNERSHIP_FAILED |
| E8 | Unknown tool | 422 or 403 TOOL_NOT_PERMITTED |
| E9 | Policy version below minimum | 403 POLICY_VERSION_STALE |
| E10 | Rejected approval presented for execution | 403 APPROVAL_INVALID |
| E11 | Expired approval | 403 APPROVAL_INVALID |
| E12 | Null amount_minor | 422 SCHEMA_VALIDATION_FAILED |

---

## Result Format (each test execution)

```json
{
  "run_id": "run-2026-10-13-001",
  "timestamp": "2026-10-13T00:00:00Z",
  "git_commit": "abc123",
  "scenario_id": "A2",
  "preconditions": "Capability issued for amount_minor=50000",
  "expected_result": "403 DIGEST_MISMATCH, mock state unchanged",
  "actual_result": "403 DIGEST_MISMATCH",
  "reason_code": "DIGEST_MISMATCH",
  "attempts": 1,
  "initial_mock_state": {"order_id": "ORDER-123", "refund_issued": false},
  "final_mock_state": {"order_id": "ORDER-123", "refund_issued": false},
  "protected_side_effect_occurred": false,
  "execution_id": null,
  "latency_ms": 12,
  "status": "PASS"
}
```

---

## Baseline Comparison (Gururaj runs)

| Scenario | Baseline A (RBAC only) | Baseline B (OPA gateway) | Baseline C (Full AgentShield) |
|---|---|---|---|
| A2 — Action substitution | NOT PROTECTED (no digest check) | NOT PROTECTED | BLOCKED |
| A3 — Concurrent replay | NOT PROTECTED | NOT PROTECTED | BLOCKED (at most 1) |
| A4 — Approval replay | NOT APPLICABLE | NOT APPLICABLE | BLOCKED |
| A6 — Revocation race | DELAYED (no execution-time check) | DELAYED | BLOCKED (executor re-checks) |
| A9 — Dependency outage | FAIL OPEN (passes without OPA) | FAIL OPEN | FAIL CLOSED |
| B1 — Benign refund | PASSES | PASSES | PASSES |

Exact measurements (blocked %, latency, throughput) to be filled by Gururaj after test runs.

---

*Last updated: 2026-10-13 | Owner: Pavan*
