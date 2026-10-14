# AgentShield V2 — Security Invariants

**Owner: Pavan**  
**Status: These invariants must hold in the running system. Gururaj tests each one.**

---

## I1 — No Agent or Gateway Bypass to the Protected Tool

**Invariant:** No path exists from the AI agent or API gateway directly to the mock protected tool that bypasses the protected executor.

**Enforcement component:** Docker network topology (executor_net); mock tool has no route on agent_net or internal_net.

**Assumption:** Container networking is correctly configured. An attacker does not have host-level network access.

**Test scenario:** A1 — Agent and gateway attempt direct HTTP requests to the mock tool's internal address.

**Acceptable evidence:** HTTP 000 (connection refused) or no route; mock tool state unchanged; audit log shows no unauthorized invocation.

---

## I2 — No Execution When Action Digest Differs

**Invariant:** A protected side effect cannot occur when the action submitted for execution has a different digest than the digest embedded in the capability.

**Enforcement component:** Protected Executor (Step 11d — executor recomputes digest, compares to capability).

**Assumption:** The shared canonicalization function is deterministic and identical at gateway and executor.

**Test scenario:** A2 — Authorize `amount_minor: 50000`; attempt execution with `amount_minor: 500000`.

**Acceptable evidence:** Executor returns 403 `reason: DIGEST_MISMATCH`; mock tool state unchanged; execution record not created or in FAILED state.

---

## I3 — No Hard-Denied Action Receives an Executable Capability

**Invariant:** When OPA returns `deny`, the gateway must not issue a capability. No amount of retries, header manipulation, or approval flow can override a hard-deny.

**Enforcement component:** API Gateway (Step 7); OPA policy.

**Assumption:** OPA policy bundle correctly encodes the deny rules; OPA is reachable.

**Test scenario:** Attempt to authorize an action with `amount_minor > policy_limit` (hard-deny threshold). Verify no capability is returned.

**Acceptable evidence:** Gateway returns 403 `reason: HARD_DENY`; no capability token in response; no capability issuance audit event.

---

## I4 — At Most One Concurrent Claim Succeeds for a Single Capability

**Invariant:** Given 100 concurrent execution requests presenting the same capability token, at most one claim succeeds and at most one protected side effect occurs.

**Enforcement component:** Redis `SET jti NX EX` (atomic); PostgreSQL `UNIQUE(jti)` constraint.

**Assumption:** Redis and PostgreSQL are available. Redis SET NX is atomic.

**Test scenario:** A3 — 100 concurrent POST /v1/actions/execute with identical capability.

**Acceptable evidence:** Exactly 1 response with 200; 99 responses with 409 `reason: CAPABILITY_ALREADY_CLAIMED`; mock tool invoked exactly once; execution record shows exactly one SUCCEEDED entry for this jti.

---

## I5 — Required Approval Is Bound to the Exact Action and Cannot Be Reused

**Invariant (5a):** An approval issued for action digest D cannot authorize execution of any action with a different digest D'.

**Invariant (5b):** An approval that has been consumed to authorize one execution cannot be consumed again for a second execution.

**Enforcement component (5a):** Executor (Step 11g — approval.action_digest must equal capability.action_digest).

**Enforcement component (5b):** PostgreSQL `consumed` flag set atomically; executor rejects consumed approvals.

**Assumption:** PostgreSQL is available. Approval consumption is atomic.

**Test scenario (5a):** A4/A6 — Approve `amount_minor: 50000`; attempt execution with `amount_minor: 500000`. Expect rejection.

**Test scenario (5b):** B2 — Approve an action; execute successfully; attempt to execute again with same approval. Expect rejection on second attempt.

**Acceptable evidence:** Second execution returns 403 `reason: APPROVAL_ALREADY_CONSUMED`; mock tool invoked at most once.

---

## I6 — Revocation After Authorization Prevents Execution

**Invariant:** If an agent is revoked after a capability is issued but before the executor's revocation check, the executor must reject the execution.

**Enforcement component:** Protected Executor (Step 11f — revocation check at execution time).

**Assumption:** Revocation is written to Redis before the executor's check. Narrow race documented in FAILURE_MODEL.md.

**Test scenario:** A6 — Issue capability; revoke agent; attempt execution.

**Acceptable evidence:** Executor returns 403 `reason: AGENT_REVOKED`; mock tool state unchanged.

**Known limitation:** A sub-millisecond race exists between revocation write and executor check. This window is documented in FAILURE_MODEL.md (F6).

---

## I7 — Critical Dependency Failure Does Not Authorize a Protected Side Effect

**Invariant:** If Redis, OPA, or the revocation store is unavailable, the executor must fail closed and not execute the protected tool.

**Enforcement component:** Protected Executor (fail-closed checks at Steps 11e, 11f, 11h).

**Assumption:** Fail-closed behavior is implemented in code, not just described.

**Test scenario:** A9 — Disable Redis; attempt execution. Disable OPA; attempt authorization.

**Acceptable evidence:** Both return 503 with appropriate reason code; mock tool state unchanged.

---

## I8 — Cross-Tenant Access Is Denied

**Invariant:** An agent from tenant-A cannot authorize or execute an action on a resource owned by tenant-B.

**Enforcement component:** API Gateway (Step 5 — resource ownership check); Executor (capability tenant_id binding).

**Assumption:** Resource ownership is correctly stored and checked in PostgreSQL.

**Test scenario:** A5 — Agent from tenant-A requests action on `tenant-B/orders/ORDER-999`.

**Acceptable evidence:** Gateway returns 403 `reason: RESOURCE_OWNERSHIP_FAILED`; no capability issued; no side effect.

---

## I9 — Uncertain Outcomes Are Reconciled Rather Than Blindly Retried

**Invariant:** When an execution enters UNKNOWN state, the system queries the mock tool's idempotency endpoint before retrying, rather than blindly invoking the tool a second time.

**Enforcement component:** Protected Executor (reconciliation logic, FAILURE_MODEL.md Section 4).

**Assumption:** Mock tool supports idempotency key queries.

**Test scenario:** A11 — Inject failure around tool invocation; observe state transition to UNKNOWN; run reconciliation; verify mock tool is not invoked a second time if it already succeeded.

**Acceptable evidence:** UNKNOWN state observed; reconciliation queries idempotency endpoint; mock tool shows exactly one invocation; final state transitions to SUCCEEDED or FAILED_FINAL.

---

## I10 — Audit Alteration Is Detected Under Documented Integrity Assumptions

**Invariant:** If a record in the audit chain is modified, deleted, or reordered, the independent verifier must detect the inconsistency.

**Enforcement component:** Audit chain hash construction (Girish's module); Independent Verifier.

**Assumption:** The attacker does not simultaneously control the signing key and all audit storage. This assumption is documented.

**Test scenario:** A10 — Modify an audit record in PostgreSQL; run verifier; expect detection.

**Acceptable evidence:** Verifier reports hash chain break at the modified record; identifies the first broken link.

**Limitation:** An attacker who controls both the signing key and all audit storage can rewrite the chain undetectably. This is out of scope (see THREAT_MODEL.md Section 3).

---

## I11 — At Least One Valid Benign Action Can Complete

**Invariant:** The security controls must not prevent a legitimate, within-policy action from completing successfully.

**Enforcement component:** Full stack — all controls must be traversable for valid input.

**Test scenario:** B1 — Valid mock refund with all preconditions met.

**Acceptable evidence:** Execution succeeds; mock tool state changes; receipt produced; audit event recorded; execution record shows SUCCEEDED.

---

## I12 — Metrics Are Derived From Actual Test Evidence

**Invariant:** Dashboard metrics and attack lab results are computed from actual system state, not hardcoded or fabricated.

**Enforcement component:** API Gateway metrics endpoint; Dashboard frontend.

**Test scenario:** Compare dashboard-displayed metrics against raw PostgreSQL execution records and Redis state.

**Acceptable evidence:** Dashboard values match database query results; no hardcoded values in frontend code.

---

## Invariant-to-Test Matrix

| Invariant | Attack Scenario | Test File | Status |
|---|---|---|---|
| I1 | A1 — Direct bypass | tests/adversarial/test_direct_bypass.py | TODO |
| I2 | A2 — Action substitution | tests/adversarial/test_action_substitution.py | TODO |
| I3 | Hard-deny enforcement | tests/unit/test_policy.py | TODO |
| I4 | A3 — Concurrent replay | tests/adversarial/test_replay.py | TODO |
| I5a | A4/A6 — Approval substitution | tests/adversarial/test_approval.py | TODO |
| I5b | B2 — Approval single-use | tests/integration/test_approval_flow.py | TODO |
| I6 | A6 — Revocation race | tests/adversarial/test_revocation.py | TODO |
| I7 | A9 — Dependency outage | tests/adversarial/test_fail_closed.py | TODO |
| I8 | A5 — Cross-tenant | tests/adversarial/test_tenant_isolation.py | TODO |
| I9 | A11 — Timeout/retry | tests/adversarial/test_recovery.py | TODO |
| I10 | A10 — Audit tampering | tests/adversarial/test_audit_tampering.py | TODO |
| I11 | B1 — Benign refund | tests/integration/test_happy_path.py | TODO |
| I12 | Metrics accuracy | tests/integration/test_metrics.py | TODO |

---

*Last updated: 2026-10-13 | Owner: Pavan*
