# AgentShield V2 — Failure Model

**Owner: Pavan**  
**Status: Authoritative. Every failure window must be handled in Alok's implementation.**

---

## 1. Purpose

This document specifies how AgentShield behaves under dependency outages, crash windows, and race conditions. The core principle is **fail-closed**: when authorization or safety state is unavailable, the protected side effect must not occur.

---

## 2. Execution State Machine

```
                    ┌──────────────────────────────────────┐
                    │                                      │
   ISSUED ──────► CLAIMED ──────► RUNNING ──────► SUCCEEDED
                    │                │
                    │                └──────► FAILED_FINAL
                    │
                    └──────────────────────► UNKNOWN
                                             │
                                             └──► (reconciliation)
```

### State Definitions

| State | Meaning |
|---|---|
| `ISSUED` | Capability has been issued to the agent. No execution record exists yet. |
| `CLAIMED` | Executor atomically claimed the capability (Redis SET NX + PG INSERT). No side effect yet. |
| `RUNNING` | Tool invocation is in progress. |
| `SUCCEEDED` | Tool returned success. Receipt and audit record persisted. |
| `FAILED_FINAL` | Tool returned a definitive failure, or a non-retriable error occurred. |
| `UNKNOWN` | Executor crashed or lost contact with the tool; outcome is uncertain. |

---

## 3. Failure Windows

### Window F1 — Before the Atomic Claim

**Scenario:** Executor crashes or loses Redis/PostgreSQL before `SET NX` and `INSERT`.

**State:** Capability is in ISSUED state only (in-memory or returned to agent). No execution record exists in PG.

**Recovery:**
- No side effect has occurred.
- The agent may retry submitting the capability (it is still valid if not expired).
- The claim attempt will proceed normally on retry.
- No reconciliation needed.

**Security invariant:** Replay protection still holds — the capability has not been claimed.

---

### Window F2 — After Claim, Before Tool Invocation

**Scenario:** Executor crashes after `SET NX` + `INSERT CLAIMED` but before calling the mock tool.

**State:** Redis claim exists. PostgreSQL record is in CLAIMED state. No side effect.

**Recovery:**
- On restart, the executor scans PostgreSQL for records stuck in CLAIMED state beyond a threshold (e.g., 60 seconds).
- For each stuck CLAIMED record: verify the capability has not expired.
- If not expired: the executor may proceed with tool invocation using the original `idempotency_key`.
- If expired: transition to FAILED_FINAL.

**Security invariant:** The Redis claim prevents another process from concurrently claiming the same capability. Only the recovery process handles the stuck record.

---

### Window F3 — During Tool Invocation (timeout or network error)

**Scenario:** The mock tool takes too long to respond, or a network partition occurs mid-call.

**State:** PostgreSQL record is in RUNNING. Outcome of the tool call is unknown.

**Recovery:**
- Transition state to UNKNOWN.
- Do NOT retry blindly.
- Query the mock tool using the `idempotency_key`:
  - If the tool reports success → transition to SUCCEEDED, persist receipt and audit record.
  - If the tool reports failure → transition to FAILED_FINAL.
  - If the tool is unreachable → leave in UNKNOWN, alert operator.
- Blind retry is prohibited: it risks a duplicate side effect if the tool does not support idempotency.

**Claim:** The system provides at-most-once capability claiming. It does NOT guarantee exactly-once external execution unless the mock tool supports idempotent reconciliation.

---

### Window F4 — After Tool Success, Before Receipt Persistence

**Scenario:** Tool invocation succeeds. Executor crashes before persisting the receipt and audit event.

**State:** PostgreSQL record may still be in RUNNING or SUCCEEDED (depending on crash timing). Mock tool state has changed.

**Recovery:**
- On restart, scan for RUNNING records.
- Query the mock tool with `idempotency_key`.
- If tool reports success → persist receipt (sign now), persist audit event, transition to SUCCEEDED.
- The signed receipt timestamp will reflect recovery time, not original execution time. Document this.

**Risk:** A receipt signed after a crash cannot assert the exact original execution timestamp. The audit record must note this.

---

### Window F5 — During Audit Delivery

**Scenario:** Audit event delivery fails after execution succeeds.

**State:** Execution is SUCCEEDED. Audit record is missing.

**Recovery:**
- The execution record itself is evidence of the operation.
- The audit pipeline should be idempotent: re-delivery of an audit event for an already-recorded execution_id is a no-op.
- Gaps in the audit chain must be reconciled by the verifier (Girish's module reports missing events).

**Risk:** A gap in the audit chain is detectable by the verifier but cannot be automatically filled without re-signing.

---

### Window F6 — Revocation Race

**Scenario:** An agent is revoked after the gateway issues a capability but before the executor performs its revocation check.

**Race window:** `t_revoke` to `t_executor_check`.

**Behavior:**
- If `t_revoke < t_executor_check`: executor sees the revocation → reject. Invariant holds.
- If `t_revoke > t_executor_check` (very narrow window): executor does not see the revocation → may proceed.

**Mitigation:**
- Revocation is written to both Redis (immediate) and PostgreSQL (durable).
- The executor checks both.
- The race window is the propagation delay of Redis writes (typically sub-millisecond on the same host).
- Document this as a known narrow race condition. It is not a design flaw in the security protocol, but an operational constraint.

**Residual risk:** A revocation that occurs within the Redis write latency window of an executor check may not be observed. This is acknowledged and documented.

---

### Window F7 — OPA Outage

**Scenario:** OPA service becomes unavailable.

**Behavior:** Fail-closed.
- Gateway cannot issue a capability without OPA confirmation → returns 503.
- Executor cannot re-evaluate policy without OPA → returns 503 `reason: POLICY_CHECK_UNAVAILABLE`.
- No protected side effect occurs.

**Recovery:** Restore OPA. No special application-level recovery needed.

---

### Window F8 — Redis Outage

**Scenario:** Redis becomes unavailable.

**Behavior:** Fail-closed.
- Executor cannot perform `SET NX` for capability claiming → returns 503 `reason: REPLAY_CHECK_UNAVAILABLE`.
- No protected side effect occurs.

**Recovery:** Restore Redis. Outstanding CLAIMED records in PostgreSQL are the ground truth for recovery.

---

### Window F9 — PostgreSQL Outage

**Scenario:** PostgreSQL becomes unavailable.

**Behavior:** Fail-closed.
- Gateway cannot resolve agent identity → 503.
- Executor cannot INSERT execution record → 503 `reason: EXECUTION_STORE_UNAVAILABLE`.
- No protected side effect occurs.

---

### Window F10 — Approval Service Outage

**Scenario:** PostgreSQL (approval table) is unavailable when approval verification is required.

**Behavior:** Fail-closed.
- Executor cannot verify or consume the approval → returns 503 `reason: APPROVAL_STORE_UNAVAILABLE`.
- No protected side effect occurs.

---

## 4. Reconciliation Protocol

When the executor discovers an execution record in UNKNOWN state:

1. Extract `idempotency_key` (= `jti`) from the execution record.
2. Call mock tool's idempotency query endpoint: `GET /mock/tool/result?idempotency_key={jti}`.
3. Interpret response:
   - `{status: "succeeded", result: {...}}` → transition to SUCCEEDED, sign and persist receipt, emit audit event.
   - `{status: "failed", error: "..."}` → transition to FAILED_FINAL, emit audit event.
   - `{status: "not_found"}` → tool did not process the request. Capability is expired by now. Transition to FAILED_FINAL.
   - Tool unreachable → leave in UNKNOWN, schedule retry of reconciliation with backoff.

4. Maximum reconciliation attempts: configurable (default: 5, with exponential backoff).
5. After max attempts with tool unreachable: transition to FAILED_FINAL, emit audit event with note `RECONCILIATION_EXHAUSTED`.

---

## 5. Claims and Disclaimers

| Claim | Status |
|---|---|
| At-most-once capability claiming | Guaranteed (Redis SET NX + PG UNIQUE) |
| Idempotent tool execution | Guaranteed IF mock tool supports idempotency key check |
| Exactly-once external side effect | NOT guaranteed in general. Guaranteed only if mock tool is idempotent AND reconciliation is run. |
| Fail-closed on Redis outage | Guaranteed |
| Fail-closed on OPA outage | Guaranteed |
| Fail-closed on revocation store outage | Guaranteed |
| Zero-window revocation race | NOT guaranteed. Narrow race exists (sub-ms). Documented. |
| Audit completeness after crash | NOT guaranteed automatically. Recovery required. |

---

*Last updated: 2026-10-13 | Owner: Pavan*
