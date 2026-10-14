# AgentShield V2 — Design-to-Test Matrix

**Owner: Pavan**  
**Status: Maps every security invariant to a concrete, executable test. Gururaj implements.**

---

## How to Read This Matrix

Each row maps:
- A security invariant (from SECURITY_INVARIANTS.md)
- To the attack scenario(s) that test it
- To the specific test file and function
- To the expected result and acceptable evidence
- To the current implementation status

A test is **PASS** only when:
1. It runs against the actual integrated services (not mocks of the security layer).
2. The actual result matches the expected result.
3. The mock tool state is verified after the test.
4. The audit evidence is verified after the test.

---

## Matrix

### I1 — No Bypass to Protected Tool

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I1-A | A1: Agent direct access | tests/adversarial/test_direct_bypass.py | `test_agent_cannot_reach_mock_tool` | Connection refused / no route | HTTP status code; mock state unchanged |
| T-I1-B | A1: Gateway direct access | tests/adversarial/test_direct_bypass.py | `test_gateway_cannot_reach_mock_tool` | Connection refused / no route | HTTP status code; mock state unchanged |

---

### I2 — No Execution on Digest Mismatch

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I2-A | A2: Amount changed | tests/adversarial/test_action_substitution.py | `test_amount_changed_after_authorization` | 403 DIGEST_MISMATCH | No execution record; mock state unchanged |
| T-I2-B | A2: Resource changed | tests/adversarial/test_action_substitution.py | `test_resource_changed_after_authorization` | 403 DIGEST_MISMATCH | No execution record; mock state unchanged |
| T-I2-C | A2: Tenant changed | tests/adversarial/test_action_substitution.py | `test_tenant_changed_after_authorization` | 403 DIGEST_MISMATCH | No execution record; mock state unchanged |
| T-I2-D | A2: Tool changed | tests/adversarial/test_action_substitution.py | `test_tool_changed_after_authorization` | 403 DIGEST_MISMATCH | No execution record; mock state unchanged |

---

### I3 — Hard-Deny Enforcement

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I3-A | Hard-deny policy rule | tests/unit/test_policy.py | `test_hard_deny_no_capability_issued` | 403 HARD_DENY | No capability in response; no issuance audit event |
| T-I3-B | Hard-deny with valid approval | tests/unit/test_policy.py | `test_hard_deny_not_overridden_by_approval` | 403 HARD_DENY | Approval cannot unlock hard-deny |

---

### I4 — At Most One Concurrent Claim

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I4-A | A3: 100 concurrent replays | tests/adversarial/test_replay.py | `test_concurrent_replay_100_requests` | 1× 200, 99× 409 CAPABILITY_ALREADY_CLAIMED | Execution record count = 1 SUCCEEDED; mock invocation count = 1 |
| T-I4-B | A3: Sequential replay | tests/adversarial/test_replay.py | `test_sequential_replay_rejected` | First 200; second 409 CAPABILITY_ALREADY_CLAIMED | |

---

### I5a — Approval Bound to Exact Action

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I5a-A | A4: Approval for different amount | tests/adversarial/test_approval.py | `test_approval_wrong_amount_rejected` | 403 APPROVAL_INVALID | Mock state unchanged |
| T-I5a-B | A4: Approval for different resource | tests/adversarial/test_approval.py | `test_approval_wrong_resource_rejected` | 403 APPROVAL_INVALID | Mock state unchanged |
| T-I5a-C | A4: Approval for different tenant | tests/adversarial/test_approval.py | `test_approval_wrong_tenant_rejected` | 403 APPROVAL_INVALID | Mock state unchanged |
| T-I5a-D | Expired approval | tests/adversarial/test_approval.py | `test_expired_approval_rejected` | 403 APPROVAL_INVALID | Mock state unchanged |
| T-I5a-E | Rejected approval | tests/adversarial/test_approval.py | `test_rejected_approval_not_accepted` | 403 APPROVAL_INVALID | Mock state unchanged |

---

### I5b — Approval Single-Use

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I5b-A | B2: Second use of consumed approval | tests/integration/test_approval_flow.py | `test_approval_consumed_after_first_use` | First: 200; Second: 403 APPROVAL_ALREADY_CONSUMED | Execution record count = 1 SUCCEEDED; approval.consumed = true |
| T-I5b-B | Concurrent approval consumption | tests/adversarial/test_approval.py | `test_concurrent_approval_consumption` | At most one 200; others 403 APPROVAL_ALREADY_CONSUMED | Mock invoked once |

---

### I6 — Revocation at Execution Time

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I6-A | A6: Revoke after authorization | tests/adversarial/test_revocation.py | `test_revocation_between_auth_and_execution` | 403 AGENT_REVOKED | Mock state unchanged |
| T-I6-B | Revoked agent cannot re-authorize | tests/adversarial/test_revocation.py | `test_revoked_agent_cannot_authorize` | 403 AGENT_REVOKED | No capability issued |

---

### I7 — Fail-Closed on Dependency Outage

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I7-A | A9: Redis unavailable | tests/adversarial/test_fail_closed.py | `test_redis_outage_blocks_execution` | 503 REPLAY_CHECK_UNAVAILABLE | Mock state unchanged |
| T-I7-B | A9: OPA unavailable | tests/adversarial/test_fail_closed.py | `test_opa_outage_blocks_authorization` | 503 POLICY_CHECK_UNAVAILABLE | No capability issued |
| T-I7-C | A9: PostgreSQL unavailable | tests/adversarial/test_fail_closed.py | `test_postgres_outage_blocks_execution` | 503 EXECUTION_STORE_UNAVAILABLE | Mock state unchanged |

---

### I8 — Cross-Tenant Isolation

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I8-A | A5: Cross-tenant resource | tests/adversarial/test_tenant_isolation.py | `test_cross_tenant_resource_rejected` | 403 RESOURCE_OWNERSHIP_FAILED | No capability issued |
| T-I8-B | A5: Identity spoof in body | tests/adversarial/test_tenant_isolation.py | `test_identity_spoof_rejected` | 403 IDENTITY_MISMATCH | No capability issued |

---

### I9 — Uncertain Outcome Reconciliation

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I9-A | A11: Tool timeout → UNKNOWN | tests/adversarial/test_recovery.py | `test_execution_enters_unknown_on_timeout` | State = UNKNOWN; no duplicate side effect | Execution record = UNKNOWN; mock invoked once |
| T-I9-B | A11: Reconciliation succeeds | tests/adversarial/test_recovery.py | `test_reconciliation_resolves_unknown` | State transitions UNKNOWN → SUCCEEDED | Mock invoked once; receipt produced |

---

### I10 — Audit Tamper Detection

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I10-A | A10: Modify record | tests/adversarial/test_audit_tampering.py | `test_modified_record_detected` | Verifier reports CHAIN_BREAK at modified record | Verifier output identifies first broken link |
| T-I10-B | A10: Delete record | tests/adversarial/test_audit_tampering.py | `test_deleted_record_detected` | Verifier reports SEQ_GAP | Verifier output identifies sequence gap |
| T-I10-C | A10: Reorder records | tests/adversarial/test_audit_tampering.py | `test_reordered_records_detected` | Verifier reports CHAIN_BREAK | |

---

### I11 — Benign Action Succeeds

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I11-A | B1: Full happy path | tests/integration/test_happy_path.py | `test_valid_refund_succeeds` | 200; mock state changed; receipt valid; audit extended | All state transitions verified; receipt signature valid |
| T-I11-B | B2: Approval required then granted | tests/integration/test_approval_flow.py | `test_approval_required_then_approved` | Blocked → approved → executes once | Approval consumed; execution succeeded |

---

### I12 — Metrics Accuracy

| Test ID | Scenario | Test File | Test Function | Expected | Evidence |
|---|---|---|---|---|---|
| T-I12-A | Metrics from real data | tests/integration/test_metrics.py | `test_metrics_match_database_state` | Dashboard metrics == DB query results | No hardcoded values; comparison passes |

---

## Glossary of Status Values

| Status | Meaning |
|---|---|
| TODO | Test designed here; not yet implemented |
| IN_PROGRESS | Being implemented by Gururaj |
| PASS | Test runs against integrated services and passes |
| FAIL | Test runs and fails (security issue) |
| NOT_IMPLEMENTED | Feature not yet built; test cannot be run |

---

*Last updated: 2026-10-13 | Owner: Pavan*
