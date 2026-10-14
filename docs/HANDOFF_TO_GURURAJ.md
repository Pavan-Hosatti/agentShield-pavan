# AgentShield V2 — Handoff: Pavan → Gururaj

**From:** Pavan (Security Architecture Lead)  
**To:** Gururaj (Red Team and Evaluation Engineer)  
**Date:** 2026-10-13

---

## 1. What to Test and Why

Your job is to prove whether the security invariants actually hold in the running system — not just in code review.

The invariants are defined in `docs/SECURITY_INVARIANTS.md`.  
The attack scenarios are defined in `docs/ATTACK_MATRIX.md`.  
The test mapping is in `docs/DESIGN_TEST_MATRIX.md`.

For every scenario: run it, record the actual result, compare to expected.

---

## 2. Authoritative Test Vector

You must verify that your environment produces this exact digest for Vector 1:

```
Input (sorted compact JSON):
{"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},"environment":"demo","intent_id":"intent-demo-001","policy_version":3,"principal_id":"agent-support-01","resource":"orders/ORDER-123","schema_version":1,"tenant_id":"tenant-demo","tool":"issue_refund"}

Expected digest: 7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28
```

If your environment produces a different digest, there is a canonicalization inconsistency. Stop and report it.

To verify:
```bash
cd agentshield
python -c "
import sys; sys.path.insert(0, 'backend')
from app.security.canonicalization import get_test_vector_1
_, digest = get_test_vector_1()
print('Digest:', digest)
expected = '7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28'
print('Match:', digest == expected)
"
```

---

## 3. Pre-Built Test Stubs

I have already written the test structure for you. Fill in the integration HTTP calls:

| File | Scenarios covered |
|---|---|
| `tests/adversarial/test_action_substitution.py` | A2 |
| `tests/adversarial/test_replay.py` | A3 |
| `tests/adversarial/test_revocation.py` | A6 |
| `tests/adversarial/test_fail_closed.py` | A9 |
| `tests/adversarial/test_direct_bypass.py` | A1 |
| `tests/adversarial/test_tenant_isolation.py` | A5, I8 |
| `tests/adversarial/test_approval.py` | A4, I5a, I5b |
| `tests/adversarial/test_audit_tampering.py` | A10, I10 |
| `tests/adversarial/test_recovery.py` | A11, I9 |
| `tests/integration/test_happy_path.py` | B1, B2 |

The unit-level parts of these tests already pass. You need to implement the `@pytest.mark.integration` methods.

---

## 4. Shared Fixtures

Use `tests/conftest.py` fixtures. They give you:
- `valid_action_data` — standard ₹500 refund action
- `tampered_action_data` — same with 10× amount
- `valid_action_digest` — correct digest for the valid action
- `authoritative_digest_v1` — the reference digest to compare against
- `valid_approval_record` — unconsumed approval for the valid action
- `consumed_approval_record` — already consumed approval
- `expired_approval_record` — past-expiry approval
- `gateway_url`, `executor_url`, `mock_tool_url` — service addresses
- `demo_agent_token` — pre-issued auth token (set `DEMO_AGENT_TOKEN` env var)

---

## 5. Evidence Format

Every test run must produce a JSON file. Use this structure:

```json
{
  "run_id": "run-2026-10-13-001",
  "timestamp": "2026-10-13T00:00:00Z",
  "git_commit": "abc123",
  "environment": "docker-compose-local",
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

Store raw results in `tests/results/`. Never hardcode or fabricate values.

---

## 6. Baseline Definitions

You must run the same attacks against three configurations:

**Baseline A — Role-based only:**
- No capability tokens
- No digest binding
- No executor-side re-verification
- Agent presents credentials → RBAC check → tool called directly
- Missing controls: C2 (digest), C4 (replay), C6 (approval binding), C7 (revocation at execution), C8 (fail-closed)

**Baseline B — OPA gateway:**
- OPA policy evaluation at gateway
- No signed capability
- No executor-side verification
- No digest binding
- No atomic replay protection
- Missing controls: C2, C4, C6 (approval binding), executor-side: C3, C7

**Baseline C — Full AgentShield:**
- All controls as implemented
- Document any control that is NOT_IMPLEMENTED

For each baseline, document exactly which controls are present and which are missing.

---

## 7. Attack Scenario Details

### A2 — Action Substitution
1. `POST /v1/actions/authorize` with `amount_minor: 50000` → get `capability_token`
2. `POST /v1/actions/execute` with `amount_minor: 500000` + original `capability_token`
3. Verify: HTTP 403, reason=DIGEST_MISMATCH, mock state unchanged

### A3 — Concurrent Replay (100 threads)
```python
import concurrent.futures, requests

# First: authorize to get capability_token
capability_token = authorize(amount=50000)

def attempt_execution(i):
    r = requests.post(executor_url + "/v1/actions/execute",
                      json={"capability_token": capability_token, "action": ...})
    return r.status_code

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
    results = list(pool.map(attempt_execution, range(100)))

success_count = results.count(200)
assert success_count == 1, f"Expected exactly 1 success, got {success_count}"
```

### A6 — Revocation Race
1. Authorize → capability
2. `POST /v1/agents/{agent_id}/revoke`
3. `POST /v1/actions/execute` → verify 403 AGENT_REVOKED

### A9 — Dependency Outage
```bash
# Kill Redis
docker-compose stop redis
# Attempt execution
curl -X POST .../v1/actions/execute ...
# Expect 503 REPLAY_CHECK_UNAVAILABLE
docker-compose start redis
```

### A10 — Audit Tampering
```python
# 1. Complete an execution
# 2. Directly modify the database
import psycopg2
conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()
cur.execute("UPDATE audit_events SET event_type = 'TAMPERED' WHERE seq = %s", (2,))
conn.commit()

# 3. Verify the tampering is detected
r = requests.post(gateway_url + "/v1/audit/verify")
assert r.json()["valid"] is False
assert r.json()["first_broken_seq"] == 2
```

---

## 8. What to Report

For each scenario:
- Status: PASS | FAIL | NOT_IMPLEMENTED
- If FAIL: exact reproduction steps, reason code received vs expected, mock state before and after
- If NOT_IMPLEMENTED: feature not yet built — do not skip silently

For the overall evaluation:
- Unauthorized protected-side-effect success rate by attack class
- Legitimate-task success rate (B1, B2)
- p50 and p95 latency added by AgentShield vs Baseline A
- Concurrent replay claim results (A3)
- Audit tamper detection rate (A10)

Do not report targets (1000 concurrent, <50ms p95) as achieved unless you have measured them.

---

## 9. Test Execution

```bash
# Run unit tests (no services needed)
pytest tests/unit/ tests/adversarial/ -m "not integration" -v

# Run integration tests (requires docker-compose up)
docker-compose up -d
pytest tests/integration/ tests/adversarial/ -m integration -v

# Generate coverage report
pytest --cov=backend/app --cov-report=html tests/unit/
```

---

*Last updated: 2026-10-13 | From: Pavan*
