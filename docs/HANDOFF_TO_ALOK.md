# AgentShield V2 — Handoff: Pavan → Alok

**From:** Pavan (Security Architecture Lead)  
**To:** Alok (Implementation Lead)  
**Date:** 2026-10-13

This document contains every requirement, interface, and decision you need to implement AgentShield V2 correctly. Read it before touching security-sensitive code.

---

## 1. What you must NOT change without consulting Pavan

- The canonical action schema (`backend/app/security/schemas.py`)
- The canonicalization function (`backend/app/security/canonicalization.py`)
- The Docker network topology in `docker-compose.yml`
- The OPA policy logic in `policy/agentshield.rego`

If you find a bug in any of these, tell Pavan first. Do not patch them unilaterally.

---

## 2. Identity Resolution — CRITICAL

**Never trust `principal_id`, `tenant_id`, or `role` from the request body.**

The gateway must:
1. Extract the Bearer token from the `Authorization` header.
2. Verify the JWT signature and expiry.
3. Look up the agent record in PostgreSQL by the token's `sub` claim.
4. Use the `principal_id` and `tenant_id` from the **database record**, not the request body.
5. Validate that the action envelope's `principal_id` and `tenant_id` **match** the database values. If they differ → return `403 IDENTITY_MISMATCH`.

This prevents T4 (identity spoofing). It is the most commonly misimplemented control.

---

## 3. Required API Endpoints

Implement these exactly. Do not rename or restructure without team agreement.

```
POST /v1/agents                          Register an agent
POST /v1/actions/authorize               Authorize an action → capability token
POST /v1/approvals/{id}/decision         Submit approval decision
POST /v1/actions/execute                 Execute with capability token
POST /v1/agents/{id}/revoke              Revoke an agent
GET  /v1/audit/events                    Get audit event log
POST /v1/audit/verify                    Run audit chain verification
GET  /v1/metrics/summary                 System metrics (real data only)
POST /v1/demo/reset                      Reset to fixture state
GET  /health                             Health check for all services
```

All error responses must include:
```json
{
  "request_id": "uuid",
  "trace_id": "uuid",
  "reason": "REASON_CODE_FROM_PROTOCOL",
  "detail": "human-readable description"
}
```

Never expose signing keys, capability tokens (in errors), private keys, or database credentials in responses.

---

## 4. Executor Verification Order

The executor must run these steps **in order** before any side effect. Do not reorder them.

```python
# Step 11a: Verify Ed25519 signature (Girish's module)
claims = girish.verify_capability(token, action, principal_id, verification_context)

# Step 11b: Check issuer, audience, environment
assert claims.iss == "agentshield-capability-issuer-v1"
assert claims.aud == "agentshield-protected-executor-v1"
assert claims.environment == current_environment

# Step 11c: Check expiry (5s clock skew)
assert claims.exp > (time.time() - 5)

# Step 11d: Recompute digest from execution request; compare to capability
execution_digest = calculate_action_digest(execution_action)
assert execution_digest == claims.action_digest  # DIGEST_MISMATCH if not equal

# Step 11e: Re-evaluate OPA with current context
opa_result = opa.evaluate(current_context)
assert opa_result.result == "allow"

# Step 11f: Check revocation (Redis first, then PostgreSQL; fail-closed)
revoked = redis.get(f"revoked:{principal_id}:{tenant_id}")
if revoked is None:  # Redis miss, check PG
    revoked = pg.query("SELECT * FROM revocations WHERE ...")
# If Redis is down → raise 503 REVOCATION_CHECK_UNAVAILABLE

# Step 11g: If approval required, verify and atomically consume
if claims.approval_id:
    approval = pg.get_approval(claims.approval_id)
    assert approval.action_digest == execution_digest
    assert approval.tenant_id == claims.tenant_id
    assert not approval.consumed
    assert approval.expires_at > now
    assert approval.decision == "approved"
    pg.consume_approval(claims.approval_id)  # ATOMIC with step 11i

# Step 11h: Atomic Redis claim
result = redis.set(claims.jti, "claimed", nx=True, ex=remaining_ttl)
if not result:
    raise 409 CAPABILITY_ALREADY_CLAIMED

# Step 11i: Durable execution record
pg.insert_execution_record(jti=claims.jti, state="CLAIMED", ...)
# UNIQUE constraint on jti — duplicate INSERT → handle as replay

# ONLY NOW: invoke mock tool
```

---

## 5. Fail-Closed Requirements

If any of these are unavailable, return 503 and do NOT execute the tool:

| Dependency | Unavailability → |
|---|---|
| Redis | 503 REPLAY_CHECK_UNAVAILABLE |
| OPA | 503 POLICY_CHECK_UNAVAILABLE |
| PostgreSQL (execution record) | 503 EXECUTION_STORE_UNAVAILABLE |
| PostgreSQL (revocation check) | 503 REVOCATION_CHECK_UNAVAILABLE |
| PostgreSQL (approval check) | 503 APPROVAL_STORE_UNAVAILABLE |

---

## 6. Database Schema Requirements

### `agents` table
```sql
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    display_name TEXT,
    permitted_tools TEXT[] NOT NULL,
    max_amount_minor BIGINT,
    environment TEXT NOT NULL,
    registered BOOLEAN NOT NULL DEFAULT TRUE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    api_key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
```

### `execution_records` table
```sql
CREATE TABLE execution_records (
    execution_id UUID PRIMARY KEY,
    jti TEXT NOT NULL UNIQUE,  -- UNIQUE constraint is required for replay protection
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    resource TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ISSUED','CLAIMED','RUNNING','SUCCEEDED','FAILED_FINAL','UNKNOWN')),
    idempotency_key TEXT NOT NULL,
    result JSONB,
    error TEXT,
    receipt_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### `approvals` table
```sql
CREATE TABLE approvals (
    approval_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    approver_identity TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    approval_policy_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
```

### `revocations` table
```sql
CREATE TABLE revocations (
    revocation_id UUID PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    revoked_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_by TEXT NOT NULL
);
CREATE INDEX ON revocations (agent_id, tenant_id);
```

### `audit_events` table
```sql
CREATE TABLE audit_events (
    seq BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    principal_id TEXT,
    action_digest TEXT,
    jti TEXT,
    execution_id UUID,
    approval_id UUID,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    signature TEXT,
    kid TEXT
);
```

---

## 7. Redis Key Conventions

| Key pattern | TTL | Purpose |
|---|---|---|
| `capability:{jti}` | = capability remaining expiry | Atomic claim (SET NX) |
| `revoked:{agent_id}:{tenant_id}` | No expiry (permanent until cleared) | Fast revocation check |
| `ratelimit:{agent_id}:{window}` | = window duration | Rate limiting |

---

## 8. Modules to Import from Girish

Girish owns the implementations. You call them; you do not duplicate them.

```python
# In executor service:
from app.security.canonicalization import calculate_action_digest, verify_digest_matches
from app.security.capability import verify_capability      # Girish implements
from app.security.approval_binding import verify_approval  # Girish implements
from app.security.execution_receipt import sign_execution_receipt  # Girish implements
from app.security.audit_chain import append_audit_record   # Girish implements
```

Agree on the final function signatures with Girish before integrating.

---

## 9. Things That Will Fail Pavan's Security Review

- Identity resolved from request body → CRITICAL finding
- No executor-side digest recomputation → CRITICAL finding
- OPA called only at gateway (not at executor) → HIGH finding
- Revocation checked only at authorization (not at execution) → HIGH finding
- Signing key logged or returned in API response → CRITICAL finding
- Hardcoded metrics in dashboard → MEDIUM finding
- Dashboard fakes revocation or approval state → HIGH finding
- Missing UNIQUE constraint on `jti` → CRITICAL finding
- Fail-open on Redis unavailability → CRITICAL finding

---

*Last updated: 2026-10-13 | From: Pavan*
