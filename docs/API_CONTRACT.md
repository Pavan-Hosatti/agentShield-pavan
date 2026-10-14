# AgentShield V2 — API Contract

**Owner: Pavan (specification) | Alok (implementation)**  
**Status: Frozen. Changes require team consensus.**

All routes are versioned at `/v1`. Alok generates the OpenAPI spec from FastAPI; this document is the authoritative design contract.

---

## Authentication

All endpoints (except `/health`) require:
```
Authorization: Bearer <jwt_or_api_key>
```

The gateway resolves `principal_id` and `tenant_id` from the credential, never from the request body.

---

## Standard Response Envelope

### Success
```json
{
  "request_id": "uuid",
  "trace_id": "uuid",
  "data": { ... }
}
```

### Error
```json
{
  "request_id": "uuid",
  "trace_id": "uuid",
  "reason": "REASON_CODE",
  "detail": "Human-readable explanation"
}
```

**Never include in error responses:** signing keys, raw capability tokens, private keys, database credentials.

---

## Endpoints

---

### POST /v1/agents

Register a new agent.

**Request body:**
```json
{
  "agent_id": "agent-support-01",
  "display_name": "Support Agent 01",
  "permitted_tools": ["issue_refund"],
  "environment": "demo"
}
```

**Response 201:**
```json
{
  "request_id": "uuid",
  "data": {
    "agent_id": "agent-support-01",
    "tenant_id": "tenant-demo",
    "api_key": "as_live_xxxx"
  }
}
```
*Note: `api_key` is returned only once at registration. Store it securely.*

**Errors:**
- `409 AGENT_ALREADY_EXISTS`
- `422 SCHEMA_VALIDATION_FAILED`

---

### POST /v1/actions/authorize

Authorize an action. Returns a signed capability token or an approval request.

**Request body:** (ActionEnvelope — see ACTION_CONTRACT.md)
```json
{
  "schema_version": 1,
  "tenant_id": "tenant-demo",
  "principal_id": "agent-support-01",
  "tool": "issue_refund",
  "resource": "orders/ORDER-123",
  "arguments": { "order_id": "ORDER-123", "amount_minor": 29999 },
  "environment": "demo",
  "policy_version": 3,
  "intent_id": "intent-demo-001"
}
```

**Response 200** (allowed, capability issued):
```json
{
  "request_id": "uuid",
  "data": {
    "capability_token": "<compact JWS>",
    "action_digest": "7b10052f...",
    "expires_at": "2026-10-13T00:05:00Z",
    "jti": "uuid"
  }
}
```

**Response 202** (needs approval):
```json
{
  "request_id": "uuid",
  "data": {
    "approval_request_id": "uuid",
    "action_digest": "7b10052f...",
    "expires_at": "2026-10-13T01:00:00Z",
    "status": "PENDING_APPROVAL"
  }
}
```

**Errors:**
- `401 INVALID_CREDENTIAL`
- `403 IDENTITY_MISMATCH`
- `403 RESOURCE_OWNERSHIP_FAILED`
- `403 HARD_DENY` (with `reason` from OPA)
- `403 APPROVAL_REQUIRED` (if re-submit without approval)
- `422 SCHEMA_VALIDATION_FAILED`
- `503 POLICY_CHECK_UNAVAILABLE`

---

### POST /v1/approvals/{id}/decision

Submit an approval decision. Approver authentication required.

**Path param:** `id` = approval_request_id

**Request body:**
```json
{
  "decision": "approved",
  "approver_note": "Verified with customer"
}
```
*`decision` must be `"approved"` or `"rejected"`*

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "approval_id": "uuid",
    "action_digest": "7b10052f...",
    "decision": "approved",
    "expires_at": "2026-10-13T01:00:00Z"
  }
}
```

**Errors:**
- `401 INVALID_CREDENTIAL` (approver not authenticated)
- `403 APPROVER_NOT_AUTHORIZED`
- `404 APPROVAL_REQUEST_NOT_FOUND`
- `409 APPROVAL_ALREADY_DECIDED`
- `410 APPROVAL_REQUEST_EXPIRED`

---

### POST /v1/actions/execute

Execute an action using a capability token. Final enforcement boundary.

**Request body:**
```json
{
  "capability_token": "<compact JWS>",
  "action": { /* ActionEnvelope — must match capability exactly */ }
}
```

**Response 200** (execution succeeded):
```json
{
  "request_id": "uuid",
  "data": {
    "execution_id": "uuid",
    "state": "SUCCEEDED",
    "action_digest": "7b10052f...",
    "receipt": {
      "receipt_id": "uuid",
      "execution_result": "succeeded",
      "timestamp": "2026-10-13T00:00:05Z",
      "kid": "key-v1"
    },
    "tool_result": { "mock_refund_id": "MOCK-001", "status": "processed" }
  }
}
```

**Errors:**
- `403 INVALID_CAPABILITY_SIGNATURE`
- `403 CAPABILITY_EXPIRED`
- `403 CAPABILITY_CONTEXT_MISMATCH`
- `403 DIGEST_MISMATCH`        ← action substitution detected
- `403 AGENT_REVOKED`
- `403 POLICY_DENY_AT_EXECUTION`
- `403 APPROVAL_INVALID`
- `403 APPROVAL_ALREADY_CONSUMED`
- `409 CAPABILITY_ALREADY_CLAIMED` ← replay detected
- `503 REPLAY_CHECK_UNAVAILABLE`
- `503 REVOCATION_CHECK_UNAVAILABLE`
- `503 EXECUTION_STORE_UNAVAILABLE`

---

### POST /v1/agents/{id}/revoke

Revoke an agent. Revocation is immediate and durable.

**Path param:** `id` = agent_id

**Request body:**
```json
{
  "reason": "Compromised credential"
}
```

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "agent_id": "agent-support-01",
    "revoked_at": "2026-10-13T00:01:00Z"
  }
}
```

**Errors:**
- `404 AGENT_NOT_FOUND`
- `409 AGENT_ALREADY_REVOKED`

---

### GET /v1/audit/events

Retrieve audit events. Supports pagination and filtering.

**Query params:**
- `tenant_id` — filter by tenant
- `principal_id` — filter by agent
- `event_type` — filter by event type
- `from_seq` — start from sequence number
- `limit` — max records (default 50, max 500)

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "events": [ { /* AuditEvent */ } ],
    "total": 42,
    "from_seq": 1,
    "next_seq": 51
  }
}
```

---

### POST /v1/audit/verify

Run independent audit chain verification.

**Request body:**
```json
{
  "from_seq": 1,
  "to_seq": 100
}
```

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "valid": true,
    "records_checked": 100,
    "issues": [],
    "first_broken_seq": null
  }
}
```

**If tampered:**
```json
{
  "data": {
    "valid": false,
    "records_checked": 50,
    "issues": [
      { "issue_type": "HASH_MISMATCH", "seq": 23,
        "detail": "record_hash mismatch at seq=23" }
    ],
    "first_broken_seq": 23
  }
}
```

---

### GET /v1/metrics/summary

Real system metrics. Never fabricated. Derived from actual execution records.

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "executions_total": 142,
    "executions_succeeded": 138,
    "executions_failed": 3,
    "executions_unknown": 1,
    "authorizations_total": 200,
    "denials_by_reason": {
      "DIGEST_MISMATCH": 12,
      "CAPABILITY_ALREADY_CLAIMED": 87,
      "AGENT_REVOKED": 3
    },
    "approvals_pending": 2,
    "approvals_consumed": 15,
    "agents_active": 3,
    "agents_revoked": 1,
    "latency_p50_ms": 18,
    "latency_p95_ms": 42,
    "audit_chain_length": 500,
    "audit_chain_valid": true
  }
}
```

**Note:** `latency_p50_ms` and `latency_p95_ms` are computed from actual request logs. If no measurements exist, return `null`, not `0`.

---

### POST /v1/demo/reset

Reset all state to demo fixtures. Demo environment only.

**Request body:**
```json
{
  "confirm": "RESET_DEMO_STATE"
}
```

**Response 200:**
```json
{
  "request_id": "uuid",
  "data": {
    "status": "reset_complete",
    "agents_created": 3,
    "orders_created": 3,
    "audit_events_cleared": 500,
    "executions_cleared": 142
  }
}
```

**Errors:**
- `403 RESET_NOT_ALLOWED` (if environment != demo)

---

### GET /health

Health check for Docker Compose and monitoring.

**Response 200:**
```json
{
  "status": "healthy",
  "services": {
    "database": "up",
    "redis": "up",
    "opa": "up"
  },
  "timestamp": "2026-10-13T00:00:00Z"
}
```

**Response 503** (degraded):
```json
{
  "status": "degraded",
  "services": {
    "database": "up",
    "redis": "down",
    "opa": "up"
  }
}
```

---

## Reason Code Reference

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_CREDENTIAL` | 401 | Bearer token invalid or expired |
| `IDENTITY_MISMATCH` | 403 | Body fields don't match credential |
| `RESOURCE_OWNERSHIP_FAILED` | 403 | Resource not owned by tenant |
| `TOOL_NOT_PERMITTED` | 403 | Tool not in agent's permitted set |
| `HARD_DENY` | 403 | OPA hard deny (no approval override) |
| `POLICY_DENY` | 403 | OPA deny at authorization |
| `POLICY_DENY_AT_EXECUTION` | 403 | OPA deny re-evaluated at execution |
| `POLICY_VERSION_STALE` | 403 | Capability policy version below minimum |
| `APPROVAL_REQUIRED` | 403 | Action needs approval, none provided |
| `APPROVAL_REJECTED` | 403 | Human approver rejected the action |
| `APPROVAL_INVALID` | 403 | Approval expired, consumed, or wrong digest |
| `APPROVAL_ALREADY_CONSUMED` | 403 | Approval already used |
| `INVALID_CAPABILITY_SIGNATURE` | 403 | Capability signature invalid |
| `CAPABILITY_EXPIRED` | 403 | Capability past expiry |
| `CAPABILITY_CONTEXT_MISMATCH` | 403 | Wrong issuer/audience/environment |
| `DIGEST_MISMATCH` | 403 | Execution action differs from authorized |
| `AGENT_REVOKED` | 403 | Agent has been revoked |
| `CAPABILITY_ALREADY_CLAIMED` | 409 | Replay detected |
| `EXECUTION_RECORD_DUPLICATE` | 409 | Duplicate execution record (replay) |
| `SCHEMA_VALIDATION_FAILED` | 422 | Request body schema invalid |
| `POLICY_CHECK_UNAVAILABLE` | 503 | OPA unreachable |
| `REPLAY_CHECK_UNAVAILABLE` | 503 | Redis unreachable |
| `REVOCATION_CHECK_UNAVAILABLE` | 503 | Revocation store unreachable |
| `EXECUTION_STORE_UNAVAILABLE` | 503 | PostgreSQL unreachable |
| `APPROVAL_STORE_UNAVAILABLE` | 503 | Approval store unreachable |

---

*Last updated: 2026-10-13 | Owner: Pavan*
