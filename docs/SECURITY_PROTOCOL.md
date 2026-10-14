# AgentShield V2 — Security Protocol

**Owner: Pavan**  
**Status: Authoritative. Alok implements. Girish verifies crypto. Gururaj tests.**

---

## 1. Protocol Overview

The AgentShield security protocol covers the full lifecycle from action proposal to durable execution evidence. Every step is mandatory. Failures at any step must produce a documented rejection, not a fallback to a weaker path.

---

## 2. Step-by-Step Authorization Protocol

### Step 1 — Agent Authentication

**Actor:** API Gateway  
**Input:** HTTP request with Authorization header (Bearer JWT or API key)  
**Process:**
1. Extract the credential from the Authorization header.
2. Verify the credential (JWT signature, expiry, issuer; or API key hash lookup).
3. Resolve `principal_id` and `tenant_id` from the server-side agent registration record.
4. Do NOT read `principal_id`, `tenant_id`, or `role` from the request body.

**Rejection condition:** Invalid credential, expired credential, unregistered agent, or mismatched tenant.  
**Error response:** `401 Unauthorized` with `reason: INVALID_CREDENTIAL`.

---

### Step 2 — Action Schema Validation

**Actor:** API Gateway  
**Input:** Request body (action envelope)  
**Process:**
1. Parse the request body as JSON. Reject duplicate keys.
2. Validate against the canonical action schema (Pydantic strict model).
3. Reject unknown fields.
4. Validate all types: integers are integers, strings are strings, no float where integer is required.
5. Verify `schema_version` is a supported version.
6. Verify `environment` matches the expected deployment environment.

**Rejection condition:** Any schema violation, unknown field, duplicate key, wrong type, unsupported version.  
**Error response:** `422 Unprocessable Entity` with `reason: SCHEMA_VALIDATION_FAILED`, field-level errors.

---

### Step 3 — Identity and Tenant Binding Verification

**Actor:** API Gateway  
**Input:** Resolved `principal_id`, `tenant_id` from credentials + action envelope fields  
**Process:**
1. Verify that the action's `tenant_id` field matches the tenant resolved from the credential.
2. Verify that the action's `principal_id` field matches the resolved agent identity.

**Rejection condition:** `principal_id` or `tenant_id` in the action body do not match the credential-resolved values.  
**Error response:** `403 Forbidden` with `reason: IDENTITY_MISMATCH`.

---

### Step 4 — Resource Ownership Check

**Actor:** API Gateway  
**Input:** `tenant_id`, `resource` from action envelope  
**Process:**
1. Look up the resource in the agent's allowed resource set (PostgreSQL).
2. Verify that the resource is owned by / accessible to the identified tenant.
3. Verify the `tool` is in the set of permitted tools for this agent.

**Rejection condition:** Resource not owned by tenant, tool not permitted for this agent.  
**Error response:** `403 Forbidden` with `reason: RESOURCE_OWNERSHIP_FAILED` or `TOOL_NOT_PERMITTED`.

---

### Step 5 — Action Canonicalization

**Actor:** API Gateway (calls Girish's canonicalization module)  
**Input:** Validated action envelope  
**Process:**
1. Call `canonicalize_action(validated_action)` → `canonical_bytes`.
2. Call `calculate_action_digest(validated_action)` → `action_digest` (hex-encoded SHA-256).
3. Store `action_digest` for use in OPA input, capability issuance, and approval binding.

**Rejection condition:** Canonicalization fails (malformed fields, unsupported encoding).  
**Note:** The canonicalization function is shared and deterministic. Both gateway and executor call the same function. No independent implementations.

---

### Step 6 — OPA Policy Evaluation

**Actor:** API Gateway → OPA  
**Input:** `{principal_id, tenant_id, tool, resource, action_digest, arguments, policy_version, environment}`  
**Process:**
1. Send the policy input document to OPA endpoint.
2. Evaluate the versioned Rego policy bundle.
3. Receive one of: `{result: "allow"}`, `{result: "deny", reason: <string>}`, `{result: "needs_approval", approval_type: <string>}`.
4. Default-deny: if no rule matches, the result is `deny`.

**Rejection condition:** `deny` result.  
**Error response:** `403 Forbidden` with `reason: POLICY_DENY`, OPA reason included.

**Policy-version handling:**  
- Each policy bundle has a semantic version.  
- The `policy_version` in the action envelope must match the active bundle's minimum acceptable version.  
- The active policy_version is embedded in the issued capability.  
- If the executor observes a capability with a policy_version below the current minimum, it rejects with `reason: POLICY_VERSION_STALE`.

---

### Step 7 — Hard-Deny Enforcement

**Actor:** API Gateway  
**Rule:** If OPA returns `deny`, no capability is issued. No approval can override a hard-deny.  
**Rejection condition:** OPA returns `deny`.  
**Error response:** `403 Forbidden` with `reason: HARD_DENY`.

---

### Step 8 — Human Approval Gate (conditional)

**Actor:** API Gateway + Human Approval Service  
**Trigger:** OPA returns `needs_approval`.  
**Process:**
1. Create a pending approval request in PostgreSQL: `{approval_request_id, tenant_id, principal_id, action_digest, required_approval_type, created_at, expires_at, status: PENDING}`.
2. Return `202 Accepted` with `{approval_request_id, action_digest, expires_at}`.
3. The approver authenticates and submits a decision to `POST /v1/approvals/{id}/decision`.
4. The decision endpoint verifies approver identity, records `{approval_id, action_digest, approver_identity, decision, created_at, expires_at, consumed: false}`.
5. The agent may re-submit the authorization request referencing `intent_id`, and the gateway will check for a valid unconsumed approval.

**Rejection condition:** No valid approval found, approval expired, approval action_digest does not match current action_digest, approval already consumed, decision is `reject`.  
**Error response:** `403 Forbidden` with `reason: APPROVAL_REQUIRED` (no approval) or `APPROVAL_REJECTED`.

---

### Step 9 — Capability Issuance

**Actor:** Capability Issuer (called by Gateway after Steps 1–8 pass)  
**Process:**
1. Generate a unique `jti` (UUID v4).
2. Construct the capability claims (see ACTION_CONTRACT.md for full field list).
3. Embed `action_digest` (must match the digest computed at Step 5).
4. Embed `approval_id` if an approval was consumed to unlock this capability.
5. Set `iat` = now, `exp` = now + configured TTL (default 300s).
6. Sign with Ed25519 using the current signing key; embed `kid` (key ID).
7. Return the signed capability token to the agent.

**Rejection condition:** Key not available (fail-closed); internal error.

---

### Step 10 — Execution Request Submission

**Actor:** AI Agent → Protected Executor  
**Input:** `{capability_token, action_envelope}`  
**Note:** Agent submits both the capability token AND the action envelope. The executor does not accept a capability alone; it must verify that the token matches the actual action being executed.

---

### Step 11 — Executor-Side Independent Verification

**Actor:** Protected Executor  
**This is the final enforcement boundary. All of the following must pass before any side effect.**

11a. **Signature verification:** Verify Ed25519 signature using registered public key resolved from `kid`. Reject unknown `kid`. Reject invalid signature.

11b. **Structural validation:** Verify `iss` (issuer), `aud` (audience = executor service identifier), `env` (environment matches current environment).

11c. **Expiry check:** Verify `exp > now - 5s` (clock skew). Reject expired capabilities.

11d. **Action digest binding:** Recompute `action_digest` from the submitted execution action envelope using the shared canonicalization module. Compare to `action_digest` embedded in the capability. Any mismatch → reject with `reason: DIGEST_MISMATCH`.

11e. **OPA re-evaluation:** Query OPA with current execution context (current policy_version, current timestamp, resource). A `deny` result → reject with `reason: POLICY_DENY_AT_EXECUTION`. A `needs_approval` with no approval → reject.

11f. **Revocation check:** Query Redis for `revoked:{principal_id}:{tenant_id}` key AND query PostgreSQL revocation table. If revoked → reject with `reason: AGENT_REVOKED`. If Redis is unavailable → fail-closed → reject with `reason: REVOCATION_CHECK_UNAVAILABLE`.

11g. **Approval verification (if required):** Look up `approval_id` in PostgreSQL. Verify `approval.action_digest == capability.action_digest`. Verify `approval.tenant_id == capability.tenant_id`. Verify `approval.consumed == false`. Verify `approval.expires_at > now`. Verify `approval.decision == approved`. Atomically set `consumed = true` in the same transaction.

11h. **Atomic capability claim:** `SET jti "claimed" NX EX <remaining_ttl>` in Redis. If key already exists → reject with `reason: CAPABILITY_ALREADY_CLAIMED`.

11i. **Durable execution record:** `INSERT INTO execution_records (jti, principal_id, tenant_id, tool, resource, action_digest, state='CLAIMED', ...)` with a UNIQUE constraint on `jti`. If INSERT fails due to duplicate → reject (handles crash-recovery replay).

---

### Step 12 — Protected Tool Invocation

**Actor:** Protected Executor  
**Process:**
1. Update execution state to RUNNING.
2. Construct tool invocation payload with `idempotency_key = jti`.
3. Call mock protected tool.
4. On success: update state to SUCCEEDED, record tool result.
5. On definitive failure: update state to FAILED_FINAL, record error.
6. On timeout / network error: update state to UNKNOWN, do NOT retry blindly. Enter reconciliation (see FAILURE_MODEL.md).

---

### Step 13 — Receipt and Audit

**Actor:** Protected Executor + Audit Pipeline (Girish's modules)  
**Process:**
1. Call `sign_execution_receipt(receipt_data, signing_key)` → signed receipt.
2. Persist receipt in PostgreSQL.
3. Call `append_audit_record(event)` → appends to hash-chained audit log.
4. Return execution result + receipt to agent.

---

## 3. Rejection Behavior Summary

| Step | Failure | HTTP Code | Reason Code |
|---|---|---|---|
| 1 | Invalid credential | 401 | INVALID_CREDENTIAL |
| 2 | Schema validation | 422 | SCHEMA_VALIDATION_FAILED |
| 3 | Identity mismatch | 403 | IDENTITY_MISMATCH |
| 4 | Resource ownership | 403 | RESOURCE_OWNERSHIP_FAILED |
| 5 | Canonicalization error | 500 | CANONICALIZATION_ERROR |
| 6 | Policy deny | 403 | POLICY_DENY |
| 7 | Hard deny | 403 | HARD_DENY |
| 8 | Approval required | 403 | APPROVAL_REQUIRED |
| 8 | Approval rejected | 403 | APPROVAL_REJECTED |
| 11a | Invalid signature | 403 | INVALID_CAPABILITY_SIGNATURE |
| 11b | Wrong issuer/audience | 403 | CAPABILITY_CONTEXT_MISMATCH |
| 11c | Expired | 403 | CAPABILITY_EXPIRED |
| 11d | Digest mismatch | 403 | DIGEST_MISMATCH |
| 11e | Policy deny at execution | 403 | POLICY_DENY_AT_EXECUTION |
| 11f | Agent revoked | 403 | AGENT_REVOKED |
| 11f | Revocation unavailable | 503 | REVOCATION_CHECK_UNAVAILABLE |
| 11g | Invalid approval | 403 | APPROVAL_INVALID |
| 11h | Already claimed | 409 | CAPABILITY_ALREADY_CLAIMED |
| 11i | Duplicate execution record | 409 | EXECUTION_RECORD_DUPLICATE |

---

## 4. Policy Version Change Handling

- Policy bundles are versioned semantically.
- The gateway always uses the current active policy bundle.
- The capability embeds `policy_version` at issuance time.
- The executor re-evaluates OPA at execution time.
- The executor rejects capabilities where `policy_version < minimum_acceptable_version` (configurable).
- Policy downgrade is rejected.

---

## 5. Key Rotation

- Each signing key has a `kid` (key ID).
- The public key registry (in PostgreSQL or config) maps `kid` → public key.
- Capability tokens embed `kid`.
- The executor resolves the public key by `kid` for verification.
- Old capabilities signed with the previous key remain valid until their `exp`, provided the old `kid` is still in the registry.
- The private key for rotation is added to the Capability Issuer configuration; the old private key is retained in the registry (public key only) until all outstanding capabilities from that key have expired.
- After the expiry window, the old `kid` can be removed from the registry.
- Unknown `kid` → reject.

---

*Last updated: 2026-10-13 | Owner: Pavan*
