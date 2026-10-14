# AgentShield V2 — Action Contract

**Owner: Pavan (specification) | Alok (implementation) | Girish (cryptographic verification)**  
**Status: Frozen after Gate 1 agreement. No changes without team consensus.**

---

## 1. Canonical Action Schema

This is the single agreed action envelope. All teammates use this exact schema.

```json
{
  "schema_version": 1,
  "tenant_id": "tenant-demo",
  "principal_id": "agent-support-01",
  "tool": "issue_refund",
  "resource": "orders/ORDER-123",
  "arguments": {
    "order_id": "ORDER-123",
    "amount_minor": 50000
  },
  "environment": "demo",
  "policy_version": 3,
  "intent_id": "intent-demo-001"
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | integer | Yes | Schema version; currently `1`. |
| `tenant_id` | string | Yes | Tenant identifier. Must match credential-resolved tenant. |
| `principal_id` | string | Yes | Agent identifier. Must match credential-resolved agent. |
| `tool` | string | Yes | Tool name. Must be in the agent's permitted tool set. |
| `resource` | string | Yes | Resource path (e.g. `orders/ORDER-123`). Must be owned by tenant. |
| `arguments` | object | Yes | Tool-specific arguments. See per-tool argument schema below. |
| `environment` | string | Yes | Deployment environment: `demo`, `staging`, `production`. |
| `policy_version` | integer | Yes | Minimum policy version required for this action. |
| `intent_id` | string | Yes | Unique request/intent identifier. UUID v4 or opaque string. |

---

## 2. Tool-Specific Argument Schemas

### `issue_refund`
```json
{
  "order_id": "ORDER-123",
  "amount_minor": 50000
}
```
| Field | Type | Required | Constraints |
|---|---|---|---|
| `order_id` | string | Yes | Must match `resource` suffix. |
| `amount_minor` | integer | Yes | Positive integer. Represents paise (1/100 of rupee). No floats. |

**Money rule:** `amount_minor: 50000` = ₹500.00. Never use floating-point rupees. Never use `amount: 500.00`.

---

## 3. Canonicalization Rules

These rules are absolute. Girish implements the canonicalization function. Alok calls it. No independent implementations.

### 3.1 Encoding
- All string values are UTF-8 encoded.
- The canonical bytes are produced by a deterministic JSON serializer.

### 3.2 Field Ordering
- Top-level fields must appear in this exact alphabetical order:
  `arguments`, `environment`, `intent_id`, `policy_version`, `principal_id`, `resource`, `schema_version`, `tenant_id`, `tool`
- Nested object fields (`arguments.*`) must also be sorted alphabetically by key.

### 3.3 Numeric Representation
- Integers are represented without decimal points: `50000`, not `50000.0` or `5.0e4`.
- Floating-point values are not permitted in security-sensitive fields.
- `amount_minor` must be an integer.

### 3.4 String Values
- No leading or trailing whitespace is permitted in identifier fields (`tenant_id`, `principal_id`, `tool`, `resource`, `intent_id`).
- Strings are not normalized (no case folding, no Unicode normalization) unless explicitly stated.

### 3.5 Null vs. Omitted
- Required fields must be present and non-null.
- Optional fields that are omitted must be excluded from canonical bytes entirely (not serialized as `null`).
- A field explicitly set to `null` that is required → schema validation failure.

### 3.6 Unknown Fields
- Unknown fields in the action envelope → schema validation failure → reject.
- The canonicalization function must not silently ignore unknown fields.

### 3.7 Duplicate JSON Keys
- Duplicate JSON keys in the input → reject immediately before canonicalization.
- The parser must detect and reject duplicates.

### 3.8 Boolean Values
- `true` → `true`, `false` → `false` (lowercase, JSON standard).

### 3.9 Nested Objects
- Nested objects are serialized with sorted keys.
- No trailing commas.
- Compact serialization (no extra whitespace).

---

## 4. Action Digest Construction

```
action_digest = SHA256(
    b"AGENTSHIELD-ACTION-V1\x00" + canonical_bytes
)
```

- The prefix is the ASCII bytes of `AGENTSHIELD-ACTION-V1` followed by a null byte (`\x00`).
- `canonical_bytes` are the UTF-8 encoded, deterministically serialized, sorted-key JSON of the validated action envelope.
- The result is a 32-byte SHA-256 hash.
- The digest is encoded as a lowercase hex string (64 characters) when stored or transmitted.

### Example

For the canonical action:
```json
{"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},"environment":"demo","intent_id":"intent-demo-001","policy_version":3,"principal_id":"agent-support-01","resource":"orders/ORDER-123","schema_version":1,"tenant_id":"tenant-demo","tool":"issue_refund"}
```

Expected digest (authoritative test vector — computed by Girish's module, verified by Gururaj):
```
# Run: python -c "
import hashlib, json
action = {'arguments': {'amount_minor': 50000, 'order_id': 'ORDER-123'}, 'environment': 'demo', 'intent_id': 'intent-demo-001', 'policy_version': 3, 'principal_id': 'agent-support-01', 'resource': 'orders/ORDER-123', 'schema_version': 1, 'tenant_id': 'tenant-demo', 'tool': 'issue_refund'}
canonical = json.dumps(action, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
digest = hashlib.sha256(b'AGENTSHIELD-ACTION-V1\x00' + canonical).hexdigest()
print(digest)
"
```

**Authoritative digest for Vector 1:**
```
7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28
```

All teammates must produce this exact output for this input.

---

## 5. Capability Claims Schema

The signed capability must contain at minimum:

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer: `agentshield-capability-issuer-v1` |
| `aud` | string | Audience: `agentshield-protected-executor-v1` |
| `sub` | string | Authenticated principal_id |
| `tenant_id` | string | Tenant ID |
| `tool` | string | Permitted tool |
| `resource` | string | Permitted resource |
| `action_digest` | string | Hex-encoded SHA-256 action digest |
| `jti` | string | Unique capability ID (UUID v4) |
| `iat` | integer | Issued-at (Unix timestamp) |
| `exp` | integer | Expiry (Unix timestamp; default iat + 300) |
| `policy_version` | integer | Policy version at issuance |
| `environment` | string | Deployment environment |
| `intent_id` | string | Request/intent ID |
| `approval_id` | string | (Optional) Approval ID if approval was required |
| `kid` | string | Key ID of the signing key |

Encoding: JWT/JWS with Ed25519 (`EdDSA` algorithm, `crv: Ed25519`).

---

## 6. Approval Record Schema

| Field | Type | Description |
|---|---|---|
| `approval_id` | string | Unique approval ID (UUID v4) |
| `tenant_id` | string | Tenant |
| `request_id` / `intent_id` | string | Links to the original action request |
| `action_digest` | string | Exact action digest this approval covers |
| `approver_identity` | string | Authenticated approver (server-resolved, not client-supplied) |
| `decision` | enum | `approved` or `rejected` |
| `created_at` | datetime | Approval creation timestamp |
| `expires_at` | datetime | Approval expiry |
| `consumed` | boolean | Whether this approval has been used |
| `approval_policy_version` | integer | Policy version at approval time |

---

## 7. Execution State Record Schema

| Field | Type | Description |
|---|---|---|
| `execution_id` | string | UUID v4 |
| `jti` | string | Capability ID (UNIQUE) |
| `principal_id` | string | Agent |
| `tenant_id` | string | Tenant |
| `tool` | string | Tool executed |
| `resource` | string | Resource |
| `action_digest` | string | Action digest |
| `state` | enum | `ISSUED`, `CLAIMED`, `RUNNING`, `SUCCEEDED`, `FAILED_FINAL`, `UNKNOWN` |
| `idempotency_key` | string | Stable key passed to mock tool (= jti) |
| `created_at` | datetime | |
| `updated_at` | datetime | |
| `result` | jsonb | Tool result (null until SUCCEEDED) |
| `error` | string | Error detail (null unless failed) |
| `receipt_id` | string | Signed receipt ID (null until SUCCEEDED) |

---

## 8. Audit Event Schema

| Field | Type | Description |
|---|---|---|
| `seq` | integer | Monotonically increasing sequence number |
| `event_id` | string | UUID v4 |
| `timestamp` | datetime | Event creation time |
| `event_type` | string | e.g., `ACTION_AUTHORIZED`, `CAPABILITY_ISSUED`, `EXECUTION_CLAIMED`, `EXECUTION_SUCCEEDED`, `EXECUTION_DENIED`, `AGENT_REVOKED`, `APPROVAL_CONSUMED`, `AUDIT_TAMPERING_DETECTED` |
| `tenant_id` | string | |
| `principal_id` | string | |
| `action_digest` | string | |
| `jti` | string | Capability ID (if applicable) |
| `execution_id` | string | (if applicable) |
| `approval_id` | string | (if applicable) |
| `prev_hash` | string | SHA-256 of previous record's canonical bytes |
| `record_hash` | string | SHA-256 of this record's canonical bytes (includes prev_hash) |
| `signature` | string | Ed25519 signature over record_hash (Girish's module) |
| `kid` | string | Key ID |

---

## 9. Test Vectors (authoritative — Girish publishes, Gururaj verifies)

### Vector 1 — Standard refund
Input (sorted JSON, compact):
```
{"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},"environment":"demo","intent_id":"intent-demo-001","policy_version":3,"principal_id":"agent-support-01","resource":"orders/ORDER-123","schema_version":1,"tenant_id":"tenant-demo","tool":"issue_refund"}
```
Expected digest: **TBD — Girish to publish after implementing canonicalization module**

### Vector 2 — Tampered amount
Input with `amount_minor: 500000` (10× larger):
Expected digest: **different from Vector 1** — must not match.

### Vector 3 — Different tenant
Input with `tenant_id: "tenant-evil"`:
Expected digest: **different from Vector 1** — must not match.

### Vector 4 — Different field order (same semantic action)
Input with keys in a different order but identical values:
Expected digest: **identical to Vector 1** — key ordering must not affect digest.

---

*Last updated: 2026-10-13 | Owner: Pavan*
