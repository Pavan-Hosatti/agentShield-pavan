# AgentShield V2 — Handoff: Pavan → Girish

**From:** Pavan (Security Architecture Lead)  
**To:** Girish (Cryptographic Protocol Engineer)  
**Date:** 2026-10-13

---

## 1. Action Digest Semantics

The canonical action digest is:

```
SHA256(b"AGENTSHIELD-ACTION-V1\x00" + canonical_bytes)
```

Where `canonical_bytes` is the UTF-8 encoded, sorted-key, compact JSON of the validated `ActionEnvelope`.

**Authoritative test vector:**

Input (sorted, compact JSON):
```
{"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},"environment":"demo","intent_id":"intent-demo-001","policy_version":3,"principal_id":"agent-support-01","resource":"orders/ORDER-123","schema_version":1,"tenant_id":"tenant-demo","tool":"issue_refund"}
```

Expected digest: `7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28`

Your `calculate_action_digest()` must produce this exact output. Gururaj verifies it.

The schemas and base canonicalization are already implemented in:
- `backend/app/security/schemas.py` — `ActionEnvelope`, `CapabilityClaims`, etc.
- `backend/app/security/canonicalization.py` — `canonicalize_action()`, `calculate_action_digest()`

**Review these and confirm your implementation agrees. If you find a discrepancy, tell Pavan before changing anything.**

---

## 2. Capability Claims Contract

The signed capability must contain these claims. Encoding: JWS with Ed25519 (`EdDSA`, `crv: Ed25519`).

```python
{
    "iss": "agentshield-capability-issuer-v1",
    "aud": "agentshield-protected-executor-v1",
    "sub": principal_id,           # Authenticated agent
    "tenant_id": tenant_id,
    "tool": tool,
    "resource": resource,
    "action_digest": hex_digest,   # From calculate_action_digest()
    "jti": str(uuid.uuid4()),      # Unique capability ID
    "iat": int(time.time()),
    "exp": int(time.time()) + 300, # 300s default TTL
    "policy_version": policy_version,
    "environment": environment,
    "intent_id": intent_id,
    "approval_id": approval_id,    # None if no approval required
    "kid": key_id,                 # Key ID for rotation support
}
```

**Key handling:**
- Private key comes from `CAPABILITY_SIGNING_KEY_PRIVATE_B64` environment variable.
- Never hardcode keys. Never log keys. Never return private key in any API response.
- Support `kid` in the header. Executor resolves public key from `kid`.
- Reject unknown `kid` values.

---

## 3. Approval Binding Requirements

An approval binds:
- `approval_id` (UUID v4)
- `tenant_id` and `intent_id`
- `action_digest` (exact — from `calculate_action_digest()`)
- `approver_identity` (server-resolved, not client-supplied)
- `decision`: `approved` or `rejected`
- `consumed`: boolean (atomic consumption at execution)
- `created_at`, `expires_at`

**Invariant I5a:** An approval for digest D must not authorize execution of action with digest D'.  
**Invariant I5b:** A consumed approval must not be reusable.

Your `verify_approval(approval, expected_action_digest)` function must check:
1. `approval.action_digest == expected_action_digest` — exact match, no tolerance
2. `approval.consumed == False`
3. `approval.expires_at > now`
4. `approval.decision == "approved"`

Return a structured result, not a boolean. Never silently accept an invalid approval.

---

## 4. Audit Chain Requirements

Each audit record includes the SHA-256 hash of the previous record, creating a tamper-evident chain.

Hash input: all fields of the record EXCEPT `record_hash` itself, serialized as sorted-key compact JSON.

```
record_hash = SHA256(sorted_compact_json(record_without_record_hash))
prev_hash = record_hash of the previous record (or "0" * 64 for first record)
```

**Your `verify_audit_chain(records)` must detect:**
1. `HASH_MISMATCH` — record_hash doesn't match computed hash
2. `CHAIN_BREAK` — prev_hash doesn't match previous record's record_hash
3. `SEQ_GAP` — sequence numbers are not contiguous
4. Reordered records (caught by chain break at the first out-of-order record)

**Return a structured report with:**
```python
{
    "valid": bool,
    "issues": [{"type": str, "seq": int, "detail": str}],
    "first_broken_seq": int | None,
    "records_checked": int,
}
```

Reference implementation of the verification logic is in:
`tests/adversarial/test_audit_tampering.py` → `verify_audit_chain()` function.  
Your implementation must produce identical results for the same inputs.

---

## 5. Execution Receipt Contract

A receipt signs the execution outcome:

```python
{
    "receipt_id": str(uuid.uuid4()),
    "execution_id": execution_id,
    "tenant_id": tenant_id,
    "principal_id": principal_id,
    "action_digest": action_digest,
    "jti": jti,
    "approval_id": approval_id,        # None if not applicable
    "execution_result": "succeeded" | "failed" | "unknown",
    "timestamp": datetime.utcnow().isoformat(),
    "executor_id": "agentshield-executor-v1",
    "schema_version": 1,
    "kid": receipt_signing_key_id,
}
```

The receipt must be independently verifiable without trusting the executor that created it.

A modified receipt must fail signature verification.  
A receipt for action A must not verify as evidence for action B (because it binds `action_digest`).

---

## 6. Key Rotation

- Each key has a `kid` (string, e.g., `"key-v1"`, `"key-v2"`).
- The public key registry maps `kid` → Ed25519 public key.
- Capabilities and receipts embed `kid` in their header/claims.
- The executor resolves the verifying key from `kid`.
- Old keys stay in the registry until all tokens signed with them have expired.
- Unknown `kid` → reject immediately.

Document what happens to old audit records when the signing key rotates. Historical records signed with the old key must still verify (the old public key stays in the registry).

---

## 7. Interface Contract with Alok

Alok will call these functions from your module. Agree on final signatures before both of you integrate.

```python
# In backend/app/security/canonicalization.py (already implemented — check correctness)
canonicalize_action(action: ActionEnvelope) -> bytes
calculate_action_digest(action: ActionEnvelope) -> str
verify_digest_matches(action: ActionEnvelope, expected_digest: str) -> bool

# In backend/app/security/capability.py (Girish implements)
issue_capability(claims: dict, signing_key: Ed25519PrivateKey) -> str  # returns JWS token
verify_capability(
    token: str,
    expected_action: ActionEnvelope,
    authenticated_principal: str,
    verification_context: dict,    # includes: current_environment, clock_skew_seconds
) -> CapabilityClaims              # raises on any verification failure

# In backend/app/security/approval_binding.py (Girish implements)
verify_approval(approval: dict, expected_action_digest: str) -> dict
# Returns: {"valid": bool, "reason": str}

# In backend/app/security/execution_receipt.py (Girish implements)
sign_execution_receipt(receipt: dict, signing_key: Ed25519PrivateKey) -> dict
verify_execution_receipt(signed_receipt: dict) -> dict
# Returns: {"valid": bool, "claims": dict | None, "reason": str}

# In backend/app/security/audit_chain.py (Girish implements)
append_audit_record(event: dict) -> dict   # returns record with computed hashes
verify_audit_chain(records: list[dict]) -> dict   # returns verification report
```

---

## 8. What Pavan Will Review

- Signing key never appears in logs, responses, or test output
- `verify_capability` raises (not returns False) on critical failures
- `verify_digest_matches` uses constant-time comparison (already in canonicalization.py)
- Test vectors match the authoritative digest: `7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28`
- Audit chain verification correctly identifies the FIRST broken link
- No custom crypto primitives — only `cryptography` library

---

*Last updated: 2026-10-13 | From: Pavan*
