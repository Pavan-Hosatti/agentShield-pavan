# AgentShield V2 — Implementation Review

**Owner: Pavan**  
**Status: Living document — updated as Alok and Girish ship code.**

---

## Purpose

This document records security findings from Pavan's review of the actual implementation. It is not a design document; it documents what was checked, what was found, and what was fixed.

---

## Review Checklist

### Gateway / API Layer
- [ ] Identity is resolved from verified credentials, not request body fields
- [ ] `principal_id` and `tenant_id` body fields are validated against credential-resolved values
- [ ] Schema validation uses strict mode (no extra fields)
- [ ] Duplicate JSON keys are rejected before canonicalization
- [ ] Resource ownership check queries database (not trusts agent input)
- [ ] Rate limiting is applied per agent, not per IP alone
- [ ] No private keys or capability tokens are returned in error responses
- [ ] Request IDs and trace IDs are present in all responses

### OPA Policy
- [ ] Default rule is `deny`
- [ ] No permissive wildcard rules exist without review
- [ ] Policy version is correctly embedded in capabilities
- [ ] Policy re-evaluation occurs at executor, not only at gateway

### Canonicalization and Digest
- [ ] Exactly one canonicalization function exists (no duplicates)
- [ ] Gateway and executor call the same function
- [ ] Test vectors produce identical output from both services
- [ ] Float amounts are rejected before canonicalization
- [ ] Unknown fields are rejected before canonicalization

### Capability Issuance
- [ ] `action_digest` is computed BEFORE signing (not after)
- [ ] `jti` is a UUID v4 (not predictable)
- [ ] `kid` is embedded and correct
- [ ] Expiry is set correctly (iat + TTL)
- [ ] Private key is never logged or returned

### Executor Verification
- [ ] All 9 verification steps (11a–11i) are implemented in order
- [ ] No short-circuit that skips verification on any code path
- [ ] OPA is called at executor, not only at gateway
- [ ] Revocation check queries Redis AND PostgreSQL
- [ ] Approval verification atomically marks consumed
- [ ] Redis SET NX TTL >= capability remaining expiry
- [ ] PostgreSQL UNIQUE on jti is enforced

### Approval Service
- [ ] Approver identity is from server-side auth, not body field
- [ ] Approval binds exact action_digest
- [ ] Consumed flag is set atomically with execution record INSERT
- [ ] Expired approvals are rejected

### Failure Handling
- [ ] Redis unavailable → fail-closed (no execution)
- [ ] OPA unavailable → fail-closed (no authorization)
- [ ] PostgreSQL unavailable → fail-closed (no execution)
- [ ] UNKNOWN state is recorded (not silently retried)
- [ ] Reconciliation protocol exists

### Audit and Receipts
- [ ] Every execution produces an audit event
- [ ] Hash chain is constructed correctly (prev_hash present)
- [ ] Receipt is signed (not self-attesting)
- [ ] Verifier is independent (does not trust the creator)

### Frontend / Dashboard
- [ ] No hardcoded metrics
- [ ] Calls real backend APIs
- [ ] Does not fabricate approval state or revocation state
- [ ] Unimplemented features are labeled

---

## Findings Log

| Finding ID | Severity | Component | Description | Reproduction | Impact | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|
| - | - | - | No findings yet — review pending implementation | - | - | - | PENDING |

### Severity Levels
- **CRITICAL**: Can cause unauthorized protected side effect
- **HIGH**: Can cause bypass of a security invariant
- **MEDIUM**: Can leak sensitive data or enable privilege information
- **LOW**: Defense-in-depth improvement

---

## Review History

| Date | Reviewer | Scope | Findings |
|---|---|---|---|
| 2026-10-13 | Pavan | Document structure, contracts | None yet — implementation not started |

---

*Last updated: 2026-10-13 | Owner: Pavan*
