# AgentShield V2 — Threat Model

**Owner: Pavan**  
**Status: Authoritative — implement controls against every threat listed here.**

---

## 1. Assets

| Asset | Description | Primary Protection |
|---|---|---|
| Protected tool credentials | Credentials that allow mock tool invocation | Executor-only possession; never in agent or gateway |
| Tenant data | Per-tenant business records, mock order state | Tenant isolation in every query; PostgreSQL row-level |
| Agent identities | Registered public keys, enrollment records | Server-side only; never trusted from request body |
| Signing keys | Ed25519 private keys for capabilities and receipts | Env secrets; never logged, never in browser, never in responses |
| Capability tokens | Signed short-lived JWTs/JWS tokens | Short expiry; single-use via Redis SET NX + PG UNIQUE |
| Human approval records | Authenticated approver decisions | Stored in PG; single-use; bound to exact action_digest |
| Policy bundles | OPA/Rego versioned policy | Versioned; policy_version embedded in capability |
| Revocation state | Per-agent revocation records | Redis + PostgreSQL; fail-closed if unavailable |
| Execution state | CLAIMED/RUNNING/SUCCEEDED/UNKNOWN records | PostgreSQL UNIQUE on jti; atomic transitions |
| Audit evidence | Hash-chained signed audit log | Append-only PG; chain verified independently |
| Administrative controls | Revocation endpoints, reset, agent management | Authenticated; rate-limited |

---

## 2. Attacker Capabilities and Threat Scenarios

### T1 — Prompt injection / model manipulation
**Capability:** Adversarial input causes the AI agent to propose a harmful action.  
**Attack:** Agent proposes `issue_refund` with `amount_minor: 5000000` instead of `50000`.  
**System control:** The action schema validates the envelope. OPA evaluates the exact parameters. A changed amount changes the action_digest, invalidating any prior capability or approval.  
**Residual:** AgentShield does not prevent the model from proposing the harmful action. It prevents the *protected side effect* from executing without valid authorization for the *exact* action.  
**Classification:** Directly mitigated (side effect). Out of scope (model reasoning).

### T2 — Action substitution after authorization
**Capability:** Agent or MITM changes parameters after the gateway issues a capability.  
**Attack:** Capability issued for `amount_minor: 50000`; execution request contains `amount_minor: 500000`.  
**System control:** Executor recomputes the action_digest from the execution-time request. Digest mismatch → reject.  
**Classification:** Directly mitigated.

### T3 — Capability replay
**Capability:** Attacker captures a valid capability and resubmits it concurrently or later.  
**Attack:** 100 concurrent POST /v1/actions/execute with same capability token.  
**System control:** Redis SET NX on jti (atomic); PostgreSQL UNIQUE constraint on jti. At most one claim succeeds.  
**Classification:** Directly mitigated.

### T4 — Identity spoofing (JSON body injection)
**Capability:** Agent submits request body with forged `principal_id`, `tenant_id`, or `role`.  
**Attack:** `{"principal_id": "admin", "tenant_id": "tenant-privileged", ...}` in request body.  
**System control:** Gateway resolves identity exclusively from verified credentials (JWT/API-key → server-side agent record). Body fields are validated against the resolved identity. A mismatch → reject.  
**Classification:** Directly mitigated.

### T5 — Cross-tenant resource access
**Capability:** Agent from tenant-A requests action on a resource owned by tenant-B.  
**Attack:** `{"tenant_id": "tenant-A", "resource": "orders/ORDER-TENANTB-999"}`.  
**System control:** Gateway checks resource ownership: tenant_id must own the resource. Capability binds tenant_id. Executor re-checks tenant_id against the execution request.  
**Classification:** Directly mitigated.

### T6 — Approval replay / approval substitution
**Capability:** An approval issued for action X is reused for action Y.  
**Attack:** Approval for `amount_minor: 50000` presented to execute `amount_minor: 500000`.  
**System control:** Approval record binds exact action_digest. Executor verifies `approval.action_digest == execution_action_digest`. Changed amount → different digest → approval rejected.  
**Classification:** Directly mitigated.

### T7 — Revocation race
**Capability:** Agent is revoked after gateway authorization but before executor invocation.  
**Attack:** Revoke agent, then attempt execution with a valid capability that was issued before revocation.  
**System control:** Executor re-queries revocation state at execution time. Revoked agent → reject regardless of capability validity.  
**Classification:** Directly mitigated (when revocation propagates before execution check).  
**Residual:** If revocation write and executor revocation check are simultaneous, a narrow race window exists. Documented in FAILURE_MODEL.md.

### T8 — Capability forging
**Capability:** Attacker constructs a capability without the signing key.  
**Attack:** Craft a capability JWT/JWS with a self-signed or no signature.  
**System control:** Executor verifies Ed25519 signature using registered public key(s). Invalid signature → reject. Unknown key_id → reject.  
**Classification:** Directly mitigated (assuming signing key is not compromised).

### T9 — Expired capability
**Capability:** Attacker reuses a capability after its expiry window.  
**Attack:** Submit execution request with a capability whose `exp` has passed.  
**System control:** Executor checks `exp` with ≤5s clock-skew allowance. Expired → reject.  
**Classification:** Directly mitigated.

### T10 — Malformed action schema
**Capability:** Submit an action with invalid fields to trigger unexpected behavior.  
**Attack:** Floating-point amount, duplicate JSON keys, unknown fields, null where required.  
**System control:** Pydantic strict validation at gateway. Canonicalization rejects ambiguous representations. Unknown fields → reject.  
**Classification:** Directly mitigated.

### T11 — Dependency outage abuse
**Capability:** Disable Redis or OPA to force fail-open behavior.  
**Attack:** Kill Redis; submit replay attempt expecting the check to be skipped.  
**System control:** Executor is fail-closed: if Redis, OPA, or revocation state is unavailable → reject. No protected side effect occurs.  
**Classification:** Directly mitigated.

### T12 — Concurrent replay under load
**Capability:** Under high concurrency, race conditions in replay check allow multiple claims.  
**Attack:** 1000 concurrent replays.  
**System control:** Redis SET NX is atomic. PostgreSQL UNIQUE constraint is atomic. Only one claim can succeed.  
**Classification:** Directly mitigated.

### T13 — Audit tampering
**Capability:** Attacker modifies, deletes, or reorders audit records.  
**Attack:** Edit a PostgreSQL audit record to remove evidence of a rejected action.  
**System control:** Hash-chain construction: each record includes hash of previous record. Verifier detects broken chain. Signed records (Girish's module) detect modification.  
**Residual:** An attacker with full database access and the signing key can rewrite the chain. This is documented. External checkpointing or blockchain anchoring would mitigate this but is optional.  
**Classification:** Mitigated under documented trust assumptions (attacker does not control signing key and audit storage simultaneously).

### T14 — Direct protected-tool access
**Capability:** Agent or gateway bypasses the executor and calls the mock tool directly.  
**Attack:** Agent sends HTTP request directly to mock_tool service.  
**System control:** Container networking (executor_net). Mock tool is not on agent_net or internal_net. No route exists.  
**Classification:** Mitigated by infrastructure controls.

### T15 — Agent-to-agent unauthorized call (A7)
**Capability:** Agent A calls Agent B without authorization.  
**Attack:** agent-support-01 calls agent-payment-processor directly.  
**System control:** All agent-to-agent calls must be authorized through the gateway and policy engine. Unregistered destinations → reject.  
**Status:** Planned. Label NOT_IMPLEMENTED until Alok ships this.

### T16 — Delegation escalation (A8)
**Capability:** A child agent receives broader scope than its parent capability.  
**Attack:** Parent can do `issue_refund` up to 50000; child requests 500000.  
**System control:** Capability scope is bounded by parent scope. Child scope is checked against parent at issuance.  
**Status:** Planned. Label NOT_IMPLEMENTED until implemented.

### T17 — Crash around tool invocation
**Capability:** Executor crashes after mock tool executes but before receipt/audit is persisted.  
**Attack:** Natural failure; adversary may retry.  
**System control:** Execution state transitions to UNKNOWN. Recovery reconciliation checks mock tool's idempotency key response before retrying. Blind retry is prohibited.  
**Classification:** Partially mitigated (reconciliation logic required).

### T18 — Leaked signing key
**Capability:** Signing private key is exposed in logs, responses, or environment dumps.  
**Attack:** Extract key from logs; forge capabilities indefinitely.  
**System control:** Keys stored in environment variables; never logged; never returned in API responses; never embedded in frontend code.  
**Classification:** Operational control. Must be verified in implementation review.

### T19 — Policy version downgrade
**Capability:** Force the executor to evaluate against an older, more permissive policy version.  
**Attack:** Submit a capability with policy_version=1 while the current enforced version is 3.  
**System control:** Executor re-queries OPA with the current policy context. If the capability's policy_version is below the minimum acceptable version defined in OPA, reject.  
**Classification:** Directly mitigated.

---

## 3. Attacker Model

### In scope
- External adversary controlling the AI agent process.
- Adversary who can observe and replay HTTP traffic between agent and gateway.
- Adversary who can modify request bodies.
- Adversary who can control the timing of revocation relative to execution.
- Adversary who can disable dependent services (chaos testing).
- Adversary with read access to the audit log (tamper and verify).
- Compromised application component operating within its *actual* permissions.

### Out of scope
- Adversary with direct access to the executor's signing private key.
- Adversary with simultaneous write access to both the audit log and the signing key.
- Adversary with root access to the database host.
- Side-channel attacks on cryptographic operations.
- Production infrastructure attacks (this system runs in a demo environment).

---

## 4. Security Assumptions

1. The Ed25519 signing key is held only by the Capability Issuer and Executor. It is not accessible to agents, the gateway, or the browser.
2. The PostgreSQL and Redis instances are accessible only within the internal_net Docker network.
3. The mock tool is accessible only within the executor_net Docker network.
4. The clock difference between services is less than 5 seconds.
5. The OPA policy bundle is served from a trusted, version-controlled source.
6. Approver identity is established by the agreed authentication mechanism, not a client-supplied name in JSON.
7. The hash chain's integrity guarantee holds only when the attacker does not control both the signing key and all audit storage.

---

## 5. Controls Outside AgentShield Scope

| Threat | Required External Control |
|---|---|
| Compromised database host | Infrastructure hardening, access control |
| Signing key theft from environment | Secrets management (Vault, KMS in production) |
| Model prompt injection (prevention) | Model-level guardrails, input sanitization |
| Network-level MITM | TLS everywhere (mTLS in production) |
| Production credential exposure | Production secrets management |
| Kubernetes multi-tenant isolation | Kubernetes RBAC and network policies |

---

*Last updated: 2026-10-13 | Owner: Pavan*
