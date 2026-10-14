# AgentShield V2 — Architecture Decision Records

**Owner: Pavan**  
**Status: Each ADR is final unless superseded by a later ADR.**

---

## ADR-001: Executor as Final Enforcement Boundary

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
The gateway performs authorization and issues capabilities, but a compromised gateway could bypass security by issuing capabilities for unauthorized actions, or a replayed capability could be reused without the gateway's involvement.

**Decision:**  
The protected executor is the final enforcement boundary. It independently re-verifies: signature, digest binding, expiry, revocation, approval, and replay claim — before any side effect. The gateway's ALLOW is a necessary condition for capability issuance, not sufficient for execution.

**Consequences:**  
- Adds latency (2 OPA calls, 1 Redis call, 1 PG write per execution).
- Makes the executor stateful (needs Redis + PG access).
- Requires the executor and gateway to share the canonicalization function.
- Makes the system robust against a compromised gateway.

---

## ADR-002: Ed25519 for Capability and Receipt Signing

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
Need a signing algorithm for capabilities and receipts that is fast, small, and well-supported by vetted Python libraries.

**Decision:**  
Use Ed25519 via the `cryptography` Python library (pyca/cryptography). No self-implemented crypto. Use JWS/JWT encoding with algorithm `EdDSA` and `crv: Ed25519`.

**Consequences:**  
- Keys are 32 bytes; signatures are 64 bytes.
- Fast verification.
- Requires the `cryptography` library.
- JWT encoding adds a small overhead but provides interoperability.

**Rejected alternatives:**  
- RSA: larger keys, slower.
- HMAC: shared secret, cannot verify without trusting the verifier.
- ECDSA (P-256): more common but Ed25519 is preferred for modern systems.

---

## ADR-003: Redis SET NX for Atomic Capability Claiming

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
Replay protection requires that a capability can be claimed at most once, even under high concurrency.

**Decision:**  
Use `SET jti "claimed" NX EX <ttl>` in Redis. This is an atomic operation. Pair it with a PostgreSQL UNIQUE constraint on `jti` in the execution_records table for durability.

**Consequences:**  
- Redis outage → fail-closed (no claims possible).
- PG UNIQUE is the durable backup; Redis is the fast path.
- TTL must be ≥ capability expiry to prevent premature key eviction.

---

## ADR-004: OPA Default-Deny Policy Semantics

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
Need a policy evaluation engine that defaults to denying access if no rule explicitly grants it.

**Decision:**  
Use OPA with Rego. Policy bundles are versioned. The default decision is `deny`. An action requires an explicit `allow` rule or a `needs_approval` rule.

**Consequences:**  
- OPA outage → fail-closed (no authorizations possible).
- Policy version is embedded in capabilities and re-checked at execution.
- Policy bundles can be updated without code changes.

---

## ADR-005: Paise (Integer Minor Units) for Monetary Amounts

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
Floating-point arithmetic is unreliable for monetary comparisons (0.1 + 0.2 ≠ 0.3). An amount comparison that uses floats could allow a policy bypass.

**Decision:**  
All monetary amounts are represented as integer paise (1/100 of a rupee). `amount_minor: 50000` means ₹500.00. No floats permitted in action envelopes.

**Consequences:**  
- Policy rules use integer comparisons (safe).
- Schema validation rejects float amounts.
- Canonical bytes contain `50000`, not `500.00`.

---

## ADR-006: Single Shared Canonicalization Function

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
If the gateway and executor compute different canonical representations of the same action, the digest comparison at execution will produce false mismatches or, worse, fail to detect real mutations.

**Decision:**  
There is exactly one canonicalization function in the codebase, owned by Girish and imported by Alok. No independent implementations. The function uses sorted-key JSON with compact separators and UTF-8 encoding.

**Consequences:**  
- All services must share the `backend/app/security/canonicalization.py` module.
- Changes to canonicalization require team consensus and test vector updates.

---

## ADR-007: Docker Network Segmentation for Tool Isolation

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
The agent must not be able to call the mock protected tool directly, bypassing the executor.

**Decision:**  
Three Docker networks:
- `agent_net`: gateway only (externally accessible).
- `internal_net`: gateway, executor, OPA, Redis, PostgreSQL.
- `executor_net`: executor, mock_tool.

The mock tool is on `executor_net` only. The agent can only reach `agent_net`. The gateway cannot reach `executor_net`.

**Consequences:**  
- Network topology is a security control, not just an organizational choice.
- Must be validated as part of A1 testing.
- Any change to docker-compose.yml networks requires Pavan review.

---

## ADR-008: Approval Is Action-Digest-Bound, Not Request-Bound

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
An approval tied to a request ID alone could be reused if the agent changes the action parameters while keeping the same request ID.

**Decision:**  
The approval record stores the exact `action_digest`. The executor verifies `approval.action_digest == capability.action_digest`. A changed parameter changes the digest, invalidating the approval.

**Consequences:**  
- Any parameter change requires a new approval.
- More secure but requires re-approval if parameters need to be corrected.

---

## ADR-009: Fail-Closed on All Critical Dependencies

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
A fail-open system would allow attacks during dependency outages (A9 scenario).

**Decision:**  
The executor fails closed (returns 503) if any of these are unavailable: Redis (replay check), OPA (policy check), PostgreSQL (execution record, revocation, approval). No protected side effect occurs during dependency outage.

**Consequences:**  
- Reduced availability during outages.
- Increased security (no bypass through chaos engineering).
- System must be designed for availability, not designed to bypass security when availability fails.

---

## ADR-010: Hash-Chain Audit Log with Independent Verifier

**Date:** 2026-10-13  
**Status:** Accepted

**Context:**  
Need tamper-evident audit evidence without full blockchain infrastructure.

**Decision:**  
Each audit record includes the SHA-256 hash of the previous record. An independent verifier (Girish's module) checks chain integrity. Optional: signed records for additional tamper evidence.

**Limitations (documented):**  
- An attacker who controls both the signing key and all audit storage can rewrite the chain.
- External checkpointing (optional feature) would mitigate this.
- Chain length may affect verification performance.

---

*Last updated: 2026-10-13 | Owner: Pavan*
