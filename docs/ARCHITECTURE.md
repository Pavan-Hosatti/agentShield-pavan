# AgentShield V3 — Architecture

**Owner: Pavan (Architecture & Threat Modeling)**  
**Status: Authoritative — all teammates implement against this document.**

---

## 1. Central Invariant

> A protected side effect executes only when every plane independently confirms authorization for the exact action, under the current context, with all security state verified at execution time — not at authorization time.

Authentication is necessary but not sufficient.  
Gateway ALLOW is necessary but not sufficient.  
**The executor is the final and only enforcement boundary.**

---

## 2. Three-Plane Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PLANE 1 — CONTROL PLANE                                        │
│                                                                  │
│  Components: API Gateway, OPA Policy Engine, Human Approval,    │
│              Capability Issuer                                   │
│                                                                  │
│  Responsibility: Evaluate whether an action is policy-permitted  │
│  Authority:      Issue a capability IF policy allows             │
│  Trust level:    Medium — verified identity, evaluated policy    │
│                                                                  │
│  What it CANNOT do:  Execute side effects                        │
│  What it DOES NOT know: Whether the executor will accept it      │
└──────────────────────────────┬──────────────────────────────────┘
                               │  signed capability token (Ed25519)
┌──────────────────────────────▼──────────────────────────────────┐
│  PLANE 2 — EXECUTION PLANE                                       │
│                                                                  │
│  Components: Protected Executor, Mock Protected Tool             │
│                                                                  │
│  Responsibility: Re-verify EVERYTHING independently              │
│  Authority:      Execute side effects — sole authority           │
│  Trust level:    Highest — trusts no prior plane's decision      │
│                                                                  │
│  What it ALWAYS does:                                            │
│    11a — Verify Ed25519 capability signature                     │
│    11b — Check issuer, audience, environment                     │
│    11c — Check expiry (±5s clock skew)                           │
│    11d — RECOMPUTE action_digest from execution request          │
│    11e — Re-query OPA with current context                       │
│    11f — Re-check agent revocation (Redis + PostgreSQL)          │
│    11g — Re-verify approval + atomic consume                     │
│    11h — Atomic Redis SET NX on jti (single-use claim)           │
│    11i — INSERT execution record (PostgreSQL UNIQUE jti)         │
│    THEN — Invoke mock tool                                       │
│    THEN — Sign receipt, emit audit event                         │
│                                                                  │
│  What it NEVER does: Trust the gateway's prior ALLOW             │
└──────────────────────────────┬──────────────────────────────────┘
                               │  durable evidence
┌──────────────────────────────▼──────────────────────────────────┐
│  PLANE 3 — EVALUATION PLANE                                      │
│                                                                  │
│  Components: Audit Pipeline, Independent Verifier,               │
│              PostgreSQL, Redis, Receipt Store                    │
│                                                                  │
│  Responsibility: Record and independently verify outcomes        │
│  Authority:      No execution authority — evidence only          │
│  Trust level:    Independent — verifies Plane 1 and 2 output     │
│                                                                  │
│  What it does:                                                   │
│    — Hash-chained audit records (SHA-256 chain)                  │
│    — Independent verifier detects tamper, deletion, reorder      │
│    — Signed execution receipts (Ed25519)                         │
│    — Drift detection between planes                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Cross-Plane Boundary Rules

| Boundary | What crosses | What NEVER crosses |
|---|---|---|
| Untrusted → Plane 1 | Authenticated HTTP (JWT/API key + action body) | Identity from body, unsigned data |
| Plane 1 → Plane 2 | Signed capability token (Ed25519 JWS) | Plaintext auth, raw credentials |
| Plane 2 → Mock Tool | Authenticated tool call + idempotency key | Capability token, agent identity |
| Any Plane → Plane 3 | Audit events, receipts | Execution authority |

**Golden rule:** The Plane 1 ALLOW decision is a *precondition* for capability issuance. It is not a *sufficient condition* for execution.

---

## 4. Why Gateway ALLOW Is Not Enough

Between Plane 1 authorization and Plane 2 execution, the following attacks are possible:

| Attack | Window | Blocked By |
|---|---|---|
| Capability replay | Any time before TTL | Redis SET NX + PG UNIQUE (11h, 11i) |
| Action substitution | In transit | Digest recompute (11d) |
| Revocation race | Revoke after ALLOW, before execute | Revocation recheck (11f) |
| Capability expiry | Time passes | Expiry check (11c) |
| Policy drift | Policy updated between ALLOW and execute | OPA re-query (11e) |
| Approval race | Two concurrent requests, one approval | Atomic consume (11g) |
| Key compromise | Signing key exposed | Unknown kid reject (11a) |

**Config B (gateway-only) misses:** T2, T7, T19 — action substitution, revocation race, policy downgrade.  
**Config C (full zero-trust) blocks all of them.**

---

## 5. Security Baselines

Three configurations with identical interfaces but different enforcement depth:

| | Config A | Config B | Config C |
|---|---|---|---|
| Description | Minimal / naive | Gateway-only | Full zero-trust |
| Control Plane | Schema only | Full enforcement | Full enforcement |
| Execution Plane | None | Partial (no digest recompute, no revocation recheck) | Full (all 9 steps) |
| Evaluation Plane | None | Audit chain | Full (chain + receipts + verifier) |
| Protection score | 6% | 61% | 100% |
| Open attack surfaces | 17 | 7 | 0 |

**Config C is the only configuration that holds all 11 security invariants.**

---

## 6. Security Invariants (Checkable Properties)

| ID | Invariant | Enforcement |
|---|---|---|
| I1 | No unauthorized side effect executes | All preconditions must pass in Plane 2 |
| I2 | Action digest binds parameters exactly | SHA-256 with prefix, recomputed at executor |
| I3 | Hard-deny not overridable by approval | OPA hard_deny fires before any allow rule |
| I4 | Single-use: jti consumed exactly once | Redis SET NX + PostgreSQL UNIQUE |
| I5 | Approval bound to exact digest, single-use | Executor re-verifies + atomic consume |
| I6 | Revocation enforced at execution time | Executor re-queries revocation state |
| I7 | Child scope ⊆ parent scope | validate_delegation() — 7 rules R1–R7 |
| I8 | Policy version cannot be downgraded | Executor re-queries OPA, minimum version enforced |
| I9 | Executor is the final enforcement boundary | Independent verification — trusts no prior decision |
| I10 | Audit chain alteration is detectable | SHA-256 hash chain + independent verifier |
| I11 | Fail-closed: unavailable dependency → reject | All critical deps: 503 if unavailable, never allow |

All 11 invariants are checkable at unit level — see `core/invariants.py`.  
Pre-flight checker: `python -m backend.app.security.invariant_checker --verbose`

---

## 7. Fail-Closed State Machine

Every execution follows a defined state sequence. Invalid transitions → REJECTED (not silently ignored).

```
PENDING → EVALUATING → DENIED (terminal)
                     → NEEDS_APPROVAL → APPROVED → AUTHORIZED → CLAIMING → EXECUTING → SUCCEEDED
                     → AUTHORIZED ──────────────────────────────────────────────────↗
                                                                           → FAILED_FINAL
                                                                           → UNKNOWN → REJECTED
```

Any attempt to skip a state → REJECTED immediately.  
UNKNOWN requires reconciliation — blind retry is prohibited (prevents double-execution).  
7 of 8 defined failure modes are fail-closed (see `core/state_machine.py`).

---

## 8. Policy Validation Pipeline

The Rego policy is validated by a static analyzer before every deployment:

```
developer edits agentshield.rego
    → CI runs: python -m app.security.opa_validator policy/agentshield.rego
    → 14 checks across CRITICAL / HIGH / MEDIUM severity
    → Any CRITICAL or HIGH violation → CI fails → policy not deployed
```

**Checks include:** default allow = false, no wildcard allow, AGENT_REVOKED hard deny,  
CROSS_TENANT_ACCESS hard deny, action_digest in approval path, monetary hard maximum,  
DEFAULT_DENY fallback, allow rules gate on count(hard_deny) == 0.

Live mutation demo: `python -m core.policy_mutation`  
Shows 5 injected flaws caught before "deployment".

---

## 9. Delegation Rules

Child capabilities cannot expand parent scope. Seven rules enforced by `validate_delegation()`:

| Rule | Constraint |
|---|---|
| R1 | Child tools ⊆ parent tools |
| R2 | Child max_amount ≤ parent max_amount |
| R3 | Child TTL ≤ parent remaining TTL |
| R4 | Child tenant_id == parent tenant_id |
| R5 | Child environments ⊆ parent environments |
| R6 | Child policy_version ≥ parent policy_version |
| R7 | Delegation depth ≤ 3 |

---

## 10. Network Topology (Docker Compose)

```
agent_net:     gateway only        ← agent talks here
internal_net:  gateway, executor, opa, redis, postgres
executor_net:  executor, mock_tool ← agent cannot reach

Agent → gateway (agent_net)
Gateway → executor (internal_net)
Executor → mock_tool (executor_net)
Agent ✗→ executor (no route)
Gateway ✗→ mock_tool (no route)
```

---

## 11. Proof Export

A cryptographically sealed evidence bundle — verifiable offline with nothing but the public key:

```bash
python -m core.proof_export --out proof_bundle.json
python -m core.proof_export --verify proof_bundle.json
```

Bundle contains: 11 invariant proofs, 8 scenario results, 14 policy checks, baseline scores,  
SHA-256 content hash, HMAC-SHA256 integrity seal.  
Anyone can verify independently — no running services needed.

---

## 12. Component Trust Classification

| Component | Issues Decisions | Executes Effects | Holds Secrets | Trusts Prior Decisions |
|---|---|---|---|---|
| AI Agent | No | No | No | N/A |
| API Gateway | Partial | No | Agent creds | N/A |
| OPA | Yes (policy) | No | No | No |
| Human Approval | Yes (approval) | No | Approver identity | No |
| Capability Issuer | Yes (capability) | No | Signing key | Yes (from OPA) |
| **Protected Executor** | **Yes (final)** | **Yes** | **Tool creds** | **No — re-verifies everything** |
| Redis | No | No | No | N/A |
| PostgreSQL | No | No | No | N/A |
| Mock Tool | No | Yes (mock) | No | Yes (from executor) |
| Audit Verifier | No | No | Audit pub key | No |

---

*Last updated: 2026-10-14 | Owner: Pavan | Version: 3.0*
