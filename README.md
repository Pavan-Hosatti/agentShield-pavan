# AgentShield V2

A zero-trust action-security gateway for AI agents.

## Team

| Owner | Responsibility |
|---|---|
| **Pavan** | System architecture, security protocol, threat model, trust boundaries, invariants, design review |
| **Alok** | Complete application implementation: backend, executor, APIs, database, frontend, integration |
| **Girish** | Cryptographic protocol, action-bound capabilities, approval integrity, signed receipts, audit chain |
| **Gururaj** | Independent red-team testing, baselines, failure testing, benchmarks, reproducible evidence |

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Start all services
docker-compose up --build

# 3. Run tests
cd backend && pytest tests/ -v

# 4. Demo reset
curl -X POST http://localhost:8000/v1/demo/reset
```

## Repository Structure

```
agentshield/
  backend/
    app/
      api/           — API route handlers (Alok)
      security/      — Schemas, canonicalization, crypto (Girish + Pavan spec)
      policy/        — OPA integration (Alok)
      services/      — Business logic (Alok)
      db/            — Database models and migrations (Alok)
      audit/         — Audit pipeline integration (Alok + Girish)
  frontend/          — React/TypeScript dashboard (Alok)
  policy/            — OPA/Rego policy bundles (Pavan)
  tests/
    unit/            — Unit tests
    integration/     — Integration tests
    adversarial/     — Attack scenarios (Gururaj)
    load/            — Load tests (Gururaj)
  demo/              — Demo scripts and fixtures
  docs/              — Architecture and design documents (Pavan)
  docker-compose.yml
  .env.example
```

## Key Documents

| Document | Owner | Purpose |
|---|---|---|
| docs/ARCHITECTURE.md | Pavan | Component responsibilities and trust boundaries |
| docs/THREAT_MODEL.md | Pavan | Assets, adversaries, threats |
| docs/SECURITY_PROTOCOL.md | Pavan | Step-by-step authorization protocol |
| docs/ACTION_CONTRACT.md | Pavan | Canonical action schema and hashing rules |
| docs/FAILURE_MODEL.md | Pavan | Dependency outages, crashes, recovery |
| docs/SECURITY_INVARIANTS.md | Pavan | Properties that must always hold |
| docs/ATTACK_MATRIX.md | Pavan/Gururaj | Attack scenarios and expected outcomes |
| docs/ADR.md | Pavan | Architecture decision records |
| docs/DESIGN_TEST_MATRIX.md | Pavan/Gururaj | Invariant → test mapping |
| docs/IMPLEMENTATION_REVIEW.md | Pavan | Security review findings |

## Implementation Gates

- **Gate 1** — Shared specification agreed ✅ (Pavan complete)
- **Gate 2** — Secure vertical slice (Alok + Girish)
- **Gate 3** — Core security tests (Gururaj)
- **Gate 4** — Audit and recovery (Girish + Alok)
- **Gate 5** — Dashboard and attack lab (Alok + Gururaj)
- **Gate 6** — Comparative evaluation (Gururaj)
- **Gate 7** — Final release (all four)

## Core Security Invariant

> A protected side effect executes only when the protected executor independently verifies authorization for the exact action, validates current authorization context, checks required approval and revocation state, and atomically claims the capability for execution.

## Important Limitations

- This system uses synthetic identities and mock protected tools. No real money movement.
- Exactly-once external execution is NOT guaranteed unless the mock tool supports idempotent reconciliation.
- A narrow revocation race window exists (documented in FAILURE_MODEL.md).
- Audit chain integrity holds only when the attacker does not control both the signing key and all audit storage.
- Agent-to-agent authorization (A7/A8) is planned but NOT_IMPLEMENTED.
