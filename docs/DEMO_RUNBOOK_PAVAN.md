# Pavan — Live Demo Runbook
**Role: Attacker B + Architecture Explainer**  
**Time slot: 3:00–4:00 (your 60 seconds on stage)**  
**Laptop: 2 (attack side)**

---

## Before judges arrive — setup (2 min)

```powershell
# Terminal 1 — start Attacker B API (Laptop 1 does this, or you)
cd "d:\reva cyber hack-pavan\agentshield"
python -m attacker_b.server
# Confirm: "Attacker B API starting on http://0.0.0.0:8003"

# Browser tab 1 — Attacker B console
# Open: d:\reva cyber hack-pavan\agentshield\attacker_b\console\index.html
# If API on Laptop 1: change API_BASE in the JS to http://<LAPTOP1_IP>:8003

# Browser tab 2 — Security console (frontend)
# Open: http://localhost:3000
# Pre-navigate to [ THREAT MAP ] tab
```

---

## Your demo sequence (60 seconds, tight)

### 0:00 — Open with the claim
> "I'm Pavan — I designed the security architecture. My claim: every attack attempt produces a cryptographic rejection, and every security property is provable from a terminal without running any services."

---

### 0:08 — Terminal: invariants (15 sec)

```powershell
cd "d:\reva cyber hack-pavan\agentshield\backend"
python -m app.security.invariant_checker --verbose
```

**Say:** "11 invariants. All holding. These are checkable properties — not documentation."

---

### 0:23 — Terminal: mutation demo (15 sec)

```powershell
cd "d:\reva cyber hack-pavan\agentshield"
python -m core.policy_mutation
```

**Say:** "5 security bugs injected into the real Rego policy. Validator catches every one. This is the CI gate — these never deploy."

---

### 0:38 — Attacker B console: replay attack (10 sec)

On Laptop 2, open `attacker_b/console/index.html`:
1. Select **S1 — Capability Replay** → click LAUNCH ATTACK
2. Point at the evidence: `5 attempts, 1 claimed, 4 rejected`

**Say:** "Capability submitted 5 times. Redis SET NX — only first one claims. Invariant I4."

---

### 0:48 — Attacker B console: the Config B gap (10 sec)

1. Select **S3 — Revoked Agent**  
2. Point at `BLOCKED in: [C] | ALLOWED in: [A, B]`

**Say:** "This is the key differentiator. Config B — gateway-only — would have allowed this attack. Config C catches it because the executor re-checks revocation independently. That's the 3-plane architecture."

---

### 0:58 — Proof bundle (if time allows, 5 sec)

```powershell
python -m core.proof_export --verify proof_bundle.json
```

**Say:** "Offline verifiable. Judges can run this themselves."

---

## If judges ask questions — answers

**"Why not just trust the gateway?"**
> "Between gateway authorization and execution, 7 attacks are possible: capability replay, action substitution, revocation race, expiry, policy drift, approval race, key compromise. Config B misses 3 of them. The executor re-verifies everything independently — that's Invariant I9."

**"How do you know the policy is correct?"**
> "Two ways. Static analyzer checks 14 properties — CRITICAL violations block deployment. And every allow rule must assert `count(hard_deny) == 0` first — that's V11, enforced at CI time."

**"What's Config A for?"**
> "It's a deliberately weak baseline — no digest check, no replay prevention, no OPA. We use it to show exactly which attacks succeed without each layer of defense. The comparison table shows Config A: 6%, Config B: 61%, Config C: 100%."

**"Can we verify this ourselves?"**
> Hand them the `proof_bundle.json`. Say: "Run `python -m core.proof_export --verify proof_bundle.json` on any machine with Python. No services needed."

---

## Quick terminal reference

```powershell
# All tests
python -m pytest tests/unit/ tests/v3/ -q
# → 364 passed

# Invariant pre-flight
cd backend && python -m app.security.invariant_checker --verbose
# → 10/10 ✅

# Policy validator
python -m app.security.opa_validator ../policy/agentshield.rego
# → 14/14 PASS

# Mutation demo (5 bugs caught)
python -m core.policy_mutation
# → 5/5 mutations detected ✓

# Canonical digest test vectors
cd backend && python -m app.security.canonicalization
# → Two digests, differ = True

# All 8 attack scenarios
python -m core.scenarios.replay_scenarios
# → 8/8 ✅ BLOCKED

# Generate proof bundle
python -m core.proof_export --out proof_bundle.json
# → verified: true

# Baseline comparison
python -m core.baselines
# → A=6%, B=61%, C=100%

# State machine demo
python -m core.state_machine
# → happy path + skip_claim attack → REJECTED
```

---

## Files to know

| File | What it is |
|---|---|
| `core/invariants.py` | 11 checkable security properties |
| `core/baselines.py` | Config A/B/C enforcement flags |
| `core/state_machine.py` | Fail-closed execution state machine |
| `core/delegation.py` | Delegation scope rules R1–R7 |
| `core/scenarios/replay_scenarios.py` | 8 live attack scenarios |
| `core/policy_mutation.py` | 5 policy flaws — all caught |
| `core/proof_export.py` | Generates verifiable proof bundle |
| `policy/agentshield.rego` | The actual OPA policy |
| `backend/app/security/opa_validator.py` | Static policy analyzer (14 checks) |
| `attacker_b/console/index.html` | Laptop 2 attack console |
| `proof_bundle.json` | Signed evidence — give to judges |
| `docs/ARCHITECTURE.md` | V3 3-plane architecture spec |

---

## Emergency fallback (if API/network down)

The attacker console works **fully offline** — built-in simulation fallback.  
All terminal commands work with no Docker, no OPA, no services.  
The proof bundle verifies with no network.

**Nothing in your part requires live Docker.**
