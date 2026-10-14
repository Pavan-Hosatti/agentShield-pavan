# Attacker B — Interface Spec for Alok

**Owner: Pavan**  
**Route prefix Alok mounts:** `/attack/replay`, `/attack/expired`, `/attack/bypass`

---

## 1. Run My API Server

```bash
# From agentshield/ root
python -m attacker_b.server
# Runs on http://0.0.0.0:8003 — reachable from Laptop 2 via Wi-Fi
```

---

## 2. Endpoints Alok Connects To

| Method | Path | What it returns |
|--------|------|-----------------|
| GET | `/` | Health check |
| GET | `/scenarios` | All 8 scenario metadata for UI pickers |
| POST/GET | `/run/{id}` | Run scenario S1–S8 |
| POST/GET | `/attack/replay` | S1 (replay) default |
| POST/GET | `/attack/expired` | S2 (expired) default |
| POST/GET | `/attack/bypass` | S4 (bypass) default |
| GET | `/all` | Run all 8 + summary |

---

## 3. ScenarioResult — JSON shape

Every endpoint returns this exact shape:

```json
{
  "scenario_id": "S1",
  "scenario_name": "Capability Replay",
  "category": "REPLAY",
  "attack_succeeded": false,
  "result_code": "JTI_ALREADY_CLAIMED",
  "http_status": 409,
  "what_happened": "Attacker submitted same capability 5× — only #1 succeeded.",
  "why_blocked": "Redis atomic SET NX on jti...",
  "invariant_reference": "I4 — Single-use: jti consumed exactly once",
  "evidence": {
    "jti": "cap-a1b2c3d4",
    "attempts": 5,
    "executions_succeeded": 1,
    "executions_rejected": 4,
    "redis_mechanism": "SET NX EX 300"
  },
  "blocked_in": ["B", "C"],
  "allowed_in": ["A"],
  "run_at": "2026-10-14T10:30:00Z"
}
```

Key fields for Alok's UI:
- `attack_succeeded`: `false` = green (blocked), `true` = red (attack worked)
- `result_code`: show in bold
- `what_happened` + `why_blocked`: plain-English for judges
- `invariant_reference`: which invariant (I1–I11) this proves
- `blocked_in` / `allowed_in`: shows Config A/B/C comparison

---

## 4. Scenario List

| ID | Route | Category | Key Defense |
|----|-------|----------|-------------|
| S1 | /attack/replay | REPLAY | Redis SET NX — I4 |
| S2 | /attack/expired | REPLAY | TTL check — F5 |
| S3 | /attack/expired?scenario=S3 | BOUNDARY | Revocation at executor — I6 |
| S4 | /attack/bypass | BOUNDARY | Network isolation — I9 |
| S5 | /attack/bypass?scenario=S5 | BOUNDARY | Policy version — I8 |
| S6 | /attack/bypass?scenario=S6 | BOUNDARY | Cross-tenant OPA — I1 |
| S7 | /attack/bypass?scenario=S7 | DELEGATION | Scope bounds — I7 |
| S8 | /attack/bypass?scenario=S8 | AVAILABILITY | Fail-closed — I11 |

---

## 5. My Standalone Console (Laptop 2)

The file `attacker_b/console/index.html` is a self-contained console.
Open it directly in browser — no server needed for the UI itself.
It calls `localhost:8003` for data but has full local fallback if API is offline.

**For the live demo:**
- Laptop 2 opens `attacker_b/console/index.html`
- Change `API_BASE` at top of JS to `http://<LAPTOP1_IP>:8003`
- All 8 attack scenarios run over Wi-Fi against the real backend

---

## 6. Python import (if Alok wants to call directly)

```python
from core.scenarios.replay_scenarios import run_scenario, list_scenarios

# Run one scenario
result = run_scenario("S1")
print(result.attack_succeeded)   # False
print(result.result_code)        # JTI_ALREADY_CLAIMED
print(result.to_dict())          # JSON-serialisable

# List all for UI
scenarios = list_scenarios()
```

---

## 7. Demo Flow — Pavan's Part (3:00–4:00)

1. On Laptop 2, open `attacker_b/console/index.html`
2. Select **S1 — Capability Replay** → click LAUNCH ATTACK → show `5 attempts, 1 claimed`
3. Select **S3 — Revoked Agent** → `BLOCKED in C, ALLOWED in B` — key differentiator
4. Click **⚡ RUN ALL** → 8/8 blocked → score board
5. Switch to Config A in toolbar → rerun S1 → "This attack would succeed in Config A"
