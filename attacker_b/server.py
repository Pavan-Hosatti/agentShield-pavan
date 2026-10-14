"""
AgentShield V3 — Attacker B API Server
Owner: Pavan

Alok connects to this. Runs on port 8003.
All existing core logic untouched — this is a thin web layer on top.

Routes:
  GET  /                       → health check
  GET  /scenarios              → list all 8 scenarios
  POST /attack/replay          → run S1 (replay) or S3 (revoked)
  POST /attack/expired         → run S2 (expired) or S3 (revoked)
  POST /attack/bypass          → run S4/S5/S6/S7/S8
  POST /run/{scenario_id}      → run any scenario by ID (S1–S8)
  GET  /run/{scenario_id}      → same (for easy browser testing)

Run with: python -m attacker_b.server
"""
from __future__ import annotations

import sys
import os

# Make core importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.scenarios.replay_scenarios import run_scenario, list_scenarios, run_all_scenarios

app = FastAPI(
    title="AgentShield V3 — Attacker B Console API",
    description="Pavan's replay/boundary attack scenarios. Interface for Alok's frontend.",
    version="3.0.0",
)

# Allow Alok's frontend on any port/host (demo Wi-Fi setup)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health():
    return {
        "service": "attacker-b",
        "owner": "Pavan",
        "status": "online",
        "scenarios": 8,
        "categories": ["REPLAY", "BOUNDARY", "DELEGATION", "AVAILABILITY"],
    }


@app.get("/scenarios")
def get_scenarios():
    """List all available attack scenarios for the UI picker."""
    return {"scenarios": list_scenarios()}


@app.get("/run/{scenario_id}")
@app.post("/run/{scenario_id}")
def run_by_id(scenario_id: str):
    """Run a specific scenario by ID (S1–S8)."""
    try:
        result = run_scenario(scenario_id.upper())
        return result.to_dict()
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/attack/replay")
@app.get("/attack/replay")
def attack_replay(scenario: str = "S1"):
    """
    Replay attack endpoint.
    scenario=S1 → capability replay
    scenario=S3 → revoked agent (revocation race)
    """
    sid = scenario.upper() if scenario.upper() in ("S1", "S3") else "S1"
    return run_scenario(sid).to_dict()


@app.post("/attack/expired")
@app.get("/attack/expired")
def attack_expired(scenario: str = "S2"):
    """Expired/revoked token endpoint."""
    sid = scenario.upper() if scenario.upper() in ("S2", "S3") else "S2"
    return run_scenario(sid).to_dict()


@app.post("/attack/bypass")
@app.get("/attack/bypass")
def attack_bypass(scenario: str = "S4"):
    """
    Bypass attack endpoint.
    S4=direct bypass, S5=policy downgrade, S6=cross-tenant, S7=delegation, S8=fail-open
    """
    valid = {"S4", "S5", "S6", "S7", "S8"}
    sid = scenario.upper() if scenario.upper() in valid else "S4"
    return run_scenario(sid).to_dict()


@app.get("/all")
def run_all():
    """Run all 8 scenarios at once — for the demo reset."""
    results = run_all_scenarios()
    return {
        "total": len(results),
        "blocked": sum(1 for r in results if not r.attack_succeeded),
        "succeeded": sum(1 for r in results if r.attack_succeeded),
        "results": [r.to_dict() for r in results],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("attacker_b.server:app", host="0.0.0.0", port=8003, reload=True)
