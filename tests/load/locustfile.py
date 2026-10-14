"""
AgentShield V2 — Load Test

Owner: Pavan (design) | Gururaj (execution)

Baseline comparison load test using Locust.
Measures p50/p95 latency and throughput for:
  - Authorization (POST /v1/actions/authorize)
  - Execution    (POST /v1/actions/execute)
  - Audit query  (GET  /v1/audit/events)

Run:
    locust -f tests/load/locustfile.py --host=http://localhost:8000
    locust -f tests/load/locustfile.py --host=http://localhost:8000 \
           --headless -u 100 -r 10 --run-time 60s \
           --csv=tests/load/results/run_$(date +%Y%m%d_%H%M%S)

Requirements:
    pip install locust==2.32.0

Performance targets (from MASTER SPEC §12):
  p95 added latency: < 50ms
  Concurrent agents: ~1000 (target, not guaranteed)

IMPORTANT: Run correctness tests BEFORE load tests.
           Load test results are only meaningful if security tests pass.
"""
from __future__ import annotations

import os
import json
import uuid
import time
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

DEMO_TOKEN   = os.environ.get("DEMO_AGENT_TOKEN", "PLACEHOLDER")
TENANT_ID    = "tenant-demo"
AGENT_ID     = "agent-support-01"


def small_refund_action(intent_suffix: str = "") -> dict:
    """A within-policy refund that does not require approval."""
    return {
        "schema_version": 1,
        "tenant_id": TENANT_ID,
        "principal_id": AGENT_ID,
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "arguments": {"order_id": "ORDER-123", "amount_minor": 29999},
        "environment": "demo",
        "policy_version": 3,
        "intent_id": f"intent-load-{uuid.uuid4()}{intent_suffix}",
    }


# ---------------------------------------------------------------------------
# User: Normal operations (benign baseline)
# ---------------------------------------------------------------------------

class AgentUser(HttpUser):
    """
    Simulates a legitimate AI agent performing refund operations.
    Mixed traffic: authorize + execute + audit read.
    """
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.headers = {
            "Authorization": f"Bearer {DEMO_TOKEN}",
            "Content-Type": "application/json",
        }

    @task(5)
    def authorize_action(self):
        """POST /v1/actions/authorize — most common operation."""
        action = small_refund_action()
        with self.client.post(
            "/v1/actions/authorize",
            json=action,
            headers=self.headers,
            catch_response=True,
            name="POST /v1/actions/authorize",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code in (403, 202):
                # 403 = policy deny (expected for some actions)
                # 202 = needs approval (expected for high-value)
                resp.success()
            else:
                resp.failure(f"Unexpected status: {resp.status_code}")

    @task(3)
    def authorize_and_execute(self):
        """Full authorize → execute flow."""
        action = small_refund_action()
        with self.client.post(
            "/v1/actions/authorize",
            json=action,
            headers=self.headers,
            catch_response=True,
            name="POST /v1/actions/authorize (full-flow)",
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"Authorize failed: {resp.status_code}")
                return
            resp.success()
            body = resp.json()

        capability_token = body.get("capability_token")
        if not capability_token:
            return

        with self.client.post(
            "/v1/actions/execute",
            json={"capability_token": capability_token, "action": action},
            headers=self.headers,
            catch_response=True,
            name="POST /v1/actions/execute",
        ) as resp:
            if resp.status_code in (200, 409):
                resp.success()
            else:
                resp.failure(f"Execute failed: {resp.status_code}")

    @task(1)
    def read_audit_events(self):
        """GET /v1/audit/events — read-heavy audit queries."""
        with self.client.get(
            "/v1/audit/events?limit=20",
            headers=self.headers,
            catch_response=True,
            name="GET /v1/audit/events",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Audit query failed: {resp.status_code}")

    @task(1)
    def check_metrics(self):
        """GET /v1/metrics/summary — dashboard polling."""
        with self.client.get(
            "/v1/metrics/summary",
            headers=self.headers,
            catch_response=True,
            name="GET /v1/metrics/summary",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Metrics failed: {resp.status_code}")


# ---------------------------------------------------------------------------
# User: Replay attacker (mixed with benign traffic)
# ---------------------------------------------------------------------------

class ReplayAttacker(HttpUser):
    """
    Simulates a replay attack mixed into the load.
    Captures a capability and replays it.
    """
    wait_time = between(0.01, 0.1)  # Fast — attacker is trying to win a race
    weight = 1  # Low weight: 1 attacker per 10 legitimate users

    def on_start(self):
        self.headers = {
            "Authorization": f"Bearer {DEMO_TOKEN}",
            "Content-Type": "application/json",
        }
        self.capability_token = None
        self.replayed_action = None
        self._acquire_capability()

    def _acquire_capability(self):
        """Get one capability to replay many times."""
        action = small_refund_action("-replay")
        try:
            resp = self.client.post(
                "/v1/actions/authorize",
                json=action,
                headers=self.headers,
                name="REPLAY: authorize (setup)",
            )
            if resp.status_code == 200:
                self.capability_token = resp.json().get("capability_token")
                self.replayed_action = action
        except Exception:
            pass

    @task
    def replay_capability(self):
        """Attempt to replay the same capability repeatedly."""
        if not self.capability_token:
            self._acquire_capability()
            return

        with self.client.post(
            "/v1/actions/execute",
            json={
                "capability_token": self.capability_token,
                "action": self.replayed_action,
            },
            headers=self.headers,
            catch_response=True,
            name="REPLAY: execute (attack A3)",
        ) as resp:
            if resp.status_code == 200:
                # First replay may succeed; record it
                resp.success()
            elif resp.status_code == 409:
                # Expected: CAPABILITY_ALREADY_CLAIMED
                resp.success()
            elif resp.status_code == 403:
                # Expected: CAPABILITY_EXPIRED or similar
                resp.success()
            else:
                resp.failure(f"Unexpected replay status: {resp.status_code}")
