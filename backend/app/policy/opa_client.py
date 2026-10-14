"""
AgentShield V2 — OPA Policy Client

Owner: Pavan (design) | Alok (integration wiring)

Wraps OPA HTTP API calls. Used by the gateway AND the executor.
The executor MUST re-call OPA at execution time — not trust the gateway's earlier ALLOW.

Protocol reference: SECURITY_PROTOCOL.md §Steps 6, 11e
Fail-closed: OPA unavailable -> raise PolicyCheckUnavailable (caller returns 503)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "agentshield/authz/decision"
OPA_TIMEOUT_SECONDS = 5.0


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------

class PolicyResult(str, Enum):
    ALLOW          = "allow"
    DENY           = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class PolicyDecision:
    result: PolicyResult
    reason: str
    approval_type: Optional[str] = None   # set when result == NEEDS_APPROVAL

    @property
    def is_allowed(self) -> bool:
        return self.result == PolicyResult.ALLOW

    @property
    def is_denied(self) -> bool:
        return self.result == PolicyResult.DENY

    @property
    def needs_approval(self) -> bool:
        return self.result == PolicyResult.NEEDS_APPROVAL


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PolicyCheckUnavailable(Exception):
    """OPA is unreachable. Executor/gateway must fail-closed (return 503)."""


class PolicyDenied(Exception):
    """OPA returned deny. Includes reason code."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Input builder
# ---------------------------------------------------------------------------

def build_opa_input(
    *,
    action: dict[str, Any],
    agent: dict[str, Any],
    resource: dict[str, Any],
    action_digest: str,
    approval: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build the OPA input document for policy evaluation.

    Args:
        action:        The validated action envelope (as dict).
        agent:         Server-side agent record (registered, revoked, permitted_tools, etc.)
        resource:      Resource ownership record (owner_tenant_id).
        action_digest: Pre-computed action digest.
        approval:      Approval record if one has been submitted (optional).

    Returns:
        OPA input dict ready for POST /v1/data/{path}.
    """
    opa_action = dict(action)
    opa_action["action_digest"] = action_digest

    inp: dict[str, Any] = {
        "action": opa_action,
        "agent": {
            "registered": agent.get("registered", False),
            "revoked": agent.get("revoked", False),
            "tenant_id": agent.get("tenant_id", ""),
            "permitted_tools": agent.get("permitted_tools", []),
            "max_amount_minor": agent.get("max_amount_minor"),
        },
        "resource": {
            "owner_tenant_id": resource.get("owner_tenant_id", ""),
        },
    }

    if approval is not None:
        inp["approval"] = {
            "valid": not approval.get("consumed", True)
                     and approval.get("decision") == "approved",
            "action_digest": approval.get("action_digest", ""),
            "tenant_id": approval.get("tenant_id", ""),
            "consumed": approval.get("consumed", True),
            "decision": approval.get("decision", "rejected"),
        }

    return inp


# ---------------------------------------------------------------------------
# Sync OPA client
# ---------------------------------------------------------------------------

def evaluate_policy(
    opa_input: dict[str, Any],
    opa_url: str = OPA_URL,
    policy_path: str = OPA_POLICY_PATH,
    timeout: float = OPA_TIMEOUT_SECONDS,
) -> PolicyDecision:
    """
    Evaluate the OPA policy synchronously.

    Fail-closed: if OPA is unreachable, raises PolicyCheckUnavailable.
    The caller must catch this and return 503 POLICY_CHECK_UNAVAILABLE.

    Args:
        opa_input:   Dict returned by build_opa_input().
        opa_url:     OPA server base URL.
        policy_path: Rego package path for the decision rule.
        timeout:     HTTP timeout in seconds.

    Returns:
        PolicyDecision with result, reason, and optional approval_type.

    Raises:
        PolicyCheckUnavailable: OPA unreachable.
        ValueError: Malformed OPA response.
    """
    url = f"{opa_url.rstrip('/')}/v1/data/{policy_path}"

    try:
        resp = httpx.post(
            url,
            json={"input": opa_input},
            timeout=timeout,
        )
        resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
        log.error("OPA unreachable at %s: %s", url, e)
        raise PolicyCheckUnavailable(
            f"OPA policy check unavailable: {e}"
        ) from e
    except Exception as e:
        log.error("OPA unexpected error: %s", e)
        raise PolicyCheckUnavailable(f"OPA unexpected error: {e}") from e

    try:
        body = resp.json()
        decision_raw = body.get("result", {})
    except (json.JSONDecodeError, AttributeError) as e:
        raise ValueError(f"Malformed OPA response: {resp.text[:200]}") from e

    # OPA returns the decision rule's value directly
    result_str = decision_raw.get("result", "deny")
    reason = decision_raw.get("reason", "DEFAULT_DENY")
    approval_type = decision_raw.get("approval_type")

    try:
        result = PolicyResult(result_str)
    except ValueError:
        log.warning("Unknown OPA result value: %r — treating as deny", result_str)
        result = PolicyResult.DENY
        reason = f"UNKNOWN_OPA_RESULT:{result_str}"

    return PolicyDecision(result=result, reason=reason, approval_type=approval_type)


# ---------------------------------------------------------------------------
# Async OPA client (for use in async FastAPI routes)
# ---------------------------------------------------------------------------

async def evaluate_policy_async(
    opa_input: dict[str, Any],
    opa_url: str = OPA_URL,
    policy_path: str = OPA_POLICY_PATH,
    timeout: float = OPA_TIMEOUT_SECONDS,
) -> PolicyDecision:
    """
    Async version of evaluate_policy() for FastAPI route handlers.

    Same fail-closed behavior as the sync version.
    """
    url = f"{opa_url.rstrip('/')}/v1/data/{policy_path}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json={"input": opa_input})
            resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
        log.error("OPA unreachable at %s: %s", url, e)
        raise PolicyCheckUnavailable(f"OPA unavailable: {e}") from e

    try:
        body = resp.json()
        decision_raw = body.get("result", {})
    except (json.JSONDecodeError, AttributeError) as e:
        raise ValueError(f"Malformed OPA response: {resp.text[:200]}") from e

    result_str = decision_raw.get("result", "deny")
    reason = decision_raw.get("reason", "DEFAULT_DENY")
    approval_type = decision_raw.get("approval_type")

    try:
        result = PolicyResult(result_str)
    except ValueError:
        result = PolicyResult.DENY
        reason = f"UNKNOWN_OPA_RESULT:{result_str}"

    return PolicyDecision(result=result, reason=reason, approval_type=approval_type)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def opa_health_check(opa_url: str = OPA_URL) -> dict[str, str]:
    """
    Check OPA server health. Used by the /health endpoint.
    Returns {"status": "up"} or {"status": "down", "error": "..."}.
    """
    try:
        resp = httpx.get(f"{opa_url.rstrip('/')}/health", timeout=2.0)
        if resp.status_code == 200:
            return {"status": "up"}
        return {"status": "down", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "down", "error": str(e)}
