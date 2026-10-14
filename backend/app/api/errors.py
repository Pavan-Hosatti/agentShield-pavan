"""
AgentShield V2 — Standardised Error Responses

Owner: Pavan (error contract) | Alok (exception handlers)

Every error response must have request_id, trace_id, reason, detail.
Reason codes are the canonical set from API_CONTRACT.md.
NEVER expose signing keys, raw tokens, or DB credentials in errors.
"""
from __future__ import annotations

import uuid
from typing import Any


def error_response(
    reason: str,
    detail: str = "",
    request_id: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    return {
        "request_id": request_id or str(uuid.uuid4()),
        "trace_id":   trace_id   or str(uuid.uuid4()),
        "reason":     reason,
        "detail":     detail,
    }


def success_response(
    data: Any,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    return {
        "request_id": request_id or str(uuid.uuid4()),
        "trace_id":   trace_id   or str(uuid.uuid4()),
        "data":       data,
    }


# ── Reason codes (canonical — must match API_CONTRACT.md) ──────────────────

class ReasonCode:
    # 401
    INVALID_CREDENTIAL             = "INVALID_CREDENTIAL"
    # 403
    IDENTITY_MISMATCH              = "IDENTITY_MISMATCH"
    RESOURCE_OWNERSHIP_FAILED      = "RESOURCE_OWNERSHIP_FAILED"
    TOOL_NOT_PERMITTED             = "TOOL_NOT_PERMITTED"
    HARD_DENY                      = "HARD_DENY"
    POLICY_DENY                    = "POLICY_DENY"
    POLICY_DENY_AT_EXECUTION       = "POLICY_DENY_AT_EXECUTION"
    POLICY_VERSION_STALE           = "POLICY_VERSION_STALE"
    APPROVAL_REQUIRED              = "APPROVAL_REQUIRED"
    APPROVAL_REJECTED              = "APPROVAL_REJECTED"
    APPROVAL_INVALID               = "APPROVAL_INVALID"
    APPROVAL_ALREADY_CONSUMED      = "APPROVAL_ALREADY_CONSUMED"
    INVALID_CAPABILITY_SIGNATURE   = "INVALID_CAPABILITY_SIGNATURE"
    CAPABILITY_EXPIRED             = "CAPABILITY_EXPIRED"
    CAPABILITY_CONTEXT_MISMATCH    = "CAPABILITY_CONTEXT_MISMATCH"
    DIGEST_MISMATCH                = "DIGEST_MISMATCH"
    AGENT_REVOKED                  = "AGENT_REVOKED"
    # 409
    CAPABILITY_ALREADY_CLAIMED     = "CAPABILITY_ALREADY_CLAIMED"
    EXECUTION_RECORD_DUPLICATE     = "EXECUTION_RECORD_DUPLICATE"
    AGENT_ALREADY_EXISTS           = "AGENT_ALREADY_EXISTS"
    AGENT_ALREADY_REVOKED          = "AGENT_ALREADY_REVOKED"
    APPROVAL_ALREADY_DECIDED       = "APPROVAL_ALREADY_DECIDED"
    # 422
    SCHEMA_VALIDATION_FAILED       = "SCHEMA_VALIDATION_FAILED"
    # 503
    POLICY_CHECK_UNAVAILABLE       = "POLICY_CHECK_UNAVAILABLE"
    REPLAY_CHECK_UNAVAILABLE       = "REPLAY_CHECK_UNAVAILABLE"
    REVOCATION_CHECK_UNAVAILABLE   = "REVOCATION_CHECK_UNAVAILABLE"
    EXECUTION_STORE_UNAVAILABLE    = "EXECUTION_STORE_UNAVAILABLE"
    APPROVAL_STORE_UNAVAILABLE     = "APPROVAL_STORE_UNAVAILABLE"
    # 404
    AGENT_NOT_FOUND                = "AGENT_NOT_FOUND"
    APPROVAL_REQUEST_NOT_FOUND     = "APPROVAL_REQUEST_NOT_FOUND"
