"""
AgentShield V2 — Capability Issuance and Verification

Owner: Girish (crypto body) | Pavan (protocol specification + interface)

issue_capability()  — called by the gateway after OPA ALLOW
verify_capability() — called by the executor before every side effect

Protocol: SECURITY_PROTOCOL.md §Steps 9, 11a-11c
Interface: HANDOFF_TO_GIRISH.md §2
"""
from __future__ import annotations

import time
import uuid
import logging
from dataclasses import dataclass
from typing import Any, Optional

log = logging.getLogger(__name__)

EXPECTED_ISSUER   = "agentshield-capability-issuer-v1"
EXPECTED_AUDIENCE = "agentshield-protected-executor-v1"


# ---------------------------------------------------------------------------
# Verification context (executor provides this — NOT derived from token)
# ---------------------------------------------------------------------------

@dataclass
class VerificationContext:
    current_environment: str
    clock_skew_seconds: int = 5


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class CapabilityVerificationError(Exception):
    """Raised on any verification failure. reason is the error code for the API."""
    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ---------------------------------------------------------------------------
# Claims builder — called by gateway
# ---------------------------------------------------------------------------

def build_capability_claims(
    *,
    principal_id: str,
    tenant_id: str,
    tool: str,
    resource: str,
    action_digest: str,
    policy_version: int,
    environment: str,
    intent_id: str,
    kid: str,
    ttl_seconds: int = 300,
    approval_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build capability claims dict ready for signing.
    action_digest MUST be the output of calculate_action_digest().
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": EXPECTED_ISSUER,
        "aud": EXPECTED_AUDIENCE,
        "sub": principal_id,
        "tenant_id": tenant_id,
        "tool": tool,
        "resource": resource,
        "action_digest": action_digest,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl_seconds,
        "policy_version": policy_version,
        "environment": environment,
        "intent_id": intent_id,
        "kid": kid,
    }
    if approval_id is not None:
        claims["approval_id"] = approval_id
    return claims


def issue_capability(claims: dict[str, Any], signing_key: Any) -> str:
    """
    Sign and return a compact JWS token.
    OWNER: Girish — implement with PyJWT + Ed25519 (EdDSA, crv=Ed25519).
    kid must be in the JWT header.
    """
    raise NotImplementedError(
        "issue_capability(): Girish implements this. "
        "Use PyJWT with algorithm='EdDSA' and kid in headers."
    )


def verify_capability(
    token: str,
    expected_action_digest: str,
    authenticated_principal: str,
    context: VerificationContext,
    key_registry: Any,
) -> dict[str, Any]:
    """
    Verify a capability token at the executor. Steps 11a-11c.
    OWNER: Girish implements. Raises CapabilityVerificationError on any failure.

    Reason codes:
      UNKNOWN_KEY_ID, INVALID_CAPABILITY_SIGNATURE,
      CAPABILITY_EXPIRED, CAPABILITY_CONTEXT_MISMATCH,
      DIGEST_MISMATCH, PRINCIPAL_MISMATCH
    """
    raise NotImplementedError(
        "verify_capability(): Girish implements this. "
        "See HANDOFF_TO_GIRISH.md §2 for the full contract."
    )
