"""
AgentShield V2 — Signed Execution Receipts

Owner: Girish (signing body) | Pavan (receipt format specification)

A receipt records the executor's outcome and is independently verifiable.

A receipt signature proves that the holder of the signing key attested
to this execution outcome. It does NOT prove the protected side effect
happened — it is tied to the durable execution record and mock-tool state
for that additional guarantee.

Receipt fields bind:
  - receipt_id, execution_id, tenant_id, principal_id
  - action_digest (exact — links to the action that was authorized)
  - jti (capability ID — links to the single-use claim)
  - execution_result: succeeded | failed | unknown
  - timestamp, executor_id, kid, schema_version
"""
from __future__ import annotations

import uuid
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)


@dataclass
class ReceiptVerificationResult:
    valid: bool
    reason: str
    claims: Optional[dict[str, Any]] = None

    @classmethod
    def ok(cls, claims: dict[str, Any]) -> "ReceiptVerificationResult":
        return cls(valid=True, reason="OK", claims=claims)

    @classmethod
    def fail(cls, reason: str) -> "ReceiptVerificationResult":
        return cls(valid=False, reason=reason)


def build_receipt(
    *,
    execution_id: str,
    tenant_id: str,
    principal_id: str,
    action_digest: str,
    jti: str,
    execution_result: str,         # "succeeded" | "failed" | "unknown"
    approval_id: Optional[str] = None,
    kid: str,
) -> dict[str, Any]:
    """
    Build a receipt payload for signing.

    Args:
        execution_result: One of "succeeded", "failed", "unknown".
        kid:              Key ID that will be used to sign.

    Returns:
        Unsigned receipt dict. Pass to sign_execution_receipt().
    """
    if execution_result not in ("succeeded", "failed", "unknown"):
        raise ValueError(
            f"execution_result must be 'succeeded', 'failed', or 'unknown', "
            f"got {execution_result!r}"
        )
    return {
        "schema_version": 1,
        "receipt_id": str(uuid.uuid4()),
        "execution_id": execution_id,
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "action_digest": action_digest,
        "jti": jti,
        "approval_id": approval_id,
        "execution_result": execution_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "executor_id": "agentshield-executor-v1",
        "kid": kid,
    }


def sign_execution_receipt(
    receipt: dict[str, Any],
    signing_key: Any,  # Ed25519PrivateKey
) -> dict[str, Any]:
    """
    Sign the receipt and return it with a signature field.
    OWNER: Girish implements the signing body.

    The signature covers all fields in the receipt (sorted canonical JSON).
    A modified receipt must fail verification.
    """
    raise NotImplementedError(
        "sign_execution_receipt(): Girish implements this. "
        "Sign the canonical JSON of the receipt dict with Ed25519."
    )


def verify_execution_receipt(
    signed_receipt: dict[str, Any],
    key_registry: Any,  # KeyRegistry
) -> ReceiptVerificationResult:
    """
    Independently verify an execution receipt.
    OWNER: Girish implements the verification body.

    Must verify:
    - Signature is valid for the kid in the receipt.
    - kid is known in the registry.
    - schema_version is supported.
    - execution_result is a valid value.

    Returns ReceiptVerificationResult, never raises silently.
    """
    raise NotImplementedError(
        "verify_execution_receipt(): Girish implements this. "
        "See HANDOFF_TO_GIRISH.md §5."
    )
