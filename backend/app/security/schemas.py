"""
AgentShield V2 — Canonical Action Schema and Execution State Definitions

Owner: Pavan (schema design) | Alok (Pydantic implementation)
This is the authoritative shared schema. Do not create alternate schemas.

All services that process action envelopes must import from this module.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Environment(str, Enum):
    DEMO = "demo"
    STAGING = "staging"
    PRODUCTION = "production"


class ExecutionState(str, Enum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED_FINAL = "FAILED_FINAL"
    UNKNOWN = "UNKNOWN"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Tool-Specific Argument Schemas
# ---------------------------------------------------------------------------

class IssueRefundArguments(BaseModel):
    """Arguments for the issue_refund tool."""

    model_config = {"extra": "forbid"}

    order_id: str = Field(..., min_length=1, max_length=128)
    amount_minor: int = Field(..., gt=0, strict=True, description="Amount in paise (integer only). 50000 = ₹500.00")

    @field_validator("amount_minor", mode="before")
    @classmethod
    def reject_float_amounts(cls, v: Any) -> int:
        """Reject floating-point amounts and numeric strings. Money must be integer paise."""
        if isinstance(v, float):
            raise ValueError(
                "amount_minor must be an integer (paise), not a float. "
                "Use 50000 for ₹500.00, not 500.0 or 500.00."
            )
        if isinstance(v, str):
            raise ValueError(
                "amount_minor must be an integer (paise), not a string. "
                "Use 50000 for ₹500.00."
            )
        return v

    @field_validator("order_id")
    @classmethod
    def validate_order_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("order_id must not be empty or whitespace only")
        return v


# Map of tool name → argument schema
TOOL_ARGUMENT_SCHEMAS: dict[str, type[BaseModel]] = {
    "issue_refund": IssueRefundArguments,
}

SUPPORTED_TOOLS: frozenset[str] = frozenset(TOOL_ARGUMENT_SCHEMAS.keys())


# ---------------------------------------------------------------------------
# Canonical Action Envelope
# ---------------------------------------------------------------------------

# Identifier pattern: no leading/trailing whitespace, printable ASCII
_ID_PATTERN = re.compile(r"^\S.*\S$|^\S$")


def _validate_identifier(v: str, field_name: str) -> str:
    """Validate that an identifier has no leading/trailing whitespace."""
    if v != v.strip():
        raise ValueError(f"{field_name} must not have leading or trailing whitespace")
    if not v:
        raise ValueError(f"{field_name} must not be empty")
    return v


class ActionEnvelope(BaseModel):
    """
    The canonical AgentShield V2 action envelope.

    This schema is the single source of truth for all action processing.
    Changes require consensus from Pavan, Alok, Girish, and Gururaj.

    Key rules:
    - Unknown fields are rejected (extra='forbid').
    - Duplicate JSON keys must be caught by the JSON parser before Pydantic.
    - All identifier fields must have no leading/trailing whitespace.
    - amount_minor must be an integer (paise), never a float.
    - schema_version must be 1.
    """

    model_config = {
        "extra": "forbid",          # Unknown fields → validation error
        "str_strip_whitespace": False,  # We handle this ourselves per field
    }

    schema_version: int = Field(
        ...,
        strict=True,
        description="Schema version. Currently must be 1.",
    )
    tenant_id: str = Field(..., min_length=1, max_length=128)
    principal_id: str = Field(..., min_length=1, max_length=128)
    tool: str = Field(..., min_length=1, max_length=64)
    resource: str = Field(..., min_length=1, max_length=256)
    arguments: dict[str, Any] = Field(...)
    environment: Environment
    policy_version: int = Field(..., ge=1)
    intent_id: str = Field(..., min_length=1, max_length=128)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"Unsupported schema_version: {v}. Only version 1 is supported.")
        return v

    @field_validator("tenant_id", "principal_id", "intent_id")
    @classmethod
    def validate_no_whitespace_padding(cls, v: str) -> str:
        if v != v.strip():
            raise ValueError("Identifier fields must not have leading or trailing whitespace")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v != v.strip():
            raise ValueError("tool must not have leading or trailing whitespace")
        if v not in SUPPORTED_TOOLS:
            raise ValueError(f"Unknown tool: {v!r}. Supported tools: {sorted(SUPPORTED_TOOLS)}")
        return v

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, v: str) -> str:
        if v != v.strip():
            raise ValueError("resource must not have leading or trailing whitespace")
        return v

    @model_validator(mode="after")
    def validate_arguments_against_tool_schema(self) -> "ActionEnvelope":
        """Validate arguments using the tool-specific schema."""
        tool_schema = TOOL_ARGUMENT_SCHEMAS.get(self.tool)
        if tool_schema is None:
            raise ValueError(f"No argument schema for tool: {self.tool!r}")
        # This will raise ValidationError with field-level details if invalid
        tool_schema.model_validate(self.arguments)
        return self

    def get_validated_arguments(self) -> BaseModel:
        """Return the arguments as a validated tool-specific model instance."""
        tool_schema = TOOL_ARGUMENT_SCHEMAS[self.tool]
        return tool_schema.model_validate(self.arguments)


# ---------------------------------------------------------------------------
# Execution Record Schema
# ---------------------------------------------------------------------------

class ExecutionRecord(BaseModel):
    """Durable execution state record (mirrors PostgreSQL execution_records table)."""

    model_config = {"extra": "forbid"}

    execution_id: str
    jti: str                          # Capability ID — UNIQUE constraint in DB
    principal_id: str
    tenant_id: str
    tool: str
    resource: str
    action_digest: str                # Hex-encoded SHA-256
    state: ExecutionState
    idempotency_key: str              # Stable key for downstream mock tool (= jti)
    result: dict[str, Any] | None = None
    error: str | None = None
    receipt_id: str | None = None


# ---------------------------------------------------------------------------
# Approval Record Schema
# ---------------------------------------------------------------------------

class ApprovalRecord(BaseModel):
    """Human approval record (mirrors PostgreSQL approvals table)."""

    model_config = {"extra": "forbid"}

    approval_id: str
    tenant_id: str
    intent_id: str                    # Links to the original action request
    action_digest: str                # Exact action digest this approval covers
    approver_identity: str            # Authenticated approver (server-resolved)
    decision: ApprovalDecision
    consumed: bool = False
    approval_policy_version: int


# ---------------------------------------------------------------------------
# Capability Claims Schema (for validation at executor)
# ---------------------------------------------------------------------------

class CapabilityClaims(BaseModel):
    """
    Expected claims in a verified capability token.
    Executor validates decoded JWT payload against this schema.
    """

    model_config = {"extra": "allow"}   # JWT may have standard claims we don't enumerate

    iss: str = Field(..., description="Issuer: agentshield-capability-issuer-v1")
    aud: str = Field(..., description="Audience: agentshield-protected-executor-v1")
    sub: str = Field(..., description="Authenticated principal_id")
    tenant_id: str
    tool: str
    resource: str
    action_digest: str
    jti: str
    iat: int
    exp: int
    policy_version: int
    environment: str
    intent_id: str
    approval_id: str | None = None
    kid: str

    EXPECTED_ISSUER: str = "agentshield-capability-issuer-v1"
    EXPECTED_AUDIENCE: str = "agentshield-protected-executor-v1"
