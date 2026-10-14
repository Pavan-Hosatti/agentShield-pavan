"""
AgentShield V2 — FastAPI Dependencies

Owner: Pavan (design) | Alok (implementation)

Provides reusable FastAPI dependencies that enforce the protocol:
  - get_verified_agent(): resolves and validates identity from credentials
  - require_environment(): validates deployment environment
  - get_redis(): provides Redis client (fail-closed on unavailability)

CRITICAL: get_verified_agent() resolves identity from the credential ONLY.
          It must NEVER trust principal_id or tenant_id from the request body.
          Violation = CRITICAL security finding (HANDOFF_TO_ALOK §2).
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)

AGENTSHIELD_ENVIRONMENT = os.environ.get("AGENTSHIELD_ENVIRONMENT", "demo")


# ---------------------------------------------------------------------------
# Agent identity context (resolved from credential)
# ---------------------------------------------------------------------------

class AgentIdentity:
    """
    Credential-resolved agent identity.
    This is the ONLY source of trust for principal_id and tenant_id.
    Never constructed from request body fields.
    """
    def __init__(self, agent_id: str, tenant_id: str, agent_record: dict):
        self.agent_id     = agent_id
        self.tenant_id    = tenant_id
        self.agent_record = agent_record  # Full DB record

    def validate_matches_action(
        self, action_principal_id: str, action_tenant_id: str
    ) -> bool:
        """
        Verify that action body fields match the credential-resolved identity.
        Returns False if they differ (gateway returns 403 IDENTITY_MISMATCH).
        """
        return (
            action_principal_id == self.agent_id
            and action_tenant_id == self.tenant_id
        )


# ---------------------------------------------------------------------------
# Stub dependencies — Alok replaces these with real implementations
# ---------------------------------------------------------------------------

async def get_verified_agent(
    # FastAPI injects: authorization: str = Header(...)
    # Alok: implement JWT verify -> DB lookup -> AgentIdentity
) -> AgentIdentity:
    """
    Dependency: Verify credential and resolve agent identity.

    Alok implements this as a FastAPI dependency using:
      1. Extract Bearer token from Authorization header
      2. Verify JWT (signature, expiry, issuer) OR hash-compare API key
      3. Look up agent record in PostgreSQL by the token's sub claim
      4. Return AgentIdentity wrapping the DB record

    This is the ONLY source of principal_id and tenant_id in the system.
    """
    raise NotImplementedError(
        "Alok: implement get_verified_agent() as a FastAPI dependency. "
        "See HANDOFF_TO_ALOK.md §2."
    )


def get_redis():
    """
    Dependency: Provide a Redis client.
    Alok configures the Redis connection pool here.
    Fail-closed: if Redis is down at startup, raise and prevent service start.
    """
    raise NotImplementedError("Alok: implement get_redis() dependency.")


def get_db():
    """
    Dependency: Provide a SQLAlchemy DB session.
    Alok configures the engine and session factory here.
    """
    raise NotImplementedError("Alok: implement get_db() dependency.")
