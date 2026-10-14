"""
AgentShield V2 — Revocation Service

Owner: Pavan (specification) | Alok (implementation)

Revocation check is performed by the executor at Step 11f.
Both Redis (fast) and PostgreSQL (durable) are checked.

Fail-closed:
  If Redis is unavailable, we still check PostgreSQL.
  If BOTH are unavailable, raise RevocationCheckUnavailable (return 503).

Invariant I6: Revocation after authorization prevents execution.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


class RevocationCheckUnavailable(Exception):
    """Both Redis and PostgreSQL revocation checks failed. Fail-closed -> 503."""


class AgentRevoked(Exception):
    """Agent is confirmed revoked. Executor returns 403 AGENT_REVOKED."""
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        super().__init__(f"Agent {agent_id!r} is revoked")


def check_revocation(
    agent_id: str,
    tenant_id: str,
    redis_client: Any,
    db_session: Any,
) -> None:
    """
    Check whether an agent is revoked. Called by the executor at Step 11f.

    Checks Redis first (fast), then PostgreSQL (durable).
    Fails closed if both are unavailable.

    Args:
        agent_id:     Agent to check.
        tenant_id:    Tenant of the agent.
        redis_client: Redis client (may be None if not configured).
        db_session:   SQLAlchemy session.

    Raises:
        AgentRevoked:                  Agent is confirmed revoked.
        RevocationCheckUnavailable:    Both checks failed (caller returns 503).
    """
    redis_available = True
    redis_revoked: bool | None = None

    # Step 1: Redis fast check
    if redis_client is not None:
        try:
            from app.services.replay_guard import is_revoked_in_redis
            redis_revoked = is_revoked_in_redis(redis_client, agent_id, tenant_id)
        except Exception as e:
            log.warning("Redis revocation check failed: %s", e)
            redis_available = False

    if redis_revoked is True:
        raise AgentRevoked(agent_id)

    # Step 2: PostgreSQL durable check
    db_error = None
    try:
        from app.db.models import Revocation
        revocation = (
            db_session.query(Revocation)
            .filter(
                Revocation.agent_id == agent_id,
                Revocation.tenant_id == tenant_id,
            )
            .first()
        )
        if revocation is not None:
            raise AgentRevoked(agent_id)
    except AgentRevoked:
        raise
    except Exception as e:
        log.error("PostgreSQL revocation check failed for agent=%s: %s", agent_id, e)
        db_error = e

    # Fail-closed: if Redis was unavailable AND PostgreSQL failed
    if not redis_available and db_error is not None:
        raise RevocationCheckUnavailable(
            f"Both Redis and PostgreSQL revocation checks failed for agent={agent_id!r}"
        )
