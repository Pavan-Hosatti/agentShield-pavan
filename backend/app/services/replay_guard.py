"""
AgentShield V2 — Replay Guard (Redis atomic claim)

Owner: Pavan (specification) | Alok (Redis wiring)

Implements the atomic capability claiming described in SECURITY_PROTOCOL.md §Step 11h.

Redis SET NX EX is atomic:
  - If key does not exist: sets it and returns True  (claim succeeded)
  - If key already exists: returns False             (already claimed — replay)

The key is the capability's jti. TTL = remaining time until capability expiry.

Fail-closed: if Redis is unavailable, raises ReplayCheckUnavailable.
The executor must catch this and return 503 REPLAY_CHECK_UNAVAILABLE.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

log = logging.getLogger(__name__)

CLAIMED_VALUE = "claimed"


class ReplayCheckUnavailable(Exception):
    """Redis is unreachable. Caller must return 503 REPLAY_CHECK_UNAVAILABLE."""


class CapabilityAlreadyClaimed(Exception):
    """This jti has already been claimed. Caller returns 409 CAPABILITY_ALREADY_CLAIMED."""
    def __init__(self, jti: str):
        self.jti = jti
        super().__init__(f"Capability jti={jti!r} already claimed")


def atomic_claim(
    redis_client,  # redis.Redis instance
    jti: str,
    capability_exp: int,
    clock_skew_seconds: int = 5,
) -> bool:
    """
    Atomically claim a capability by its jti using Redis SET NX EX.

    Args:
        redis_client:       Redis client instance (redis.Redis).
        jti:                Unique capability ID from the capability token.
        capability_exp:     Unix timestamp of capability expiry (from token 'exp' claim).
        clock_skew_seconds: Add this buffer to the TTL to handle clock differences.

    Returns:
        True if the claim succeeded (first time this jti was seen).

    Raises:
        CapabilityAlreadyClaimed: jti was already in Redis (replay detected).
        ReplayCheckUnavailable:   Redis is unreachable (fail-closed).
        ValueError:               TTL is <= 0 (capability already expired).
    """
    now = int(time.time())
    ttl = (capability_exp - now) + clock_skew_seconds

    if ttl <= 0:
        raise ValueError(f"Capability jti={jti!r} is expired (exp={capability_exp}, now={now})")

    redis_key = f"capability:{jti}"

    try:
        result = redis_client.set(redis_key, CLAIMED_VALUE, nx=True, ex=ttl)
    except Exception as e:
        log.error("Redis SET NX failed for jti=%s: %s", jti, e)
        raise ReplayCheckUnavailable(f"Redis unavailable: {e}") from e

    if result is None:
        # Key already existed — replay detected
        raise CapabilityAlreadyClaimed(jti)

    return True


def is_claimed(redis_client, jti: str) -> bool:
    """
    Check if a jti is already claimed (non-atomic read — for monitoring only).
    Do NOT use this as the replay protection check — use atomic_claim().
    """
    try:
        return redis_client.exists(f"capability:{jti}") > 0
    except Exception:
        return False


def set_revocation(redis_client, agent_id: str, tenant_id: str) -> bool:
    """
    Write a revocation entry to Redis for fast executor-side lookup.
    This is written alongside the PostgreSQL revocation record.

    Redis key has no TTL — revocations are permanent until cleared by reset.
    """
    key = f"revoked:{agent_id}:{tenant_id}"
    try:
        redis_client.set(key, "1")
        return True
    except Exception as e:
        log.error("Failed to write Redis revocation for agent=%s: %s", agent_id, e)
        return False


def is_revoked_in_redis(redis_client, agent_id: str, tenant_id: str) -> Optional[bool]:
    """
    Check Redis for agent revocation.

    Returns:
        True  — agent is revoked (Redis key exists)
        False — agent is NOT revoked (Redis key absent)
        None  — Redis unavailable (caller must fail-closed and check PostgreSQL)
    """
    key = f"revoked:{agent_id}:{tenant_id}"
    try:
        return redis_client.exists(key) > 0
    except Exception as e:
        log.error("Redis revocation check failed for agent=%s: %s", agent_id, e)
        return None  # Caller must treat None as fail-closed


def clear_revocation(redis_client, agent_id: str, tenant_id: str) -> None:
    """Remove a revocation from Redis. Used by demo reset only."""
    try:
        redis_client.delete(f"revoked:{agent_id}:{tenant_id}")
    except Exception as e:
        log.warning("Failed to clear Redis revocation for agent=%s: %s", agent_id, e)
