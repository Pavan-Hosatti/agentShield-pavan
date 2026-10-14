"""
AgentShield V2 — Replay Guard Unit Tests

Owner: Pavan

Tests the atomic capability claiming interface WITHOUT Redis.
Uses a mock Redis client to verify the contract.

The real integration test (concurrent 100 replays) is in tests/adversarial/test_replay.py.
"""
from __future__ import annotations

import time
import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.services.replay_guard import (
    atomic_claim,
    is_claimed,
    set_revocation,
    is_revoked_in_redis,
    clear_revocation,
    CapabilityAlreadyClaimed,
    ReplayCheckUnavailable,
    CLAIMED_VALUE,
)


# ---------------------------------------------------------------------------
# Mock Redis
# ---------------------------------------------------------------------------

class MockRedis:
    """Minimal Redis mock for unit testing."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._fail = False

    def set(self, key: str, value: str, nx: bool = False, ex: int = None) -> bool | None:
        if self._fail:
            raise ConnectionError("Mock Redis unavailable")
        if nx:
            if key in self._store:
                return None   # Key exists — SET NX fails
            self._store[key] = value
            return True
        self._store[key] = value
        return True

    def exists(self, key: str) -> int:
        if self._fail:
            raise ConnectionError("Mock Redis unavailable")
        return 1 if key in self._store else 0

    def delete(self, key: str) -> int:
        return 1 if self._store.pop(key, None) is not None else 0

    def simulate_failure(self):
        self._fail = True

    def restore(self):
        self._fail = False


# ---------------------------------------------------------------------------
# atomic_claim tests
# ---------------------------------------------------------------------------

class TestAtomicClaim:
    def setup_method(self):
        self.redis = MockRedis()
        self.jti  = "cap-test-jti-001"
        self.exp  = int(time.time()) + 300   # valid for 300s

    def test_first_claim_succeeds(self):
        result = atomic_claim(self.redis, self.jti, self.exp)
        assert result is True

    def test_second_claim_raises_already_claimed(self):
        """I4: At most one claim succeeds for a given jti."""
        atomic_claim(self.redis, self.jti, self.exp)
        with pytest.raises(CapabilityAlreadyClaimed) as exc:
            atomic_claim(self.redis, self.jti, self.exp)
        assert exc.value.jti == self.jti

    def test_different_jtis_both_succeed(self):
        """Two different capabilities can both be claimed."""
        r1 = atomic_claim(self.redis, "jti-a", self.exp)
        r2 = atomic_claim(self.redis, "jti-b", self.exp)
        assert r1 is True
        assert r2 is True

    def test_expired_capability_raises_value_error(self):
        """Claiming an expired capability must fail before touching Redis."""
        past_exp = int(time.time()) - 10
        with pytest.raises(ValueError, match="expired"):
            atomic_claim(self.redis, self.jti, past_exp)

    def test_redis_unavailable_raises_replay_check_unavailable(self):
        """I7: Redis failure must raise ReplayCheckUnavailable -> 503."""
        self.redis.simulate_failure()
        with pytest.raises(ReplayCheckUnavailable):
            atomic_claim(self.redis, self.jti, self.exp)

    def test_100_concurrent_claims_only_one_succeeds(self):
        """
        Simulate 100 serial attempts against the SAME Redis store.
        At most one should succeed; the rest raise CapabilityAlreadyClaimed.
        """
        shared_redis = MockRedis()
        success_count = 0
        for _ in range(100):
            try:
                atomic_claim(shared_redis, self.jti, self.exp)
                success_count += 1
            except CapabilityAlreadyClaimed:
                pass
        assert success_count == 1, \
            f"Expected exactly 1 success, got {success_count}"


# ---------------------------------------------------------------------------
# Revocation tests
# ---------------------------------------------------------------------------

class TestRevocationRedis:
    def setup_method(self):
        self.redis = MockRedis()

    def test_set_revocation_marks_agent(self):
        result = set_revocation(self.redis, "agent-001", "tenant-demo")
        assert result is True

    def test_is_revoked_after_set(self):
        set_revocation(self.redis, "agent-001", "tenant-demo")
        assert is_revoked_in_redis(self.redis, "agent-001", "tenant-demo") is True

    def test_not_revoked_before_set(self):
        assert is_revoked_in_redis(self.redis, "agent-001", "tenant-demo") is False

    def test_revocation_is_per_agent(self):
        set_revocation(self.redis, "agent-001", "tenant-demo")
        # Different agent is not revoked
        assert is_revoked_in_redis(self.redis, "agent-002", "tenant-demo") is False

    def test_redis_failure_returns_none(self):
        """I7: Redis failure must return None (caller fails closed)."""
        self.redis.simulate_failure()
        result = is_revoked_in_redis(self.redis, "agent-001", "tenant-demo")
        assert result is None, "Expected None on Redis failure (fail-closed signal)"

    def test_clear_revocation_removes_key(self):
        set_revocation(self.redis, "agent-001", "tenant-demo")
        clear_revocation(self.redis, "agent-001", "tenant-demo")
        assert is_revoked_in_redis(self.redis, "agent-001", "tenant-demo") is False

    def test_redis_failure_in_set_returns_false(self):
        self.redis.simulate_failure()
        result = set_revocation(self.redis, "agent-001", "tenant-demo")
        assert result is False
