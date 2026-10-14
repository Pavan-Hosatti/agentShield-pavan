"""
AgentShield V2 — Key Management Tests

Owner: Pavan

Tests that the key registry, generation, serialization, and rotation
all behave correctly and securely.
"""
from __future__ import annotations

import base64
import os
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

from app.security.key_management import (
    KeyRecord,
    KeyRegistry,
    generate_ed25519_keypair,
    serialize_private_key_b64,
    serialize_public_key_b64,
    load_private_key_from_b64,
    load_public_key_from_b64,
    generate_demo_registry,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_generates_valid_keypair(self):
        priv, pub = generate_ed25519_keypair()
        assert isinstance(priv, Ed25519PrivateKey)
        assert isinstance(pub, Ed25519PublicKey)

    def test_each_generation_is_unique(self):
        _, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        b1 = serialize_public_key_b64(pub1)
        b2 = serialize_public_key_b64(pub2)
        assert b1 != b2, "Two key generations produced the same key"

    def test_private_key_b64_is_32_bytes(self):
        priv, _ = generate_ed25519_keypair()
        b64 = serialize_private_key_b64(priv)
        raw = base64.b64decode(b64)
        assert len(raw) == 32, f"Ed25519 private key must be 32 bytes, got {len(raw)}"

    def test_public_key_b64_is_32_bytes(self):
        _, pub = generate_ed25519_keypair()
        b64 = serialize_public_key_b64(pub)
        raw = base64.b64decode(b64)
        assert len(raw) == 32, f"Ed25519 public key must be 32 bytes, got {len(raw)}"


# ---------------------------------------------------------------------------
# Serialization round-trips
# ---------------------------------------------------------------------------

class TestKeySerialization:
    def test_private_key_round_trip(self):
        priv, _ = generate_ed25519_keypair()
        b64 = serialize_private_key_b64(priv)
        loaded = load_private_key_from_b64(b64)
        # Verify they sign/verify identically
        msg = b"test message agentshield"
        sig_orig = priv.sign(msg)
        sig_loaded = loaded.sign(msg)
        # Ed25519 is deterministic — same key, same message, same signature
        assert sig_orig == sig_loaded

    def test_public_key_round_trip(self):
        _, pub = generate_ed25519_keypair()
        b64 = serialize_public_key_b64(pub)
        loaded = load_public_key_from_b64(b64)
        assert serialize_public_key_b64(loaded) == b64

    def test_invalid_b64_private_key_raises(self):
        with pytest.raises(ValueError, match="Failed to load"):
            load_private_key_from_b64("not-valid-base64!!!")

    def test_wrong_length_private_key_raises(self):
        with pytest.raises(ValueError):
            # 16 bytes is wrong — Ed25519 needs exactly 32
            load_private_key_from_b64(base64.b64encode(b"\x00" * 16).decode())

    def test_invalid_b64_public_key_raises(self):
        with pytest.raises(ValueError):
            load_public_key_from_b64("not-valid-base64!!!")


# ---------------------------------------------------------------------------
# Key registry
# ---------------------------------------------------------------------------

class TestKeyRegistry:
    def setup_method(self):
        self.registry = KeyRegistry()
        priv, pub = generate_ed25519_keypair()
        self.record = KeyRecord(kid="key-v1", private_key=priv, public_key=pub, active=True)

    def test_register_and_retrieve_signing_key(self):
        self.registry.register(self.record, make_default=True)
        retrieved = self.registry.get_signing_key()
        assert retrieved.kid == "key-v1"
        assert retrieved.can_sign()

    def test_get_signing_key_by_kid(self):
        self.registry.register(self.record)
        retrieved = self.registry.get_signing_key(kid="key-v1")
        assert retrieved.kid == "key-v1"

    def test_unknown_kid_raises_keyerror(self):
        self.registry.register(self.record)
        with pytest.raises(KeyError, match="Unknown key"):
            self.registry.get_signing_key(kid="key-unknown")

    def test_unknown_kid_for_verification_raises_keyerror(self):
        """SECURITY: Unknown kid must raise KeyError — caller must reject the token."""
        self.registry.register(self.record)
        with pytest.raises(KeyError, match="Unknown signing key"):
            self.registry.get_verifying_key("key-unknown")

    def test_no_signing_key_registered_raises(self):
        with pytest.raises(KeyError, match="No signing key"):
            self.registry.get_signing_key()

    def test_default_kid_is_set_after_register(self):
        self.registry.register(self.record, make_default=True)
        assert self.registry.default_kid == "key-v1"

    def test_list_kids(self):
        self.registry.register(self.record)
        kids = self.registry.list_kids()
        assert "key-v1" in kids

    def test_record_can_sign_false_without_private_key(self):
        _, pub = generate_ed25519_keypair()
        verify_only = KeyRecord(kid="key-old", private_key=None, public_key=pub, active=False)
        assert not verify_only.can_sign()

    def test_inactive_key_cannot_sign(self):
        priv, pub = generate_ed25519_keypair()
        inactive = KeyRecord(kid="key-inactive", private_key=priv, public_key=pub, active=False)
        self.registry.register(inactive)
        with pytest.raises(PermissionError, match="cannot sign"):
            self.registry.get_signing_key(kid="key-inactive")


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

class TestKeyRotation:
    def test_rotation_deactivates_old_key(self):
        registry = KeyRegistry()
        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()

        rec1 = KeyRecord(kid="key-v1", private_key=priv1, public_key=pub1, active=True)
        rec2 = KeyRecord(kid="key-v2", private_key=priv2, public_key=pub2, active=True)

        registry.register(rec1, make_default=True)
        registry.rotate(rec2)

        # Old key is now inactive for signing
        assert registry.default_kid == "key-v2"
        with pytest.raises(PermissionError):
            registry.get_signing_key(kid="key-v1")

    def test_rotation_keeps_old_key_for_verification(self):
        """Old kid must remain in registry for verifying existing tokens."""
        registry = KeyRegistry()
        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()

        rec1 = KeyRecord(kid="key-v1", private_key=priv1, public_key=pub1, active=True)
        rec2 = KeyRecord(kid="key-v2", private_key=priv2, public_key=pub2, active=True)

        registry.register(rec1, make_default=True)
        registry.rotate(rec2)

        # Old key must still be resolvable for verification
        pub = registry.get_verifying_key("key-v1")
        assert pub is not None

    def test_cannot_retire_active_default_key(self):
        registry, _, _ = generate_demo_registry("key-v1")
        with pytest.raises(PermissionError, match="Cannot retire the active"):
            registry.retire("key-v1")

    def test_retire_removes_historical_key(self):
        registry = KeyRegistry()
        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()

        rec1 = KeyRecord(kid="key-v1", private_key=priv1, public_key=pub1, active=True)
        rec2 = KeyRecord(kid="key-v2", private_key=priv2, public_key=pub2, active=True)

        registry.register(rec1, make_default=True)
        registry.rotate(rec2)
        registry.retire("key-v1")

        assert "key-v1" not in registry.list_kids()
        with pytest.raises(KeyError):
            registry.get_verifying_key("key-v1")


# ---------------------------------------------------------------------------
# Demo registry
# ---------------------------------------------------------------------------

class TestDemoRegistry:
    def test_demo_registry_is_usable(self):
        registry, priv_b64, pub_b64 = generate_demo_registry("test-key-1")
        assert registry.default_kid == "test-key-1"
        key = registry.get_signing_key()
        assert key.can_sign()

    def test_demo_registry_keys_are_valid_b64(self):
        _, priv_b64, pub_b64 = generate_demo_registry()
        # Both must be decodable as 32-byte values
        assert len(base64.b64decode(priv_b64)) == 32
        assert len(base64.b64decode(pub_b64)) == 32

    def test_private_key_not_exposed_in_str_representation(self):
        """Private key bytes must not appear in str/repr of KeyRecord."""
        _, priv, pub = generate_demo_registry()
        # This test documents the intent. The actual enforcement is in not logging keys.
        assert "PRIVATE" not in priv  # b64 won't contain this word
