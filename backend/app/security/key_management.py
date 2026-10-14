"""
AgentShield V2 — Key Management

Owner: Pavan (specification) | Girish (integration with capability signing)

Handles:
- Ed25519 key generation and serialization
- Public key registry (kid -> public key)
- Key rotation support
- Environment-based key loading

Security rules (ADR-002, THREAT_MODEL §T18):
- Private keys are NEVER logged, returned in responses, or in frontend.
- Keys are loaded from environment variables only.
- Unknown kid -> reject immediately.
- Rotation: old kid stays in registry until all tokens signed with it expire.
"""
from __future__ import annotations

import base64
import os
import logging
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

log = logging.getLogger(__name__)


@dataclass
class KeyRecord:
    kid: str
    private_key: Optional[Ed25519PrivateKey]  # None = verify-only record
    public_key: Ed25519PublicKey
    active: bool = True

    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def can_sign(self) -> bool:
        return self.private_key is not None and self.active


class KeyRegistry:
    """Registry of all known signing keys. Supports rotation and historical verification."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}
        self._default_kid: Optional[str] = None

    def register(self, record: KeyRecord, make_default: bool = False) -> None:
        self._keys[record.kid] = record
        if make_default or (self._default_kid is None and record.can_sign()):
            self._default_kid = record.kid

    def get_signing_key(self, kid: Optional[str] = None) -> KeyRecord:
        if kid is None:
            kid = self._default_kid
        if kid is None:
            raise KeyError("No signing key registered")
        record = self._keys.get(kid)
        if record is None:
            raise KeyError(f"Unknown key kid={kid!r}")
        if not record.can_sign():
            raise PermissionError(f"Key kid={kid!r} cannot sign")
        return record

    def get_verifying_key(self, kid: str) -> Ed25519PublicKey:
        """Resolve public key from kid. Raises KeyError for unknown kid."""
        record = self._keys.get(kid)
        if record is None:
            raise KeyError(f"Unknown signing key kid={kid!r} — token rejected")
        return record.public_key

    def rotate(self, new_record: KeyRecord) -> None:
        """Rotate to a new key. Old key stays for verification of existing tokens."""
        if self._default_kid:
            old = self._keys.get(self._default_kid)
            if old:
                self._keys[self._default_kid] = KeyRecord(
                    kid=old.kid,
                    private_key=old.private_key,
                    public_key=old.public_key,
                    active=False,
                )
                log.info("Deactivated old signing key kid=%s", self._default_kid)
        self.register(new_record, make_default=True)
        log.info("Rotated to new signing key kid=%s", new_record.kid)

    def retire(self, kid: str) -> None:
        """Remove a historical key. Only after all tokens signed with it have expired."""
        if kid not in self._keys:
            raise KeyError(f"Cannot retire unknown kid={kid!r}")
        if kid == self._default_kid:
            raise PermissionError(f"Cannot retire the active default key kid={kid!r}")
        del self._keys[kid]

    def list_kids(self) -> list[str]:
        return list(self._keys.keys())

    @property
    def default_kid(self) -> Optional[str]:
        return self._default_kid


# ---------------------------------------------------------------------------
# Key generation helpers
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_private_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


def serialize_public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_private_key_from_b64(b64_str: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64_str))
    except Exception as e:
        raise ValueError(f"Failed to load Ed25519 private key: {e}") from e


def load_public_key_from_b64(b64_str: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64_str))
    except Exception as e:
        raise ValueError(f"Failed to load Ed25519 public key: {e}") from e


def load_registry_from_env() -> KeyRegistry:
    """
    Load key registry from environment variables.

    Required:
        CAPABILITY_SIGNING_KEY_PRIVATE_B64
        CAPABILITY_SIGNING_KEY_ID  (default: key-v1)

    Optional:
        CAPABILITY_PUBLIC_KEYS  — comma-separated "kid:b64pubkey" for historical keys
    """
    registry = KeyRegistry()
    private_b64 = os.environ.get("CAPABILITY_SIGNING_KEY_PRIVATE_B64", "").strip()
    kid = os.environ.get("CAPABILITY_SIGNING_KEY_ID", "key-v1").strip()

    if not private_b64:
        raise EnvironmentError(
            "CAPABILITY_SIGNING_KEY_PRIVATE_B64 is not set. "
            "Generate with: python -m app.security.key_management"
        )

    private_key = load_private_key_from_b64(private_b64)
    registry.register(
        KeyRecord(kid=kid, private_key=private_key,
                  public_key=private_key.public_key(), active=True),
        make_default=True,
    )

    for entry in os.environ.get("CAPABILITY_PUBLIC_KEYS", "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        h_kid, pub_b64 = entry.split(":", 1)
        h_kid = h_kid.strip()
        if h_kid == kid:
            continue
        try:
            pub_key = load_public_key_from_b64(pub_b64.strip())
            registry.register(KeyRecord(kid=h_kid, private_key=None,
                                        public_key=pub_key, active=False))
        except ValueError as e:
            log.warning("Skipping invalid historical key kid=%s: %s", h_kid, e)

    return registry


def generate_demo_registry(kid: str = "key-v1") -> tuple["KeyRegistry", str, str]:
    """Generate a fresh registry for tests. Returns (registry, priv_b64, pub_b64)."""
    priv, pub = generate_ed25519_keypair()
    registry = KeyRegistry()
    registry.register(KeyRecord(kid=kid, private_key=priv, public_key=pub, active=True),
                      make_default=True)
    return registry, serialize_private_key_b64(priv), serialize_public_key_b64(pub)


if __name__ == "__main__":
    """Generate a key pair for .env: python -m app.security.key_management"""
    import sys
    kid = sys.argv[1] if len(sys.argv) > 1 else "key-v1"
    priv, pub = generate_ed25519_keypair()
    print(f"CAPABILITY_SIGNING_KEY_PRIVATE_B64={serialize_private_key_b64(priv)}")
    print(f"CAPABILITY_SIGNING_KEY_ID={kid}")
    print(f"# Public:  CAPABILITY_PUBLIC_KEYS={kid}:{serialize_public_key_b64(pub)}")
