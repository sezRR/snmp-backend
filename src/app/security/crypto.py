"""Encryption for stored SNMP credentials.

Unlike a password, an SNMP passphrase has to come back out: pysnmp needs the
plaintext at poll time to localize a USM key. So this is encryption with a key
ring, not hashing — `users.password_hash` is the wrong model to copy here, and
copying it would produce credentials the collector cannot use.

What that buys and what it does not: the ciphertext is useless to anyone who
walks off with a `pg_dump`, a replica, or a backup. It is *not* protection
against a compromised app container, which by construction holds the key in its
environment. Treat this as raising the cost of a database-only breach, and
protect access to `.env` and the container runtime.

Three details are load-bearing:

* **Key ring, not key.** Every row records the `key_id` it was encrypted under,
  so a rotation adds a key, flips the active id, and lets
  `python -m app.db.reencrypt` walk the rows at its leisure. Rows still on the
  old key keep decrypting throughout.
* **AAD binds the row to its own ciphertext.** The additional authenticated
  data is `credential_id|key_id|secret_version`, so a blob lifted from one row
  into another fails to decrypt rather than silently authenticating the
  collector to a host as the wrong principal — which, with reusable profiles, is
  exactly the confusion worth making impossible.
* **The fingerprint is stored, not derived on read.** It exists so a UI can tell
  two profiles apart without seeing either secret, and computing it on demand
  would mean decrypting every row of every list response.
"""

from __future__ import annotations

import hmac
import json
import os
from hashlib import sha256
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Settings

# 96 bits, the size AES-GCM is specified around: anything else forces an extra
# GHASH pass and buys nothing.
NONCE_BYTES = 12

# Domain separation, so the fingerprint HMAC can never collide with any other
# use of the same key material.
_FINGERPRINT_LABEL = b"snmp-credential-fingerprint-v1"


class CredentialCryptoError(RuntimeError):
    """The key ring cannot serve this row: key missing, or ciphertext invalid."""


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Stable bytes for a secret payload.

    Sorted keys and no incidental whitespace, so the same secrets always produce
    the same fingerprint regardless of how the dict was built.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class CredentialCipher:
    """AES-256-GCM over the key ring in `Settings`."""

    def __init__(self, ring: dict[str, bytes], active_key_id: str) -> None:
        self._ring = ring
        self._active_key_id = active_key_id

    @classmethod
    def from_settings(cls, settings: Settings) -> CredentialCipher:
        return cls(settings.credential_key_ring, settings.snmp_credential_active_key)

    @property
    def active_key_id(self) -> str:
        if not self._active_key_id or self._active_key_id not in self._ring:
            raise CredentialCryptoError(
                "no active credential key is configured; set "
                "SNMP_CREDENTIAL_KEYS and SNMP_CREDENTIAL_ACTIVE_KEY"
            )
        return self._active_key_id

    @property
    def usable(self) -> bool:
        """Whether anything can be encrypted or decrypted at all."""
        return bool(self._ring)

    def _key(self, key_id: str) -> bytes:
        material = self._ring.get(key_id)
        if material is None:
            raise CredentialCryptoError(
                f"credential is encrypted under key {key_id!r}, which is not in "
                "SNMP_CREDENTIAL_KEYS — restore that key to the ring, or delete "
                "and re-enter the credential"
            )
        return material

    @staticmethod
    def _aad(credential_id: UUID, key_id: str, secret_version: int) -> bytes:
        return f"{credential_id}|{key_id}|{secret_version}".encode()

    def encrypt(
        self, credential_id: UUID, secret_version: int, payload: dict[str, Any]
    ) -> tuple[bytes, str]:
        """Returns `(nonce ‖ ciphertext, key_id)`, under the active key."""
        key_id = self.active_key_id
        nonce = os.urandom(NONCE_BYTES)
        blob = AESGCM(self._key(key_id)).encrypt(
            nonce,
            canonical_payload(payload),
            self._aad(credential_id, key_id, secret_version),
        )
        return nonce + blob, key_id

    def decrypt(
        self, credential_id: UUID, secret_version: int, key_id: str, blob: bytes
    ) -> dict[str, Any]:
        if len(blob) <= NONCE_BYTES:
            raise CredentialCryptoError(
                f"credential {credential_id} has a truncated ciphertext"
            )
        try:
            plaintext = AESGCM(self._key(key_id)).decrypt(
                blob[:NONCE_BYTES],
                blob[NONCE_BYTES:],
                self._aad(credential_id, key_id, secret_version),
            )
        except InvalidTag as exc:
            # Either the wrong key, or the row's identity no longer matches what
            # was sealed into it. Both mean "do not use this", and neither is
            # worth distinguishing to the caller.
            raise CredentialCryptoError(
                f"credential {credential_id} failed authentication: wrong key, or "
                "the stored ciphertext does not belong to this row"
            ) from exc
        return json.loads(plaintext)

    def fingerprint(self, payload: dict[str, Any]) -> str:
        """A short, stable tag for a secret payload. Not reversible.

        Keyed with the active key so it is meaningless outside this deployment —
        a leaked fingerprint on its own confirms nothing about a passphrase.
        Truncated to 8 bytes, which is plenty to tell two profiles apart and too
        short to be worth attacking.
        """
        key = hmac.new(
            self._key(self.active_key_id), _FINGERPRINT_LABEL, sha256
        ).digest()
        return hmac.new(key, canonical_payload(payload), sha256).hexdigest()[:16]
