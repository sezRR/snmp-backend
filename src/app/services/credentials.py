from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from app.db import credentials as credentials_repo
from app.db.pool import Database
from app.models.credential import (
    AuthProtocol,
    PrivProtocol,
    ResolvedCredential,
    SecurityLevel,
    SnmpVersion,
)
from app.security.crypto import CredentialCipher, CredentialCryptoError

log = logging.getLogger(__name__)


class CredentialNotFound(LookupError):
    """The machine names a credential that is no longer there."""


def resolve_row(cipher: CredentialCipher, row: dict[str, Any]) -> ResolvedCredential:
    """Turn a `get_secret` row into a usable credential. Decrypts."""
    payload = cipher.decrypt(
        row["id"], row["secret_version"], row["key_id"], bytes(row["secret"])
    )
    snmp_version = SnmpVersion(row["snmp_version"])
    return ResolvedCredential(
        id=row["id"],
        name=row["name"],
        secret_version=row["secret_version"],
        snmp_version=snmp_version,
        community=payload.get("community"),
        username=row["username"],
        security_level=(
            SecurityLevel(row["security_level"]) if row["security_level"] else None
        ),
        auth_protocol=(
            AuthProtocol(row["auth_protocol"]) if row["auth_protocol"] else None
        ),
        priv_protocol=(
            PrivProtocol(row["priv_protocol"]) if row["priv_protocol"] else None
        ),
        auth_passphrase=payload.get("auth"),
        priv_passphrase=payload.get("priv"),
    )


class CredentialCache:
    """Fetch-and-decrypt, memoised on `(credential_id, secret_version)`."""

    def __init__(self, db: Database, cipher: CredentialCipher) -> None:
        self._db = db
        self._cipher = cipher
        self._entries: dict[tuple[UUID, int], ResolvedCredential] = {}
        # Machines sampled together commonly share a profile; without this the
        # first tick after an edit decrypts once per machine.
        self._locks: dict[tuple[UUID, int], asyncio.Lock] = {}

    async def resolve(
        self, credential_id: UUID, secret_version: int
    ) -> ResolvedCredential:
        key = (credential_id, secret_version)
        cached = self._entries.get(key)
        if cached is not None:
            return cached

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Another waiter may have filled it while this one queued.
            cached = self._entries.get(key)
            if cached is not None:
                return cached

            row = await self._db.run_query(credentials_repo.get_secret, credential_id)
            if row is None:
                raise CredentialNotFound(
                    f"credential {credential_id} no longer exists"
                )
            resolved = resolve_row(self._cipher, row)
            if resolved.secret_version != secret_version:
                # Edited between the machine list and this fetch: cache what was
                # actually read.
                log.info(
                    "credential %s changed while resolving (v%s -> v%s)",
                    resolved.name,
                    secret_version,
                    resolved.secret_version,
                )
            self._entries[resolved.cache_key] = resolved
            self._prune(resolved.id, resolved.secret_version)
            return resolved

    def _prune(self, credential_id: UUID, keep_version: int) -> None:
        """Drop superseded versions of one credential, and their locks."""
        stale = [
            key
            for key in self._entries
            if key[0] == credential_id and key[1] != keep_version
        ]
        for key in stale:
            del self._entries[key]
            self._locks.pop(key, None)

    def forget(self, credential_id: UUID) -> None:
        """Drop every version of a credential — it was deleted."""
        for key in [k for k in self._entries if k[0] == credential_id]:
            del self._entries[key]
            self._locks.pop(key, None)


__all__ = [
    "CredentialCache",
    "CredentialCryptoError",
    "CredentialNotFound",
    "resolve_row",
]
