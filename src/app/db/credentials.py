"""SNMP credential repository.

Same shape as `app.db.machines`: every function takes a `Connection` first and
blocks, so it is called through `Database.run_query`.

The one convention worth stating is why `_COLUMNS` stops where it does. It
lists metadata only — no `secret`, no `key_id`. Ciphertext comes out through
`get_secret()` and nowhere else, so an ordinary read path cannot select it by
accident and no new endpoint can start returning it just by reusing the list
query. There is exactly one caller of `get_secret` outside this module
(`app.services.credentials`), which is the whole point.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

_COLUMNS = (
    "id, name, description, snmp_version, username, security_level, "
    "auth_protocol, priv_protocol, secret_version, fingerprint, "
    "created_at, updated_at"
)


def insert(
    conn: Connection,
    credential_id: UUID,
    name: str,
    description: str | None,
    snmp_version: str,
    username: str | None,
    security_level: str | None,
    auth_protocol: str | None,
    priv_protocol: str | None,
    secret: bytes,
    key_id: str,
    fingerprint: str,
) -> dict[str, Any] | None:
    """Create a profile. Returns None when the name is taken.

    The id is supplied rather than defaulted by the database: it is sealed into
    the ciphertext as additional authenticated data, so it has to be known
    before the encryption, which happens before this insert.
    """
    row = conn.execute(
        text(
            f"""
            INSERT INTO snmp_credentials (
                id, name, description, snmp_version, username, security_level,
                auth_protocol, priv_protocol, secret, key_id, fingerprint
            )
            VALUES (
                :id, :name, :description, :snmp_version, :username,
                :security_level, :auth_protocol, :priv_protocol, :secret,
                :key_id, :fingerprint
            )
            ON CONFLICT (name) DO NOTHING
            RETURNING {_COLUMNS}
            """
        ),
        {
            "id": credential_id,
            "name": name,
            "description": description,
            "snmp_version": snmp_version,
            "username": username,
            "security_level": security_level,
            "auth_protocol": auth_protocol,
            "priv_protocol": priv_protocol,
            "secret": secret,
            "key_id": key_id,
            "fingerprint": fingerprint,
        },
    ).mappings().first()
    return dict(row) if row else None


def get(conn: Connection, credential_id: UUID) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLUMNS} FROM snmp_credentials WHERE id = :id"),
            {"id": credential_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def get_by_name(conn: Connection, name: str) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLUMNS} FROM snmp_credentials WHERE name = :name"),
            {"name": name},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def get_secret(conn: Connection, credential_id: UUID) -> dict[str, Any] | None:
    """Everything needed to decrypt one profile. The only path to ciphertext."""
    row = (
        conn.execute(
            text(
                """
                SELECT id, name, snmp_version, username, security_level,
                       auth_protocol, priv_protocol, secret, key_id, secret_version
                FROM snmp_credentials
                WHERE id = :id
                """
            ),
            {"id": credential_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def list_all(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(f"SELECT {_COLUMNS} FROM snmp_credentials ORDER BY name")
    ).mappings()
    return [dict(row) for row in rows]


def list_secrets(conn: Connection) -> list[dict[str, Any]]:
    """Every row's ciphertext, for `python -m app.db.reencrypt` only."""
    rows = conn.execute(
        text(
            "SELECT id, name, secret, key_id, secret_version "
            "FROM snmp_credentials ORDER BY name"
        )
    ).mappings()
    return [dict(row) for row in rows]


def update_metadata(
    conn: Connection,
    credential_id: UUID,
    name: str | None,
    description: str | None,
    description_given: bool,
) -> dict[str, Any] | None:
    """Patch the two fields that are not part of the secret.

    `description_given` distinguishes "clear it" from "leave it alone", the same
    way `machines.update` handles `label`.
    """
    row = conn.execute(
        text(
            f"""
            UPDATE snmp_credentials
            SET name        = COALESCE(:name, name),
                description = CASE WHEN :description_given
                                   THEN :description ELSE description END,
                updated_at  = now()
            WHERE id = :id
            RETURNING {_COLUMNS}
            """
        ),
        {
            "id": credential_id,
            "name": name,
            "description": description,
            "description_given": description_given,
        },
    ).mappings().first()
    return dict(row) if row else None


def update_secret(
    conn: Connection,
    credential_id: UUID,
    snmp_version: str,
    username: str | None,
    security_level: str | None,
    auth_protocol: str | None,
    priv_protocol: str | None,
    secret: bytes,
    key_id: str,
    fingerprint: str,
) -> dict[str, Any] | None:
    """Replace the USM shape and the secret, bumping `secret_version`.

    The bump is what the sampler watches: it keys both its decrypted cache and
    its per-credential `SnmpEngine` on `(id, secret_version)`, so an edit that
    left the counter alone would keep polling with the old passphrase until the
    process restarted.
    """
    row = conn.execute(
        text(
            f"""
            UPDATE snmp_credentials
            SET snmp_version   = :snmp_version,
                username       = :username,
                security_level = :security_level,
                auth_protocol  = :auth_protocol,
                priv_protocol  = :priv_protocol,
                secret         = :secret,
                key_id         = :key_id,
                fingerprint    = :fingerprint,
                secret_version = secret_version + 1,
                updated_at     = now()
            WHERE id = :id
            RETURNING {_COLUMNS}
            """
        ),
        {
            "id": credential_id,
            "snmp_version": snmp_version,
            "username": username,
            "security_level": security_level,
            "auth_protocol": auth_protocol,
            "priv_protocol": priv_protocol,
            "secret": secret,
            "key_id": key_id,
            "fingerprint": fingerprint,
        },
    ).mappings().first()
    return dict(row) if row else None


def rewrap(
    conn: Connection,
    credential_id: UUID,
    secret: bytes,
    key_id: str,
    fingerprint: str,
) -> bool:
    """Re-encrypt one row under a new key. Same plaintext, so no version bump.

    `secret_version` is untouched on purpose: nothing about the credential
    changed, and bumping it would invalidate every sampler cache and force a
    fleet-wide re-localization of USM keys for what is bookkeeping.
    """
    result = conn.execute(
        text(
            """
            UPDATE snmp_credentials
            SET secret = :secret, key_id = :key_id, fingerprint = :fingerprint
            WHERE id = :id
            """
        ),
        {
            "id": credential_id,
            "secret": secret,
            "key_id": key_id,
            "fingerprint": fingerprint,
        },
    )
    return result.rowcount > 0


def bound_macs(conn: Connection, credential_id: UUID) -> list[str]:
    """Which machines use this profile — the body of the 409 on delete."""
    rows = conn.execute(
        text(
            "SELECT CAST(mac AS text) AS mac FROM machines "
            "WHERE credential_id = :id ORDER BY mac"
        ),
        {"id": credential_id},
    ).mappings()
    return [row["mac"] for row in rows]


def delete(conn: Connection, credential_id: UUID) -> bool:
    """Remove a profile. The FK is RESTRICT, so a bound one raises instead."""
    result = conn.execute(
        text("DELETE FROM snmp_credentials WHERE id = :id"), {"id": credential_id}
    )
    return result.rowcount > 0
