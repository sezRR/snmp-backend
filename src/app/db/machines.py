from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

_COLUMNS = (
    "CAST(mac AS text) AS mac, host(ipv4) AS ipv4, label, enabled, external, "
    "credential_id, created_at, updated_at"
)

# The collector's view: machine plus its credential's identity and secret
# counter, which are the sampler's cache key. Joined, not denormalised, so an
# edit lands on the next tick. Spelled out because `created_at`/`updated_at`
# exist on both tables.
_POLL_COLUMNS = (
    "CAST(m.mac AS text) AS mac, host(m.ipv4) AS ipv4, m.label, m.enabled, "
    "m.external, m.credential_id, m.created_at, m.updated_at, "
    "c.name AS credential_name, c.secret_version AS credential_secret_version"
)


def insert(
    conn: Connection, mac: str, ipv4: str, label: str | None, external: bool = False
) -> dict[str, Any] | None:
    """Register a machine. Returns None when the MAC is already registered."""
    row = conn.execute(
        text(
            f"""
            INSERT INTO machines (mac, ipv4, label, external)
            VALUES (:mac, :ipv4, :label, :external)
            ON CONFLICT (mac) DO NOTHING
            RETURNING {_COLUMNS}
            """
        ),
        {"mac": mac, "ipv4": ipv4, "label": label, "external": external},
    ).mappings().first()
    return dict(row) if row else None


def get(conn: Connection, mac: str) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLUMNS} FROM machines WHERE mac = :mac"), {"mac": mac}
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def get_by_ipv4(conn: Connection, ipv4: str) -> dict[str, Any] | None:
    row = (
        conn.execute(
            text(f"SELECT {_COLUMNS} FROM machines WHERE ipv4 = :ipv4"), {"ipv4": ipv4}
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def list_all(conn: Connection, enabled_only: bool = False) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"""
            SELECT {_COLUMNS}
            FROM machines
            WHERE (:enabled_only IS FALSE OR enabled)
            ORDER BY created_at
            """
        ),
        {"enabled_only": enabled_only},
    ).mappings()
    return [dict(row) for row in rows]


def list_for_polling(conn: Connection) -> list[dict[str, Any]]:
    """The enabled machines, each with the credential it is bound to.

    A LEFT JOIN, not an inner one: an unbound machine still comes back so the
    collector can record "no credential bound" against it. Dropping it from the
    result would make a machine that is enabled and registered simply vanish
    from /admin/collector, which is the least helpful way to report a
    misconfiguration.
    """
    rows = conn.execute(
        text(
            f"""
            SELECT {_POLL_COLUMNS}
            FROM machines m
            LEFT JOIN snmp_credentials c ON c.id = m.credential_id
            WHERE m.enabled
            ORDER BY m.created_at
            """
        )
    ).mappings()
    return [dict(row) for row in rows]


def bind_credential(
    conn: Connection, mac: str, credential_id: UUID
) -> dict[str, Any] | None:
    row = conn.execute(
        text(
            f"""
            UPDATE machines
            SET credential_id = :credential_id, updated_at = now()
            WHERE mac = :mac
            RETURNING {_COLUMNS}
            """
        ),
        {"mac": mac, "credential_id": credential_id},
    ).mappings().first()
    return dict(row) if row else None


def unbind_credential(conn: Connection, mac: str) -> dict[str, Any] | None:
    row = conn.execute(
        text(
            f"""
            UPDATE machines
            SET credential_id = NULL, updated_at = now()
            WHERE mac = :mac
            RETURNING {_COLUMNS}
            """
        ),
        {"mac": mac},
    ).mappings().first()
    return dict(row) if row else None


def bind_unbound(conn: Connection, credential_id: UUID) -> int:
    """Bind every machine that has no credential. Used once, at bootstrap."""
    result = conn.execute(
        text(
            "UPDATE machines SET credential_id = :credential_id, updated_at = now() "
            "WHERE credential_id IS NULL"
        ),
        {"credential_id": credential_id},
    )
    return result.rowcount


def update(
    conn: Connection,
    mac: str,
    label: str | None,
    enabled: bool | None,
    ipv4: str | None,
    label_given: bool,
) -> dict[str, Any] | None:
    """Patch label, enabled and/or ipv4.

    `label_given` distinguishes "set the label to null" from "leave it alone",
    which a nullable value alone cannot express. The caller decides whether an
    address patch is allowed — that depends on who owns the address.
    """
    row = conn.execute(
        text(
            f"""
            UPDATE machines
            SET label      = CASE WHEN :label_given THEN :label ELSE label END,
                enabled    = COALESCE(:enabled, enabled),
                ipv4       = COALESCE(CAST(:ipv4 AS inet), ipv4),
                updated_at = now()
            WHERE mac = :mac
            RETURNING {_COLUMNS}
            """
        ),
        {
            "label_given": label_given,
            "label": label,
            "enabled": enabled,
            "ipv4": ipv4,
            "mac": mac,
        },
    ).mappings().first()
    return dict(row) if row else None


def set_ipv4(conn: Connection, mac: str, ipv4: str) -> dict[str, Any] | None:
    """Follow an address change in OpenStack, which owns the IPv4."""
    row = conn.execute(
        text(
            f"""
            UPDATE machines
            SET ipv4 = CAST(:ipv4 AS inet), updated_at = now()
            WHERE mac = :mac AND ipv4 <> CAST(:ipv4 AS inet)
            RETURNING {_COLUMNS}
            """
        ),
        {"ipv4": ipv4, "mac": mac},
    ).mappings().first()
    return dict(row) if row else None


def mark_managed(conn: Connection, mac: str) -> bool:
    """Clear the external flag once OpenStack turns out to know the MAC.

    A machine registered as external while the lookup was unavailable, or one
    later imported into the fleet, would otherwise keep claiming to be outside
    OpenStack while its record is right there.
    """
    result = conn.execute(
        text(
            "UPDATE machines SET external = false, updated_at = now() "
            "WHERE mac = :mac AND external"
        ),
        {"mac": mac},
    )
    return result.rowcount > 0


def delete(conn: Connection, mac: str) -> bool:
    """Remove a machine. Its metrics go with it, via ON DELETE CASCADE."""
    result = conn.execute(
        text("DELETE FROM machines WHERE mac = :mac"), {"mac": mac}
    )
    return result.rowcount > 0
