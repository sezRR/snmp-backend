"""Machine repository.

Every function takes a `Connection` as its first argument and blocks, so it is
called through `Database.run_query`, which supplies the connection from the pool
and runs the call in the threadpool.

The SQL is hand-written rather than built from the ORM mapping in `db.tables`:
`macaddr` and `inet` need casts on the way out (`mac::text`, `host(ipv4)`) for
the Pydantic models to validate them, and `UPDATE ... RETURNING` with a
CASE-guarded patch has no natural ORM spelling. Note that `text()` reads `:` as
a bind marker, so every cast is written `CAST(x AS type)`.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

_COLUMNS = (
    "CAST(mac AS text) AS mac, host(ipv4) AS ipv4, label, enabled, external, "
    "created_at, updated_at"
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
