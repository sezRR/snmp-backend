"""Machine repository.

Every function takes a cursor as its first argument and blocks, so it is called
through `Database.run_query`, which supplies the cursor from the pool and runs
the call in the threadpool.
"""

from __future__ import annotations

from typing import Any

_COLUMNS = "mac::text AS mac, host(ipv4) AS ipv4, label, enabled, created_at, updated_at"


def insert(cur, mac: str, ipv4: str, label: str | None) -> dict[str, Any] | None:
    """Register a machine. Returns None when the MAC is already registered."""
    cur.execute(
        f"""
        INSERT INTO machines (mac, ipv4, label)
        VALUES (%s, %s, %s)
        ON CONFLICT (mac) DO NOTHING
        RETURNING {_COLUMNS}
        """,
        (mac, ipv4, label),
    )
    return cur.fetchone()


def get(cur, mac: str) -> dict[str, Any] | None:
    cur.execute(f"SELECT {_COLUMNS} FROM machines WHERE mac = %s", (mac,))
    return cur.fetchone()


def get_by_ipv4(cur, ipv4: str) -> dict[str, Any] | None:
    cur.execute(f"SELECT {_COLUMNS} FROM machines WHERE ipv4 = %s", (ipv4,))
    return cur.fetchone()


def list_all(cur, enabled_only: bool = False) -> list[dict[str, Any]]:
    cur.execute(
        f"""
        SELECT {_COLUMNS}
        FROM machines
        WHERE (%s IS FALSE OR enabled)
        ORDER BY created_at
        """,
        (enabled_only,),
    )
    return cur.fetchall()


def update(
    cur,
    mac: str,
    label: str | None,
    enabled: bool | None,
    label_given: bool,
) -> dict[str, Any] | None:
    """Patch label and/or enabled.

    `label_given` distinguishes "set the label to null" from "leave it alone",
    which a nullable value alone cannot express.
    """
    cur.execute(
        f"""
        UPDATE machines
        SET label      = CASE WHEN %s THEN %s ELSE label END,
            enabled    = COALESCE(%s, enabled),
            updated_at = now()
        WHERE mac = %s
        RETURNING {_COLUMNS}
        """,
        (label_given, label, enabled, mac),
    )
    return cur.fetchone()


def set_ipv4(cur, mac: str, ipv4: str) -> dict[str, Any] | None:
    """Follow an address change in OpenStack, which owns the IPv4."""
    cur.execute(
        f"""
        UPDATE machines
        SET ipv4 = %s, updated_at = now()
        WHERE mac = %s AND ipv4 <> %s
        RETURNING {_COLUMNS}
        """,
        (ipv4, mac, ipv4),
    )
    return cur.fetchone()


def delete(cur, mac: str) -> bool:
    """Remove a machine. Its metrics go with it, via ON DELETE CASCADE."""
    cur.execute("DELETE FROM machines WHERE mac = %s", (mac,))
    return cur.rowcount > 0
