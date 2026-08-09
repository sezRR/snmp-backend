"""Metric repository.

Same convention as `machines`: connection first, blocking, called through
`Database.run_query`.

Aggregates reach into the jsonb payload with `->` / `->>` plus a cast. Missing
keys yield NULL rather than an error, so a sample written before a metric
existed simply does not contribute to that metric's average — which is what
makes the jsonb column safe to evolve.

Casts are spelled `CAST(x AS type)` throughout rather than `x::type`, because
SQLAlchemy's `text()` reads a bare `:` as the start of a bind parameter and
would swallow the type name.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import insert, text
from sqlalchemy.engine import Connection

from app.db.tables import metrics as metrics_table

# max() over the disk array, tolerating a payload where `disk` is absent or is
# not an array at all.
_DISK_LATERAL = """
    LEFT JOIN LATERAL (
        SELECT max(CAST(d->>'used_percent' AS double precision)) AS pct
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(m.metrics->'disk') = 'array'
                 THEN m.metrics->'disk'
                 ELSE CAST('[]' AS jsonb) END
        ) AS d
    ) AS disk ON TRUE
"""


def insert_many(
    conn: Connection, samples: list[tuple[datetime, str, dict[str, Any]]]
) -> int:
    """Batch-insert samples.

    Goes through the Core table so the JSONB column adapts each dict, and so the
    engine's `executemany_mode="values_plus_batch"` folds the whole batch into
    one `execute_values` round trip — the same shape the collector had before.
    """
    if not samples:
        return 0
    conn.execute(
        insert(metrics_table),
        [{"ts": ts, "mac": mac, "metrics": payload} for ts, mac, payload in samples],
    )
    return len(samples)


def list_samples(
    conn: Connection,
    macs: list[str] | None,
    since: datetime | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            """
            SELECT ts, CAST(mac AS text) AS mac, metrics
            FROM metrics
            WHERE (CAST(:macs AS text[]) IS NULL
                   OR CAST(mac AS text) = ANY (CAST(:macs AS text[])))
              AND (CAST(:since AS timestamptz) IS NULL
                   OR ts >= CAST(:since AS timestamptz))
            ORDER BY ts DESC
            LIMIT :limit
            """
        ),
        {"macs": macs, "since": since, "limit": limit},
    ).mappings()
    return [dict(row) for row in rows]


def stats(
    conn: Connection,
    bucket: str,
    hours: float,
    macs: list[str] | None,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"""
            SELECT
                -- CAST to text first, not straight to interval: the driver would
                -- otherwise want a timedelta, and '15 minutes' is friendlier in
                -- a query string.
                time_bucket(CAST(CAST(:bucket AS text) AS interval), m.ts)               AS bucket,
                CAST(m.mac AS text)                                                      AS mac,
                count(*)                                                                 AS samples,
                avg(CAST(m.metrics->'cpu'->>'usage_percent' AS double precision))        AS cpu_usage_percent_avg,
                max(CAST(m.metrics->'cpu'->>'usage_percent' AS double precision))        AS cpu_usage_percent_max,
                avg(CAST(m.metrics->'ram'->>'used_percent' AS double precision))         AS ram_used_percent_avg,
                max(CAST(m.metrics->'ram'->>'used_percent' AS double precision))         AS ram_used_percent_max,
                avg(disk.pct)                                                            AS disk_used_percent_avg,
                max(disk.pct)                                                            AS disk_used_percent_max,
                avg(CAST(m.metrics->'network'->>'rx_bps' AS double precision))           AS net_rx_bps_avg,
                max(CAST(m.metrics->'network'->>'rx_bps' AS double precision))           AS net_rx_bps_max,
                avg(CAST(m.metrics->'network'->>'tx_bps' AS double precision))           AS net_tx_bps_avg,
                max(CAST(m.metrics->'network'->>'tx_bps' AS double precision))           AS net_tx_bps_max,
                -- disk_io totals are scalars on the object, unlike the per-mount
                -- `disk` array above, so they need no lateral.
                avg(CAST(m.metrics->'disk_io'->>'read_bps' AS double precision))         AS disk_read_bps_avg,
                max(CAST(m.metrics->'disk_io'->>'read_bps' AS double precision))         AS disk_read_bps_max,
                avg(CAST(m.metrics->'disk_io'->>'write_bps' AS double precision))        AS disk_write_bps_avg,
                max(CAST(m.metrics->'disk_io'->>'write_bps' AS double precision))        AS disk_write_bps_max,
                avg(CAST(m.metrics->'disk_io'->>'read_iops' AS double precision))        AS disk_read_iops_avg,
                max(CAST(m.metrics->'disk_io'->>'read_iops' AS double precision))        AS disk_read_iops_max,
                avg(CAST(m.metrics->'disk_io'->>'write_iops' AS double precision))       AS disk_write_iops_avg,
                max(CAST(m.metrics->'disk_io'->>'write_iops' AS double precision))       AS disk_write_iops_max
            FROM metrics AS m
            {_DISK_LATERAL}
            WHERE m.ts > now() - (CAST(:hours AS double precision) * INTERVAL '1 hour')
              AND (CAST(:macs AS text[]) IS NULL
                   OR CAST(m.mac AS text) = ANY (CAST(:macs AS text[])))
            GROUP BY bucket, m.mac
            ORDER BY bucket DESC, m.mac
            """
        ),
        {"bucket": bucket, "hours": hours, "macs": macs},
    ).mappings()
    return [dict(row) for row in rows]


def latest_per_machine(conn: Connection) -> list[dict[str, Any]]:
    """Most recent sample per machine — the cheap way, using the (mac, ts) index."""
    rows = conn.execute(
        text(
            """
            SELECT DISTINCT ON (mac) ts, CAST(mac AS text) AS mac, metrics
            FROM metrics
            ORDER BY mac, ts DESC
            """
        )
    ).mappings()
    return [dict(row) for row in rows]


def counts_by_machine(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            """
            SELECT CAST(mac AS text) AS mac, count(*) AS samples, max(ts) AS latest
            FROM metrics
            GROUP BY mac
            ORDER BY mac
            """
        )
    ).mappings()
    return [dict(row) for row in rows]


def purge_machine(conn: Connection, mac: str, before: datetime | None) -> int:
    """Delete one machine's history, optionally only rows older than `before`."""
    result = conn.execute(
        text(
            """
            DELETE FROM metrics
            WHERE mac = :mac
              AND (CAST(:before AS timestamptz) IS NULL
                   OR ts < CAST(:before AS timestamptz))
            """
        ),
        {"mac": mac, "before": before},
    )
    return result.rowcount


def purge_all(conn: Connection, before: datetime | None) -> tuple[str, int | None]:
    """Delete every machine's history.

    With `before`, drops whole chunks — cheap, but chunk-granular: a chunk that
    straddles the cutoff is kept, so slightly newer data than requested may
    survive. Without it, TRUNCATE clears every chunk at once.
    """
    if before is None:
        conn.execute(text("TRUNCATE TABLE metrics"))
        return "truncate", None
    conn.execute(
        text("SELECT drop_chunks('metrics', older_than => CAST(:before AS timestamptz))"),
        {"before": before},
    )
    return "drop_chunks", None
