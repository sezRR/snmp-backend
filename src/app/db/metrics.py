"""Metric repository.

Same convention as `machines`: cursor first, blocking, called through
`Database.run_query`.

Aggregates reach into the jsonb payload with `->` / `->>` plus a cast. Missing
keys yield NULL rather than an error, so a sample written before a metric
existed simply does not contribute to that metric's average — which is what
makes the jsonb column safe to evolve.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg2.extras import Json, execute_values

# max() over the disk array, tolerating a payload where `disk` is absent or is
# not an array at all.
_DISK_LATERAL = """
    LEFT JOIN LATERAL (
        SELECT max((d->>'used_percent')::double precision) AS pct
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(m.metrics->'disk') = 'array'
                 THEN m.metrics->'disk'
                 ELSE '[]'::jsonb END
        ) AS d
    ) AS disk ON TRUE
"""


def insert_many(cur, samples: list[tuple[datetime, str, dict[str, Any]]]) -> int:
    """Batch-insert samples. `Json` adapts the dict to jsonb."""
    if not samples:
        return 0
    execute_values(
        cur,
        "INSERT INTO metrics (ts, mac, metrics) VALUES %s",
        [(ts, mac, Json(metrics)) for ts, mac, metrics in samples],
    )
    return len(samples)


def list_samples(
    cur,
    macs: list[str] | None,
    since: datetime | None,
    limit: int,
) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT ts, mac::text AS mac, metrics
        FROM metrics
        WHERE (%(macs)s::text[] IS NULL OR mac::text = ANY (%(macs)s))
          AND (%(since)s::timestamptz IS NULL OR ts >= %(since)s)
        ORDER BY ts DESC
        LIMIT %(limit)s
        """,
        {"macs": macs, "since": since, "limit": limit},
    )
    return cur.fetchall()


def stats(
    cur,
    bucket: str,
    hours: float,
    macs: list[str] | None,
) -> list[dict[str, Any]]:
    cur.execute(
        f"""
        SELECT
            -- text::interval, not ::interval: psycopg2 would otherwise need a
            -- timedelta, and '15 minutes' is friendlier in a query string.
            time_bucket(%(bucket)s::text::interval, m.ts)               AS bucket,
            m.mac::text                                                 AS mac,
            count(*)                                                    AS samples,
            avg((m.metrics->'cpu'->>'usage_percent')::double precision) AS cpu_usage_percent_avg,
            max((m.metrics->'cpu'->>'usage_percent')::double precision) AS cpu_usage_percent_max,
            avg((m.metrics->'ram'->>'used_percent')::double precision)  AS ram_used_percent_avg,
            max((m.metrics->'ram'->>'used_percent')::double precision)  AS ram_used_percent_max,
            avg(disk.pct)                                               AS disk_used_percent_avg,
            max(disk.pct)                                               AS disk_used_percent_max,
            avg((m.metrics->'network'->>'rx_bps')::double precision)    AS net_rx_bps_avg,
            max((m.metrics->'network'->>'rx_bps')::double precision)    AS net_rx_bps_max,
            avg((m.metrics->'network'->>'tx_bps')::double precision)    AS net_tx_bps_avg,
            max((m.metrics->'network'->>'tx_bps')::double precision)    AS net_tx_bps_max,
            -- disk_io totals are scalars on the object, unlike the per-mount
            -- `disk` array above, so they need no lateral.
            avg((m.metrics->'disk_io'->>'read_bps')::double precision)   AS disk_read_bps_avg,
            max((m.metrics->'disk_io'->>'read_bps')::double precision)   AS disk_read_bps_max,
            avg((m.metrics->'disk_io'->>'write_bps')::double precision)  AS disk_write_bps_avg,
            max((m.metrics->'disk_io'->>'write_bps')::double precision)  AS disk_write_bps_max,
            avg((m.metrics->'disk_io'->>'read_iops')::double precision)  AS disk_read_iops_avg,
            max((m.metrics->'disk_io'->>'read_iops')::double precision)  AS disk_read_iops_max,
            avg((m.metrics->'disk_io'->>'write_iops')::double precision) AS disk_write_iops_avg,
            max((m.metrics->'disk_io'->>'write_iops')::double precision) AS disk_write_iops_max
        FROM metrics AS m
        {_DISK_LATERAL}
        WHERE m.ts > now() - (%(hours)s::double precision * INTERVAL '1 hour')
          AND (%(macs)s::text[] IS NULL OR m.mac::text = ANY (%(macs)s))
        GROUP BY bucket, m.mac
        ORDER BY bucket DESC, m.mac
        """,
        {"bucket": bucket, "hours": hours, "macs": macs},
    )
    return cur.fetchall()


def latest_per_machine(cur) -> list[dict[str, Any]]:
    """Most recent sample per machine — the cheap way, using the (mac, ts) index."""
    cur.execute(
        """
        SELECT DISTINCT ON (mac) ts, mac::text AS mac, metrics
        FROM metrics
        ORDER BY mac, ts DESC
        """
    )
    return cur.fetchall()


def counts_by_machine(cur) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT mac::text AS mac, count(*) AS samples, max(ts) AS latest
        FROM metrics
        GROUP BY mac
        ORDER BY mac
        """
    )
    return cur.fetchall()


def purge_machine(cur, mac: str, before: datetime | None) -> int:
    """Delete one machine's history, optionally only rows older than `before`."""
    cur.execute(
        """
        DELETE FROM metrics
        WHERE mac = %s
          AND (%s::timestamptz IS NULL OR ts < %s)
        """,
        (mac, before, before),
    )
    return cur.rowcount


def purge_all(cur, before: datetime | None) -> tuple[str, int | None]:
    """Delete every machine's history.

    With `before`, drops whole chunks — cheap, but chunk-granular: a chunk that
    straddles the cutoff is kept, so slightly newer data than requested may
    survive. Without it, TRUNCATE clears every chunk at once.
    """
    if before is None:
        cur.execute("TRUNCATE TABLE metrics")
        return "truncate", None
    cur.execute(
        "SELECT drop_chunks('metrics', older_than => %s::timestamptz)", (before,)
    )
    return "drop_chunks", None
