"""Metric repository.

Same convention as `machines`: connection first, blocking, called through
`Database.run_query`.

Every metric is its own column. It used to be one jsonb blob, and the aggregates
reached into it with `->` / `->>` plus a cast; the payload is now flattened
before it is written (`app.services.snmp.flatten`). The columns are all
nullable, which preserves the property that made jsonb safe to evolve: a sample
taken before a metric existed, or one whose SNMP walk failed, contributes
nothing to that metric's average rather than erroring.

Reads past the raw retention window are answered from the continuous aggregates
instead — see `app.db.rollups` for the routing and why the rollups store sums
and counts rather than averages.

Casts are spelled `CAST(x AS type)` throughout rather than `x::type`, because
SQLAlchemy's `text()` reads a bare `:` as the start of a bind parameter and
would swallow the type name.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import insert, text
from sqlalchemy.engine import Connection

from app.db import rollups
from app.db.tables import metrics as metrics_table

# Derived from the table rather than restated, so the two can never drift. The
# order is the table's, which is also the order `app.services.snmp.flatten`
# lists them in; `tests/test_flatten.py` asserts the two agree.
METRIC_COLUMNS: tuple[str, ...] = tuple(
    column.name for column in metrics_table.columns if column.name not in ("ts", "mac")
)

_SELECT_COLUMNS = ", ".join(METRIC_COLUMNS)


def insert_many(conn: Connection, samples: list[dict[str, Any]]) -> int:
    """Batch-insert flattened samples.

    Each dict is `{"ts": ..., "mac": ..., **flatten(payload)}`. Goes through the
    Core table so the engine's `executemany_mode="values_plus_batch"` folds the
    whole batch into one `execute_values` round trip — the same shape the
    collector had before.
    """
    if not samples:
        return 0
    conn.execute(insert(metrics_table), samples)
    return len(samples)


def list_samples(
    conn: Connection,
    macs: list[str] | None,
    since: datetime | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            f"""
            SELECT ts, CAST(mac AS text) AS mac, {_SELECT_COLUMNS}
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
    raw_hours: float = rollups.RAW_HOURS,
    rollup_1m_hours: float = rollups.ROLLUP_1M_HOURS,
) -> list[dict[str, Any]]:
    """`time_bucket` aggregates, read from whichever source still has the range.

    The shape of the result does not depend on the source: the caller asks for a
    window and a bucket width and gets the same columns back either way.
    """
    source = rollups.pick_source(hours, raw_hours, rollup_1m_hours)
    time_column = rollups.SOURCE_TIME_COLUMN[source]
    rows = conn.execute(
        text(
            f"""
            SELECT
                -- CAST to text first, not straight to interval: the driver would
                -- otherwise want a timedelta, and '15 minutes' is friendlier in
                -- a query string.
                --
                -- greatest() floors the bucket at what the source can actually
                -- resolve. Asking a one-hour rollup for five-minute buckets does
                -- not fail, it returns one populated bucket in twelve — which a
                -- chart draws as an outage rather than as a resolution limit.
                time_bucket(
                    greatest(
                        CAST(CAST(:bucket AS text) AS interval),
                        CAST(CAST(:min_bucket AS text) AS interval)
                    ),
                    m.{time_column}
                ) AS bucket,
                CAST(m.mac AS text) AS mac,
                {rollups.SOURCE_SAMPLES[source]} AS samples,
                {rollups.stats_projection(source)}
            FROM {source} AS m
            WHERE m.{time_column} > now() - (CAST(:hours AS double precision) * INTERVAL '1 hour')
              AND (CAST(:macs AS text[]) IS NULL
                   OR CAST(m.mac AS text) = ANY (CAST(:macs AS text[])))
            -- Grouped and ordered by position, not by the `bucket` alias. A
            -- rollup source has its own column called `bucket`, and on that
            -- ambiguity Postgres resolves GROUP BY to the *input* column --
            -- which would group by the source's own minute or hour bucket and
            -- silently ignore the width the caller asked for. ORDER BY resolves
            -- the other way, to the output column, so spelling either as a name
            -- makes the two disagree. Ordinals mean the same thing in both.
            GROUP BY 1, 2
            ORDER BY 1 DESC, 2
            """
        ),
        {
            "bucket": bucket,
            "min_bucket": rollups.SOURCE_MIN_BUCKET[source],
            "hours": hours,
            "macs": macs,
        },
    ).mappings()
    return [dict(row) for row in rows]


def latest_per_machine(conn: Connection) -> list[dict[str, Any]]:
    """Most recent sample per machine, off the (mac, ts DESC) index.

    The table alias is what makes that true. `mac` is projected as text, so an
    unqualified `ORDER BY mac` resolves to that output column rather than to the
    macaddr it was cast from — and a sort key of `(mac)::text` matches no index,
    which turns this into a full scan and an on-disk sort of the whole retention
    window to return one row per machine. Qualified, it is a SkipScan per chunk.
    """
    rows = conn.execute(
        text(
            f"""
            SELECT DISTINCT ON (m.mac) m.ts, CAST(m.mac AS text) AS mac, {_SELECT_COLUMNS}
            FROM metrics AS m
            ORDER BY m.mac, m.ts DESC
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

    Neither touches the continuous aggregates, which keep their own copy of the
    history at coarser resolution. Dropping those is a retention setting, not a
    purge.
    """
    if before is None:
        conn.execute(text("TRUNCATE TABLE metrics"))
        return "truncate", None
    conn.execute(
        text("SELECT drop_chunks('metrics', older_than => CAST(:before AS timestamptz))"),
        {"before": before},
    )
    return "drop_chunks", None
