from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import insert, text
from sqlalchemy.engine import Connection

from app.db import rollups
from app.db.tables import metrics as metrics_table

# Derived from the table so the two cannot drift; `tests/test_flatten.py`
# asserts the order matches `app.services.snmp.flatten`.
METRIC_COLUMNS: tuple[str, ...] = tuple(
    column.name for column in metrics_table.columns if column.name not in ("ts", "mac")
)

_SELECT_COLUMNS = ", ".join(METRIC_COLUMNS)

_ROLLUP_SOURCES: tuple[tuple[str, str], ...] = (
    ("metrics_1m", "bucket"),
    ("metrics_1h", "bucket"),
)


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
    source: str,
    bucket: str,
    start: datetime,
    end: datetime,
    macs: list[str] | None,
) -> list[dict[str, Any]]:
    """`time_bucket` aggregates over one `[start, end)` window.

    Which source still holds that window is the caller's call — it is a question
    about the configured retentions, which live in settings, not here. The shape
    of the result does not depend on the answer: the caller asks for a window
    and a bucket width and gets the same columns back either way.
    """
    time_column = rollups.SOURCE_TIME_COLUMN[source]
    rows = conn.execute(
        text(
            f"""
            SELECT
                -- CAST to text first, not straight to interval: the driver
                -- would otherwise want a timedelta. The string comes from
                -- `StatsBucket`, a closed set of presets, so it is never
                -- caller-controlled text.
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
            WHERE m.{time_column} >= CAST(:start AS timestamptz)
              AND m.{time_column} < CAST(:end AS timestamptz)
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
            "start": start,
            "end": end,
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
            SELECT
                'metrics' AS source,
                CAST(mac AS text) AS mac,
                count(*) AS rows,
                count(*) AS samples,
                min(ts) AS oldest,
                max(ts) AS latest
            FROM metrics
            GROUP BY mac
            UNION ALL
            SELECT
                'metrics_1m' AS source,
                CAST(mac AS text) AS mac,
                count(*) AS rows,
                CAST(sum(samples) AS bigint) AS samples,
                min(bucket) AS oldest,
                max(bucket) AS latest
            FROM metrics_1m
            GROUP BY mac
            UNION ALL
            SELECT
                'metrics_1h' AS source,
                CAST(mac AS text) AS mac,
                count(*) AS rows,
                CAST(sum(samples) AS bigint) AS samples,
                min(bucket) AS oldest,
                max(bucket) AS latest
            FROM metrics_1h
            GROUP BY mac
            ORDER BY mac
            """
        )
    ).mappings()

    by_machine: dict[str, dict[str, Any]] = {}
    for row in rows:
        count = dict(row)
        source = count.pop("source")
        mac = count.pop("mac")
        machine = by_machine.setdefault(
            mac,
            {
                "mac": mac,
                **{
                    name: {
                        "rows": 0,
                        "samples": 0,
                        "oldest": None,
                        "latest": None,
                    }
                    for name in ("metrics", "metrics_1m", "metrics_1h")
                },
            },
        )
        machine[source] = count
    result = list(by_machine.values())
    for machine in result:
        # Preserve the original endpoint fields as aliases for raw storage while
        # the nested fields add the two rollup sources.
        machine["samples"] = machine["metrics"]["samples"]
        machine["latest"] = machine["metrics"]["latest"]
    return result


def allow_bulk_decompression(conn: Connection) -> None:
    """Let one purge rewrite every compressed segment belonging to a machine."""
    conn.execute(
        text(
            "SET LOCAL timescaledb.max_tuples_decompressed_per_dml_transaction = 0"
        )
    )


def _purge_source(
    conn: Connection,
    source: str,
    time_column: str,
    mac: str,
    before: datetime | None,
) -> int:
    result = conn.execute(
        text(
            f"""
            DELETE FROM {source}
            WHERE mac = :mac
              AND (CAST(:before AS timestamptz) IS NULL
                   OR {time_column} < CAST(:before AS timestamptz))
            """
        ),
        {"mac": mac, "before": before},
    )
    return result.rowcount


def purge_machine_rollups(
    conn: Connection, mac: str, before: datetime | None
) -> dict[str, int]:
    """Delete matching buckets from both aggregate materializations.

    A materialized aggregate cannot be split without the raw samples from which
    it was built. A bucket beginning before an unaligned cutoff is therefore
    removed whole, favoring complete erasure over preserving newer data in that
    same minute or hour. If newer raw samples still exist, a later continuous-
    aggregate refresh can rebuild that boundary bucket from only those samples.
    """
    return {
        source: _purge_source(conn, source, time_column, mac, before)
        for source, time_column in _ROLLUP_SOURCES
    }


def purge_machine(
    conn: Connection, mac: str, before: datetime | None
) -> dict[str, int]:
    """Delete one machine from raw storage and both materialized rollups."""
    allow_bulk_decompression(conn)
    deleted = {"metrics": _purge_source(conn, "metrics", "ts", mac, before)}
    deleted.update(purge_machine_rollups(conn, mac, before))
    return deleted


def purge_all(conn: Connection, before: datetime | None) -> tuple[str, int | None]:
    """Delete every machine's history.

    With `before`, drops whole chunks — cheap, but chunk-granular: a chunk that
    straddles the cutoff is kept, so some older data may survive. Without it,
    TRUNCATE clears every chunk at once.

    The same operation is applied to both continuous aggregates so a purge does
    not leave independently materialized history behind.
    """
    if before is None:
        conn.execute(text("TRUNCATE TABLE metrics, metrics_1m, metrics_1h"))
        return "truncate", None
    for source in ("metrics", *(name for name, _ in _ROLLUP_SOURCES)):
        conn.execute(
            text(
                f"SELECT drop_chunks('{source}', "
                "older_than => CAST(:before AS timestamptz))"
            ),
            {"before": before},
        )
    return "drop_chunks", None
