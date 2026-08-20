"""The continuous aggregate spec, and how a query reads through it.

`metrics` keeps three days of five second samples. Anything older is answered
from `metrics_1m` and `metrics_1h`, which are TimescaleDB continuous aggregates
over the same columns. This module holds the column spec both of them are built
from, and the SQL fragments that let one query shape read either the raw table
or a rollup.

Why the rollups store `sum` and `count` rather than `avg`: re-bucketing an
average is only correct when every bucket carried the same number of samples,
and they do not. A poll that failed writes no row at all, and any single column
can be NULL on its own — a rate is unknown until there are two counter readings
behind it. Keeping the numerator and denominator apart makes
`sum(x_sum) / sum(x_n)` exact at any bucket width.

This spec is deliberately *not* imported by the migration that creates the
views. A migration is a snapshot: if it read this module, editing the spec would
silently change what an old revision replays as, and a database rebuilt from
scratch would diverge from one migrated forward. The migration carries its own
literal SQL, generated from this spec once, by hand.
"""

from __future__ import annotations

from datetime import UTC, datetime

# Gauges: a reading whose average over a window is meaningful. Each contributes
# `<col>_sum`, `<col>_n` and `<col>_max` to both views.
ROLLUP_GAUGES: tuple[str, ...] = (
    "cpu_usage_pct",
    "ram_used_pct",
    "ram_used_bytes",
    "disk_root_used_pct",
    "disk_max_used_pct",
    "net_rx_bps",
    "net_tx_bps",
    "dio_read_bps",
    "dio_write_bps",
    "dio_read_iops",
    "dio_write_iops",
    "dio_busy_pct",
)

# Monotonic counters and per-machine constants. Averaging either is meaningless,
# but the highest value in a bucket is exactly right for both: for a counter the
# difference between two buckets is the traffic between them, which is what
# keeps "bytes moved last month" answerable after the raw rows are gone; for a
# constant every value in the bucket is the same one.
ROLLUP_MAXES: tuple[str, ...] = (
    "net_rx_bytes",
    "net_tx_bytes",
    "dio_read_bytes",
    "dio_write_bytes",
    "cpu_cores",
    "ram_total_bytes",
    "disk_root_total_bytes",
    "net_speed_bps",
)

# Public aggregate name -> the raw column behind it. The names on the left are
# the wire contract of `GET /metrics/stats` and predate the wide-row schema, so
# they are kept exactly as they were.
#
# `disk_used_percent` maps to `disk_max_used_pct`, which is the fullest *real*
# filesystem. It used to be the fullest of every mount including tmpfs, so a
# full `/run/credentials/...` read as a full disk. Same question, better answer.
STATS_METRICS: tuple[tuple[str, str], ...] = (
    ("cpu_usage_percent", "cpu_usage_pct"),
    ("ram_used_percent", "ram_used_pct"),
    ("disk_used_percent", "disk_max_used_pct"),
    ("net_rx_bps", "net_rx_bps"),
    ("net_tx_bps", "net_tx_bps"),
    ("disk_read_bps", "dio_read_bps"),
    ("disk_write_bps", "dio_write_bps"),
    ("disk_read_iops", "dio_read_iops"),
    ("disk_write_iops", "dio_write_iops"),
)


def stats_projection(source: str) -> str:
    """The `avg`/`max` pair for every public metric, for one source table.

    Raw rows average directly. A rollup divides the stored sum by the stored
    count, which is what keeps the result exact when buckets hold different
    numbers of samples.
    """
    lines: list[str] = []
    for public, column in STATS_METRICS:
        if source == "metrics":
            lines.append(f"avg(m.{column}) AS {public}_avg")
            lines.append(f"max(m.{column}) AS {public}_max")
        else:
            lines.append(
                f"sum(m.{column}_sum) / nullif(sum(m.{column}_n), 0) AS {public}_avg"
            )
            lines.append(f"max(m.{column}_max) AS {public}_max")
    return ",\n                ".join(lines)


def hours_back(start: datetime) -> float:
    """How far back a window's start reaches from now, in hours.

    That reach, not the window's length, is what decides the source: a one-hour
    window six months ago is answered from a rollup even though an hour of raw
    data would have covered it, because those rows are long gone.
    """
    return max((datetime.now(UTC) - start).total_seconds() / 3600.0, 0.0)


def pick_source(hours: float, raw_hours: float, rollup_1m_hours: float) -> str:
    """Which table can answer a request reaching `hours` back.

    Raw first, because it is the only source with sub-minute resolution. Past
    the raw window the choice is forced: the rows simply are not there any more.
    """
    if hours <= raw_hours:
        return "metrics"
    if hours <= rollup_1m_hours:
        return "metrics_1m"
    return "metrics_1h"


# The finest bucket each source can honestly answer. Asking a one-hour rollup
# for five-minute buckets does not fail, it just returns one populated bucket in
# twelve, which reads as an outage on a chart rather than as a resolution limit.
SOURCE_MIN_BUCKET: dict[str, str] = {
    "metrics": "1 second",
    "metrics_1m": "1 minute",
    "metrics_1h": "1 hour",
}

# The same floors as a number, for `StatsBucket.at_least` to round a request up
# to a preset before the query runs — the router reports that preset back in
# `X-Metrics-Bucket`, and the `greatest()` in the query stays as the backstop.
SOURCE_MIN_BUCKET_SECONDS: dict[str, float] = {
    "metrics": 1.0,
    "metrics_1m": 60.0,
    "metrics_1h": 3_600.0,
}


# The column a source buckets on. Raw rows bucket on their timestamp; a rollup
# is already bucketed and re-buckets on the bucket it carries.
SOURCE_TIME_COLUMN: dict[str, str] = {
    "metrics": "ts",
    "metrics_1m": "bucket",
    "metrics_1h": "bucket",
}

# How to count samples per output bucket. Raw counts rows; a rollup already
# counted them and must add those counts up rather than count its own rows.
SOURCE_SAMPLES: dict[str, str] = {
    "metrics": "count(*)",
    "metrics_1m": "sum(m.samples)",
    "metrics_1h": "sum(m.samples)",
}
