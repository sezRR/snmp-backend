from __future__ import annotations

from datetime import UTC, datetime

# Gauges — averageable. Each contributes `_sum`, `_n` and `_max` to both views.
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

# Counters and per-machine constants: the bucket maximum is right for both — a
# counter's difference between buckets is the traffic between them.
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

# Public name -> raw column. The left side is the wire contract of
# `GET /metrics/stats` and predates the wide-row schema, so it is unchanged.
# `disk_used_percent` now means the fullest *real* filesystem, not any tmpfs.
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


# The finest bucket each source can honestly answer: a coarser rollup would
# return one populated bucket in twelve, which reads as an outage.
SOURCE_MIN_BUCKET: dict[str, str] = {
    "metrics": "1 second",
    "metrics_1m": "1 minute",
    "metrics_1h": "1 hour",
}

# The same floors as numbers, so a request rounds up to a preset the router can
# report back in `X-Metrics-Bucket`.
SOURCE_MIN_BUCKET_SECONDS: dict[str, float] = {
    "metrics": 1.0,
    "metrics_1m": 60.0,
    "metrics_1h": 3_600.0,
}


# What each source buckets on: raw rows their timestamp, rollups their bucket.
SOURCE_TIME_COLUMN: dict[str, str] = {
    "metrics": "ts",
    "metrics_1m": "bucket",
    "metrics_1h": "bucket",
}

# Sample counting: raw counts rows, a rollup sums the counts it already holds.
SOURCE_SAMPLES: dict[str, str] = {
    "metrics": "count(*)",
    "metrics_1m": "sum(m.samples)",
    "metrics_1h": "sum(m.samples)",
}
