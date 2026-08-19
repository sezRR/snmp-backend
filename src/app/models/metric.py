from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MetricSample(BaseModel):
    """One SNMP sample, in the nested shape clients read.

    `metrics` stays untyped because two different things arrive here. A live
    sample is whatever the collector just produced, per-mount and per-interface
    arrays included. A sample read back from the database has been through
    `app.services.snmp.flatten`: storage keeps one scalar per metric, so the
    arrays are gone and `disk` comes back holding the root filesystem alone.

    Both are the same shape as far as a consumer reading `metrics["cpu"]
    ["usage_percent"]` is concerned, which is why the model does not distinguish
    them. Anything iterating `disk` should expect one entry from history and
    however many the machine has from `/metrics/latest` and the stream.
    """

    ts: datetime
    mac: str
    metrics: dict[str, Any]


class MetricStatsRow(BaseModel):
    """A `time_bucket` aggregate row.

    Field names predate the wide-row schema and are kept exactly: this is the
    wire contract of `GET /metrics/stats`. `app.db.rollups.STATS_METRICS` maps
    each of them to the column it now reads.

    Depending on the range asked for these come from the raw table or from one
    of the continuous aggregates. The numbers mean the same thing either way —
    a rollup keeps sums and counts rather than averages precisely so that
    re-bucketing stays exact.
    """

    bucket: datetime
    mac: str
    samples: int
    cpu_usage_percent_avg: float | None = None
    cpu_usage_percent_max: float | None = None
    ram_used_percent_avg: float | None = None
    ram_used_percent_max: float | None = None
    # The fullest filesystem on the machine, not the root one. Pseudo
    # filesystems are excluded — a full `/run/credentials/...` is a tmpfs doing
    # its job, not a disk about to fill up.
    disk_used_percent_avg: float | None = None
    disk_used_percent_max: float | None = None
    # Bytes per second, averaged over the samples in the bucket. Null for a
    # bucket whose samples predate the metric or carry no rate.
    net_rx_bps_avg: float | None = None
    net_rx_bps_max: float | None = None
    net_tx_bps_avg: float | None = None
    net_tx_bps_max: float | None = None
    # Disk throughput in bytes per second and IOPS in operations per second,
    # summed across the machine's real block devices. Null for a bucket whose
    # samples predate the metric or whose agent serves no DISKIO-MIB.
    disk_read_bps_avg: float | None = None
    disk_read_bps_max: float | None = None
    disk_write_bps_avg: float | None = None
    disk_write_bps_max: float | None = None
    disk_read_iops_avg: float | None = None
    disk_read_iops_max: float | None = None
    disk_write_iops_avg: float | None = None
    disk_write_iops_max: float | None = None


class PurgeResult(BaseModel):
    scope: str = Field(description="'machine' or 'all'")
    mac: str | None = None
    before: datetime | None = None
    method: str = Field(description="delete, truncate or drop_chunks")
    rows_deleted: int | None = Field(
        default=None,
        description="Null when the method does not report a row count (truncate, drop_chunks)",
    )
