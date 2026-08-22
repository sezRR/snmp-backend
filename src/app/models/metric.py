from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class StatsBucket(StrEnum):
    """The `time_bucket` widths `GET /metrics/stats` accepts.

    A closed set rather than a free-form Postgres interval. The interval used to
    be taken straight from the query string and cast in SQL, so anything
    Postgres could not parse came back as a 500 from the driver instead of a 422
    from validation, and any width at all was accepted — including ones no
    source can resolve and ones that would return a million rows.

    The member value is what goes on the wire, `interval` is what SQL gets, and
    `seconds` is the same width as a number, for working out how many buckets a
    requested window covers before running the query.
    """

    S30 = "30s"
    M1 = "1m"
    M5 = "5m"
    M15 = "15m"
    H1 = "1h"
    H6 = "6h"
    D1 = "1d"
    D7 = "7d"

    @property
    def interval(self) -> str:
        return _BUCKET_INTERVALS[self]

    @property
    def seconds(self) -> float:
        return _BUCKET_SECONDS[self]

    @classmethod
    def at_least(cls, seconds: float) -> StatsBucket:
        """The narrowest preset no finer than `seconds`; the widest if none is.

        Two different questions reduce to this one. Fitting a window to a point
        count asks for a bucket at least `span / points` wide; flooring at what
        a rollup can resolve asks for one at least its bucket wide. Members are
        declared narrowest-first, so the first match is the answer.
        """
        return next((bucket for bucket in cls if bucket.seconds >= seconds), cls.D7)


_BUCKET_INTERVALS: dict[StatsBucket, str] = {
    StatsBucket.S30: "30 seconds",
    StatsBucket.M1: "1 minute",
    StatsBucket.M5: "5 minutes",
    StatsBucket.M15: "15 minutes",
    StatsBucket.H1: "1 hour",
    StatsBucket.H6: "6 hours",
    StatsBucket.D1: "1 day",
    StatsBucket.D7: "7 days",
}

_BUCKET_SECONDS: dict[StatsBucket, float] = {
    StatsBucket.S30: 30.0,
    StatsBucket.M1: 60.0,
    StatsBucket.M5: 300.0,
    StatsBucket.M15: 900.0,
    StatsBucket.H1: 3_600.0,
    StatsBucket.H6: 21_600.0,
    StatsBucket.D1: 86_400.0,
    StatsBucket.D7: 604_800.0,
}


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
    # The fullest real filesystem, not root: a full tmpfs is not a full disk.
    disk_used_percent_avg: float | None = None
    disk_used_percent_max: float | None = None
    # Bytes per second over the bucket; null when no sample carried a rate.
    net_rx_bps_avg: float | None = None
    net_rx_bps_max: float | None = None
    net_tx_bps_avg: float | None = None
    net_tx_bps_max: float | None = None
    # Throughput and IOPS summed across real block devices; null without
    # DISKIO-MIB.
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
