from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MetricSample(BaseModel):
    """One SNMP sample.

    `metrics` is deliberately untyped: it is stored as jsonb and its shape is
    whatever the collector produced, so metrics can be added or dropped without
    touching the schema or this model.
    """

    ts: datetime
    mac: str
    metrics: dict[str, Any]


class MetricStatsRow(BaseModel):
    """A `time_bucket` aggregate row, computed over the jsonb payload."""

    bucket: datetime
    mac: str
    samples: int
    cpu_usage_percent_avg: float | None = None
    cpu_usage_percent_max: float | None = None
    ram_used_percent_avg: float | None = None
    ram_used_percent_max: float | None = None
    disk_used_percent_avg: float | None = None
    disk_used_percent_max: float | None = None
    # Bytes per second, averaged over the samples in the bucket. Null for a
    # bucket whose samples predate the metric or carry no rate.
    net_rx_bps_avg: float | None = None
    net_rx_bps_max: float | None = None
    net_tx_bps_avg: float | None = None
    net_tx_bps_max: float | None = None


class PurgeResult(BaseModel):
    scope: str = Field(description="'machine' or 'all'")
    mac: str | None = None
    before: datetime | None = None
    method: str = Field(description="delete, truncate or drop_chunks")
    rows_deleted: int | None = Field(
        default=None,
        description="Null when the method does not report a row count (truncate, drop_chunks)",
    )
