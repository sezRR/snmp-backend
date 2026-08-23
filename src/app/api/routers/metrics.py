from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.api.deps import CollectorDep, DbDep, SettingsDep
from app.api.security import requires
from app.security.scopes import Scope
from app.api.routers.machines import parse_mac
from app.db import machines as machines_repo
from app.db import metrics as metrics_repo
from app.db import rollups
from app.models.metric import (
    MetricCounts,
    MetricSample,
    MetricStatsRow,
    PurgeResult,
    StatsBucket,
)
from app.services.snmp.flatten import nest

log = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

MacQuery = Annotated[
    list[str] | None,
    Query(description="Repeat to filter on several machines; omit for all"),
]

# Counted on the effective bucket, after the source's floor, so a long range at
# 30s buckets is judged on the buckets it would really return.
MAX_BUCKETS = 5_000

# What an omitted `bucket` aims for: a fixed width cannot serve both an hour
# and a month, so it is fitted to the window. 360 is a chart's worth.
TARGET_POINTS = 360

# The other factor: rows are buckets times machines, so stats names its machines.
MAX_MACS = 10


def _as_utc(value: datetime) -> datetime:
    """Read a naive timestamp as UTC rather than as the database's timezone."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _normalise_macs(macs: list[str] | None) -> list[str] | None:
    return [parse_mac(m) for m in macs] if macs else None


def _sample(row: dict) -> MetricSample:
    """A stored row as the nested reading clients have always been given.

    The row is scalars; the wire shape is nested. `nest` rebuilds it, with the
    per-mount, per-device and per-interface arrays absent because storage does
    not keep them. Live samples, which do, come from the collector instead.
    """
    return MetricSample(ts=row["ts"], mac=row["mac"], metrics=nest(row))


@router.get("/metrics", dependencies=[requires(Scope.METRICS_READ)])
async def list_metrics(
    db: DbDep,
    mac: MacQuery = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 100,
) -> list[MetricSample]:
    rows = await db.run_query(
        metrics_repo.list_samples, _normalise_macs(mac), since, limit
    )
    return [_sample(row) for row in rows]


@router.get("/metrics/latest", dependencies=[requires(Scope.METRICS_READ)])
async def latest_metrics(db: DbDep, collector: CollectorDep) -> list[MetricSample]:
    """The most recent sample per machine — what a dashboard opens with.

    Served from the collector's last reading where there is one, because that
    still carries the per-mount and per-interface detail the database does not
    keep. A machine the collector has not sampled since this process started
    falls back to its stored row, which reconstructs to root-only — a gap of at
    most one interval after a restart, not a bug.
    """
    live = collector.last_samples
    rows = await db.run_query(metrics_repo.latest_per_machine)
    stored = [_sample(row) for row in rows if row["mac"] not in live]
    return sorted([*live.values(), *stored], key=lambda sample: sample.mac)


@router.get("/metrics/stats", dependencies=[requires(Scope.METRICS_READ)])
async def metric_stats(
    db: DbDep,
    settings: SettingsDep,
    response: Response,
    start: Annotated[
        datetime,
        Query(
            alias="from",
            description="Window start, inclusive. ISO 8601; naive is read as UTC",
        ),
    ],
    end: Annotated[
        datetime,
        Query(alias="to", description="Window end, exclusive"),
    ],
    mac: Annotated[
        list[str],
        Query(
            min_length=1,
            max_length=MAX_MACS,
            description="Required; repeat to chart several machines at once",
        ),
    ],
    bucket: Annotated[
        StatsBucket | None,
        Query(
            description=(
                "Bucket width — one of the presets. Omitted, it is fitted to "
                "the window; either way it is floored at what the source resolves"
            )
        ),
    ] = None,
) -> list[MetricStatsRow]:
    """`time_bucket` aggregates over an explicit `[from, to)` window.

    A metric a sample has nothing to say about contributes nothing rather than
    erroring, which is what keeps a machine with a partial SNMP answer from
    poisoning the whole bucket.

    Reads past the raw retention window are answered from the continuous
    aggregates, so how far back a caller can ask is bounded by the rollups'
    retention rather than by the raw table's.

    `bucket` is a preset rather than a free-form interval — an unparseable one
    used to reach Postgres and come back a 500 — and is optional: omitted, it is
    fitted to the window so that the answer is about `TARGET_POINTS` long
    whatever the range. Either way it is then floored at what the chosen source
    can resolve. Both of those change the width the caller gets, so the width
    that was used comes back in `X-Metrics-Bucket`, and the table it was read
    from in `X-Metrics-Source`.
    """
    start, end = _as_utc(start), _as_utc(end)
    if end <= start:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="`to` must be after `from`",
        )
    source = rollups.pick_source(
        rollups.hours_back(start),
        settings.metrics_retention_days * 24,
        settings.metrics_rollup_1m_retention_days * 24,
    )
    span = (end - start).total_seconds()
    # Flooring to a preset, not the source's interval string, so the width can
    # be named back to the caller as something they can ask for again.
    chosen = bucket or StatsBucket.at_least(span / TARGET_POINTS)
    floor = StatsBucket.at_least(rollups.SOURCE_MIN_BUCKET_SECONDS[source])
    effective = max(chosen, floor, key=lambda preset: preset.seconds)
    buckets = span / effective.seconds
    if buckets > MAX_BUCKETS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"window covers {buckets:.0f} buckets of {effective.value} "
                f"(max {MAX_BUCKETS}) — widen `bucket` or shorten the window"
            ),
        )
    rows = await db.run_query(
        metrics_repo.stats,
        source,
        effective.interval,
        start,
        end,
        _normalise_macs(mac),
    )
    response.headers["X-Metrics-Bucket"] = effective.value
    response.headers["X-Metrics-Source"] = source
    return [MetricStatsRow(**row) for row in rows]


@router.get("/metrics/counts", dependencies=[requires(Scope.METRICS_READ)])
async def metric_counts(db: DbDep) -> list[MetricCounts]:
    """Rows, represented samples and time coverage per machine and source."""
    rows = await db.run_query(metrics_repo.counts_by_machine)
    return [MetricCounts(**row) for row in rows]


@router.delete(
    "/machines/{mac}/metrics", dependencies=[requires(Scope.METRICS_WRITE)]
)
async def purge_machine_metrics(
    mac: str,
    db: DbDep,
    before: Annotated[
        datetime | None,
        Query(
            description=(
                "Purge raw samples older than this. A matching 1m or 1h rollup "
                "bucket is removed whole; a later refresh may rebuild it from "
                "surviving newer raw samples"
            )
        ),
    ] = None,
) -> PurgeResult:
    """Purge one machine's raw and rolled-up history.

    The machine normally remains registered. Aggregate-only history left by a
    deregistration from before rollup cleanup was introduced can also be purged.
    An unaligned `before` removes the containing rollup bucket; when newer raw
    samples survive, the normal refresh policy may rebuild it without the purged
    samples.
    """
    normalised = parse_mac(mac)
    row = await db.run_query(machines_repo.get, normalised)
    deleted = await db.run_query(metrics_repo.purge_machine, normalised, before)
    if row is None and not any(deleted.values()):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    log.info(
        "purged metrics for %s (before=%s): %s",
        normalised,
        before,
        deleted,
    )
    return PurgeResult(
        scope="machine",
        mac=normalised,
        before=before,
        method="delete",
        rows_deleted=sum(deleted.values()),
        rows_deleted_by_source=deleted,
    )


@router.delete("/metrics", dependencies=[requires(Scope.METRICS_WRITE)])
async def purge_all_metrics(
    db: DbDep,
    confirm: Annotated[
        bool, Query(description="Required: guards against an accidental wipe")
    ] = False,
    before: Annotated[
        datetime | None,
        Query(description="Drop only chunks entirely older than this"),
    ] = None,
) -> PurgeResult:
    """Purge every machine's history.

    Without `before` this truncates raw metrics and drops every rollup chunk.
    With it, whole chunks are dropped from all three sources — cheap, but
    chunk-granular, so a chunk straddling the cutoff survives and older data may
    remain.
    """
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="pass ?confirm=true to purge all metrics",
        )
    method, rows = await db.run_query(metrics_repo.purge_all, before)
    log.warning("purged all metrics via %s (before=%s)", method, before)
    return PurgeResult(scope="all", before=before, method=method, rows_deleted=rows)
