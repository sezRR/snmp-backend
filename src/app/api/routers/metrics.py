"""Metric history, aggregates and purges."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import DbDep
from app.api.routers.machines import parse_mac
from app.db import machines as machines_repo
from app.db import metrics as metrics_repo
from app.models.metric import MetricSample, MetricStatsRow, PurgeResult

log = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

MacQuery = Annotated[
    list[str] | None,
    Query(description="Repeat to filter on several machines; omit for all"),
]


def _normalise_macs(macs: list[str] | None) -> list[str] | None:
    return [parse_mac(m) for m in macs] if macs else None


@router.get("/metrics")
async def list_metrics(
    db: DbDep,
    mac: MacQuery = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 100,
) -> list[MetricSample]:
    rows = await db.run_query(
        metrics_repo.list_samples, _normalise_macs(mac), since, limit
    )
    return [MetricSample(**row) for row in rows]


@router.get("/metrics/latest")
async def latest_metrics(db: DbDep) -> list[MetricSample]:
    """The most recent sample per machine — what a dashboard opens with."""
    rows = await db.run_query(metrics_repo.latest_per_machine)
    return [MetricSample(**row) for row in rows]


@router.get("/metrics/stats")
async def metric_stats(
    db: DbDep,
    bucket: Annotated[
        str, Query(description="Postgres interval, e.g. '30 seconds', '15 minutes'")
    ] = "5 minutes",
    hours: Annotated[float, Query(gt=0, le=8760)] = 1.0,
    mac: MacQuery = None,
) -> list[MetricStatsRow]:
    """`time_bucket` aggregates computed over the jsonb payload.

    A metric absent from a sample contributes nothing rather than erroring, which
    is what keeps the payload safe to change.
    """
    rows = await db.run_query(
        metrics_repo.stats, bucket, hours, _normalise_macs(mac)
    )
    return [MetricStatsRow(**row) for row in rows]


@router.get("/metrics/counts")
async def metric_counts(db: DbDep) -> list[dict]:
    """Row count and latest sample per machine."""
    return await db.run_query(metrics_repo.counts_by_machine)


@router.delete("/machines/{mac}/metrics")
async def purge_machine_metrics(
    mac: str,
    db: DbDep,
    before: Annotated[
        datetime | None, Query(description="Only purge samples older than this")
    ] = None,
) -> PurgeResult:
    """Purge one machine's history, keeping the machine registered."""
    normalised = parse_mac(mac)
    row = await db.run_query(machines_repo.get, normalised)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    deleted = await db.run_query(metrics_repo.purge_machine, normalised, before)
    log.info("purged %s samples for %s (before=%s)", deleted, normalised, before)
    return PurgeResult(
        scope="machine",
        mac=normalised,
        before=before,
        method="delete",
        rows_deleted=deleted,
    )


@router.delete("/metrics")
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

    Without `before` this truncates the hypertable. With it, whole chunks are
    dropped — cheap, but chunk-granular, so a chunk straddling the cutoff
    survives and slightly newer data may remain.
    """
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="pass ?confirm=true to purge all metrics",
        )
    method, rows = await db.run_query(metrics_repo.purge_all, before)
    log.warning("purged all metrics via %s (before=%s)", method, before)
    return PurgeResult(scope="all", before=before, method=method, rows_deleted=rows)
