"""Operational endpoints: collector status, OpenStack cache inspection and flush."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.api.deps import CollectorDep, LookupDep
from app.api.security import requires
from app.security.scopes import Scope
from app.models.openstack import CacheFlushed, CacheStats, ServerInfo

log = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/collector", dependencies=[requires(Scope.ADMIN_READ)])
async def collector_status(collector: CollectorDep) -> dict[str, Any]:
    """Loop health plus per-machine success/failure counts."""
    return collector.status()


@router.post("/collector/tick", dependencies=[requires(Scope.ADMIN_WRITE)])
async def force_tick(collector: CollectorDep) -> dict[str, Any]:
    """Run one collection round now, without waiting for the interval.

    Useful when demonstrating the pipeline — and when debugging a machine that
    just started failing.

    Declines rather than queues when the loop is mid-tick: waiting for the lock
    would just run a second round the instant the first finished, against
    counter baselines a few milliseconds old, and every rate in it would be
    noise.
    """
    if collector.ticking:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a collection round is already running; try again shortly",
        )
    stored = await collector.tick()
    return {"stored": stored, "failed": collector.last_failed}


@router.get("/openstack/cache", dependencies=[requires(Scope.ADMIN_READ)])
async def cache_stats(lookup: LookupDep) -> CacheStats:
    return lookup.stats()


@router.get("/openstack/servers", dependencies=[requires(Scope.ADMIN_READ)])
async def cached_servers(lookup: LookupDep) -> list[ServerInfo]:
    """The fleet as the lookup currently sees it — the addresses registerable."""
    return await lookup.servers()


@router.post(
    "/openstack/cache/flush", dependencies=[requires(Scope.ADMIN_WRITE)]
)
async def flush_cache(lookup: LookupDep) -> CacheFlushed:
    """Drop the cache; the next read repopulates it from upstream."""
    return CacheFlushed(dropped_servers=lookup.flush())
