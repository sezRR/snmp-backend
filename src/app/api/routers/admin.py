"""Operational endpoints: collector status, OpenStack cache inspection and flush."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.api.deps import CollectorDep, LookupDep
from app.models.openstack import CacheFlushed, CacheStats, ServerInfo

log = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/collector")
async def collector_status(collector: CollectorDep) -> dict[str, Any]:
    """Loop health plus per-machine success/failure counts."""
    return collector.status()


@router.post("/collector/tick")
async def force_tick(collector: CollectorDep) -> dict[str, Any]:
    """Run one collection round now, without waiting for the interval.

    Useful when demonstrating the pipeline — and when debugging a machine that
    just started failing.
    """
    stored = await collector.tick()
    return {"stored": stored, "failed": collector.last_failed}


@router.get("/openstack/cache")
async def cache_stats(lookup: LookupDep) -> CacheStats:
    return lookup.stats()


@router.get("/openstack/servers")
async def cached_servers(lookup: LookupDep) -> list[ServerInfo]:
    """The fleet as the lookup currently sees it — the addresses registerable."""
    return await lookup.servers()


@router.post("/openstack/cache/flush")
async def flush_cache(lookup: LookupDep) -> CacheFlushed:
    """Drop the cache; the next read repopulates it from upstream."""
    return CacheFlushed(dropped_servers=lookup.flush())
