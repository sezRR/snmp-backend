"""Server-Sent Events for live metrics.

Streaming is a side channel onto the collector's output: samples are written to
TimescaleDB first and published second, so subscribing changes nothing about what
is stored. Events therefore arrive at the collector's cadence
(`COLLECTOR_INTERVAL_SECONDS`), not on demand.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from sse_starlette.sse import EventSourceResponse

from app.api.deps import BusDep, DbDep, SettingsDep
from app.api.routers.machines import parse_mac
from app.db import machines as machines_repo
from app.models.metric import MetricSample
from app.services.bus import MetricBus

log = logging.getLogger(__name__)

router = APIRouter(tags=["stream"])


async def _events(
    bus: MetricBus, macs: set[str] | None, request: Request
) -> AsyncIterator[dict]:
    yield {
        "event": "connected",
        "data": json.dumps({"macs": sorted(macs) if macs else "all"}),
    }
    async for sample in bus.subscribe(macs):
        if await request.is_disconnected():  # pragma: no cover - client-driven
            break
        yield {
            "event": "metric",
            "data": MetricSample.model_dump_json(sample),
        }


@router.get("/metrics/stream")
async def stream_metrics(
    request: Request,
    bus: BusDep,
    settings: SettingsDep,
    mac: Annotated[
        list[str] | None,
        Query(description="Repeat to follow several machines; omit for every machine"),
    ] = None,
) -> EventSourceResponse:
    macs = {parse_mac(m) for m in mac} if mac else None
    return EventSourceResponse(
        _events(bus, macs, request),
        # A comment every N seconds keeps proxies from closing an idle stream.
        ping=int(settings.sse_heartbeat_seconds),
    )


@router.get("/machines/{mac}/metrics/stream")
async def stream_machine_metrics(
    mac: str,
    request: Request,
    bus: BusDep,
    db: DbDep,
    settings: SettingsDep,
) -> EventSourceResponse:
    normalised = parse_mac(mac)
    row = await db.run_query(machines_repo.get, normalised)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return EventSourceResponse(
        _events(bus, {normalised}, request),
        ping=int(settings.sse_heartbeat_seconds),
    )
