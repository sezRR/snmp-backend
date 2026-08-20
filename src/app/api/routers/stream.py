"""Server-Sent Events for live metrics.

Streaming is a side channel onto the collector's output: samples are written to
TimescaleDB first and published second, so subscribing changes nothing about what
is stored. Events therefore arrive at the collector's cadence
(`COLLECTOR_INTERVAL_SECONDS`), not on demand.

A stream is the one place where "authenticate the request" is not enough. Every
other endpoint answers and is gone inside a few milliseconds, so a credential
checked at the start is a credential checked at the end. A stream authenticates
once and then holds the connection open for hours, which would let a session
ended in the meantime — a changed password, a disabled account — keep reading
live data for as long as the socket stayed up. So the loop re-asks, at the
heartbeat's cadence, and closes the stream with a `session-revoked` event when
the answer changes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sse_starlette.sse import EventSourceResponse

from app.api.deps import BusDep, DbDep, SessionEpochsDep, SettingsDep
from app.api.routers.machines import parse_mac
from app.api.security import Principal, get_stream_principal
from app.db import machines as machines_repo
from app.models.metric import MetricSample
from app.services.bus import MetricBus
from app.services.sessions import SessionEpochs

log = logging.getLogger(__name__)

# Both routes authenticate through get_stream_principal rather than the usual
# Bearer dependency: a browser's EventSource cannot set an Authorization header,
# so it presents a single-use ticket as ?ticket= instead. Either way the caller
# must hold metrics:read. See app.api.security.
router = APIRouter(tags=["stream"], dependencies=[Depends(get_stream_principal)])


def _still_live(
    epochs: SessionEpochs, principal: Principal
) -> Callable[[], Awaitable[bool]]:
    """The connect-time check, kept callable for the life of the stream."""

    async def check() -> bool:
        return await epochs.matches(principal.user_id, principal.epoch)

    return check


async def _events(
    bus: MetricBus,
    macs: set[str] | None,
    request: Request,
    still_live: Callable[[], Awaitable[bool]],
    recheck_seconds: float,
) -> AsyncIterator[dict]:
    yield {
        "event": "connected",
        "data": json.dumps({"macs": sorted(macs) if macs else "all"}),
    }

    samples = bus.subscribe(macs)
    # The subscription is awaited through a task that outlives each round of the
    # loop rather than a cancellable `wait_for`: cancelling a pending `__anext__`
    # would unwind the generator and drop the subscription, so a stream on an
    # idle fleet would unsubscribe itself every time the recheck timer fired.
    pending: asyncio.Task[MetricSample] | None = None
    try:
        while True:
            if pending is None:
                pending = asyncio.ensure_future(anext(samples))
            done, _ = await asyncio.wait({pending}, timeout=recheck_seconds)

            if not await still_live():
                # Named, so the client can tell this apart from a dropped
                # connection: one means reconnect, the other means sign in.
                yield {
                    "event": "session-revoked",
                    "data": json.dumps({"reason": "session ended"}),
                }
                return

            if pending not in done:
                continue

            try:
                sample = pending.result()
            except StopAsyncIteration:  # pragma: no cover - bus never stops
                return
            finally:
                pending = None

            if await request.is_disconnected():  # pragma: no cover - client-driven
                return
            yield {
                "event": "metric",
                "data": MetricSample.model_dump_json(sample),
            }
    finally:
        if pending is not None:
            # Awaited, not just cancelled: cancellation is delivered on the next
            # trip through the loop, and closing the subscription while its
            # `__anext__` is still running raises "already running".
            pending.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pending
        await samples.aclose()


@router.get("/metrics/stream")
async def stream_metrics(
    request: Request,
    bus: BusDep,
    settings: SettingsDep,
    epochs: SessionEpochsDep,
    principal: Annotated[Principal, Depends(get_stream_principal)],
    mac: Annotated[
        list[str] | None,
        Query(description="Repeat to follow several machines; omit for every machine"),
    ] = None,
) -> EventSourceResponse:
    macs = {parse_mac(m) for m in mac} if mac else None
    return EventSourceResponse(
        _events(
            bus,
            macs,
            request,
            _still_live(epochs, principal),
            settings.sse_heartbeat_seconds,
        ),
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
    epochs: SessionEpochsDep,
    principal: Annotated[Principal, Depends(get_stream_principal)],
) -> EventSourceResponse:
    normalised = parse_mac(mac)
    row = await db.run_query(machines_repo.get, normalised)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return EventSourceResponse(
        _events(
            bus,
            {normalised},
            request,
            _still_live(epochs, principal),
            settings.sse_heartbeat_seconds,
        ),
        ping=int(settings.sse_heartbeat_seconds),
    )
