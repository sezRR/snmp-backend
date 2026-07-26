"""In-process fan-out from the collector to SSE subscribers.

The collector publishes every sample here after writing it to TimescaleDB, so
streaming is a side channel: with no subscribers the writes still happen, and a
subscriber that cannot keep up loses events rather than growing a queue without
bound.

In-process means per-pod. With more than one replica a client only sees samples
collected by the pod it connected to; a shared bus (Redis, NATS, or Postgres
LISTEN/NOTIFY) would be the fix.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator

from app.models.metric import MetricSample

log = logging.getLogger(__name__)


class _Subscription:
    def __init__(self, macs: set[str] | None, maxsize: int) -> None:
        self.macs = macs
        self.queue: asyncio.Queue[MetricSample] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    def wants(self, sample: MetricSample) -> bool:
        return self.macs is None or sample.mac in self.macs


class MetricBus:
    def __init__(self, queue_maxsize: int = 100) -> None:
        self._queue_maxsize = queue_maxsize
        self._subscriptions: set[_Subscription] = set()

    @property
    def subscriber_count(self) -> int:
        return len(self._subscriptions)

    def publish(self, sample: MetricSample) -> None:
        """Non-blocking; called from the collector loop."""
        for sub in self._subscriptions:
            if not sub.wants(sample):
                continue
            try:
                sub.queue.put_nowait(sample)
            except asyncio.QueueFull:
                # Drop the oldest so a stalled client sees recent data when it
                # resumes, instead of a backlog it will never catch up on.
                try:
                    sub.queue.get_nowait()
                    sub.queue.put_nowait(sample)
                except (asyncio.QueueEmpty, asyncio.QueueFull):  # pragma: no cover
                    pass
                sub.dropped += 1

    async def subscribe(self, macs: set[str] | None = None) -> AsyncIterator[MetricSample]:
        """Yield samples until the consumer stops iterating or disconnects."""
        sub = _Subscription(macs, self._queue_maxsize)
        self._subscriptions.add(sub)
        log.info(
            "sse subscriber attached (macs=%s, total=%s)",
            "all" if macs is None else sorted(macs),
            len(self._subscriptions),
        )
        try:
            while True:
                yield await sub.queue.get()
        finally:
            self._subscriptions.discard(sub)
            log.info(
                "sse subscriber detached (dropped=%s, total=%s)",
                sub.dropped,
                len(self._subscriptions),
            )
