"""The polling loop.

Every `COLLECTOR_INTERVAL_SECONDS`:

1. read the enabled machines;
2. refresh each IPv4 from the OpenStack lookup — OpenStack owns the address, so a
   re-IP'd server keeps being polled without the client doing anything;
3. sample all of them concurrently, bounded by `COLLECTOR_CONCURRENCY`;
4. write the batch in one insert;
5. publish each sample to the bus for SSE subscribers.

A machine that fails to answer is recorded and skipped; it never stops the tick
or the other machines' samples.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app.config import Settings
from app.db import machines as machines_repo
from app.db import metrics as metrics_repo
from app.db.pool import Database
from app.models.metric import MetricSample
from app.services.bus import MetricBus
from app.services.openstack import CachedOpenStack, normalise_mac
from app.services.snmp import SnmpSampler

log = logging.getLogger(__name__)


class MachineStatus:
    """Per-machine outcome of the last few ticks, for /admin/collector."""

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.ipv4: str | None = None
        self.ok_count = 0
        self.fail_count = 0
        self.last_ok: datetime | None = None
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ipv4": self.ipv4,
            "ok_count": self.ok_count,
            "fail_count": self.fail_count,
            "last_ok": self.last_ok,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
        }


class Collector:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        sampler: SnmpSampler,
        lookup: CachedOpenStack,
        bus: MetricBus,
    ) -> None:
        self._settings = settings
        self._db = db
        self._sampler = sampler
        self._lookup = lookup
        self._bus = bus
        self._task: asyncio.Task[None] | None = None
        self._semaphore = asyncio.Semaphore(settings.collector_concurrency)
        # The loop and POST /admin/collector/tick both call `tick()`. Two ticks
        # running at once would interleave their reads of the same counter
        # baselines and derive nonsense rates from them.
        self._tick_lock = asyncio.Lock()

        # Observability, all in memory.
        self.started_at: datetime | None = None
        self.tick_count = 0
        self.last_tick_at: datetime | None = None
        self.last_tick_duration: float | None = None
        self.last_inserted = 0
        self.last_failed = 0
        self.last_tick_error: str | None = None
        self.overrun_count = 0
        # Smoothed tick-to-tick spacing. The configured interval is what we ask
        # for; this is what the loop actually achieves, and they diverge as soon
        # as a tick outruns its period.
        self.effective_interval: float | None = None
        self._last_tick_started: float | None = None
        self.statuses: dict[str, MachineStatus] = {}

    @property
    def _sample_budget(self) -> float:
        """Wall-clock ceiling on one machine's sample.

        Bounds the tick regardless of how the sampler spends its time — SNMP
        timeouts, retries and DNS all sit underneath it. Defaults to most of the
        interval, so a slot is never held across a whole period.
        """
        configured = self._settings.collector_sample_timeout_seconds
        if configured > 0:
            return configured
        return max(1.0, self._settings.collector_interval_seconds * 0.8)

    # ---- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._task is not None:
            return
        self.started_at = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._run(), name="metric-collector")
        log.info(
            "collector started (every %ss, concurrency %s)",
            self._settings.collector_interval_seconds,
            self._settings.collector_concurrency,
        )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
            log.info("collector stopped")

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ---- loop ---------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            # Read fresh each pass rather than binding it once for the lifetime
            # of the process, so the value cannot go stale behind a reload.
            interval = self._settings.collector_interval_seconds
            started = time.monotonic()
            if self._last_tick_started is not None:
                spacing = started - self._last_tick_started
                self.effective_interval = (
                    spacing
                    if self.effective_interval is None
                    else round(0.8 * self.effective_interval + 0.2 * spacing, 3)
                )
            self._last_tick_started = started

            try:
                await self.tick()
                self.last_tick_error = None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A whole failed tick (database down, lookup down) must not kill
                # the loop — the next one may well succeed.
                self.last_tick_error = f"{type(exc).__name__}: {exc}"
                log.exception("collector tick failed")
            elapsed = time.monotonic() - started
            self.last_tick_duration = elapsed

            if elapsed > interval:
                # Without this the loop just runs back to back and every status
                # reading still claims the configured interval. Say so instead:
                # the cadence is now whatever the tick costs.
                self.overrun_count += 1
                log.warning(
                    "collector tick took %.2fs, longer than the %.2fs interval "
                    "(%s machines, %s failed) — cadence is degraded",
                    elapsed,
                    interval,
                    self.last_inserted + self.last_failed,
                    self.last_failed,
                )
            # Subtract the work from the period so the cadence does not drift.
            await asyncio.sleep(max(0.0, interval - elapsed))

    async def tick(self) -> int:
        """One collection round. Returns how many samples were stored."""
        async with self._tick_lock:
            return await self._tick()

    @property
    def ticking(self) -> bool:
        """Whether a round is in flight, so a forced tick can decline instead."""
        return self._tick_lock.locked()

    async def _tick(self) -> int:
        self.tick_count += 1
        self.last_tick_at = datetime.now(timezone.utc)

        rows = await self._db.run_query(machines_repo.list_all, True)
        if not rows:
            self.last_inserted = 0
            self.last_failed = 0
            return 0

        targets = await self._resolve_addresses(rows)

        results = await asyncio.gather(
            *(self._sample_one(mac, ipv4) for mac, ipv4 in targets),
            return_exceptions=False,
        )
        samples = [sample for sample in results if sample is not None]

        self.last_inserted = len(samples)
        self.last_failed = len(targets) - len(samples)

        if samples:
            await self._db.run_query(
                metrics_repo.insert_many,
                [(s.ts, s.mac, s.metrics) for s in samples],
            )
            # Published only after the write, so a subscriber never sees a
            # sample that failed to persist.
            for sample in samples:
                self._bus.publish(sample)

        return len(samples)

    async def _resolve_addresses(self, rows: list[dict[str, Any]]) -> list[tuple[str, str]]:
        """Pair each MAC with the address to poll, following OpenStack."""
        try:
            index = await self._lookup.mac_index()
        except Exception as exc:
            # Lookup down: keep polling the addresses we already have rather
            # than skipping the tick entirely.
            log.warning("address refresh skipped: %s", exc)
            index = {}

        targets: list[tuple[str, str]] = []
        for row in rows:
            mac = row["mac"]
            ipv4 = row["ipv4"]
            server = index.get(normalise_mac(mac))
            if server is not None and server.ipv4 != ipv4:
                log.info("machine %s moved %s -> %s", mac, ipv4, server.ipv4)
                await self._db.run_query(machines_repo.set_ipv4, mac, server.ipv4)
                ipv4 = server.ipv4
            targets.append((mac, ipv4))
            self.statuses.setdefault(mac, MachineStatus(mac)).ipv4 = ipv4
        return targets

    async def _sample_one(self, mac: str, ipv4: str) -> MetricSample | None:
        status = self.statuses.setdefault(mac, MachineStatus(mac))
        async with self._semaphore:
            try:
                # The MAC, not the address, is what the sampler remembers
                # counter baselines under: OpenStack may re-IP a machine between
                # two ticks and its history should survive that.
                metrics = await asyncio.wait_for(
                    self._sampler.sample(ipv4, mac), timeout=self._sample_budget
                )
            except asyncio.TimeoutError:
                # Recorded like any other failure. The point is the slot: a host
                # that never answers must not hold one for a whole period.
                status.fail_count += 1
                status.last_error = f"TimeoutError: no sample within {self._sample_budget:.1f}s"
                status.last_error_at = datetime.now(timezone.utc)
                log.warning(
                    "sample timed out for %s (%s) after %.1fs",
                    mac,
                    ipv4,
                    self._sample_budget,
                )
                return None
            except Exception as exc:
                status.fail_count += 1
                status.last_error = f"{type(exc).__name__}: {exc}"
                status.last_error_at = datetime.now(timezone.utc)
                log.warning("sample failed for %s (%s): %s", mac, ipv4, exc)
                return None
        status.ok_count += 1
        status.last_ok = datetime.now(timezone.utc)
        return MetricSample(ts=datetime.now(timezone.utc), mac=mac, metrics=metrics)

    # ---- status -------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._settings.collector_enabled,
            "running": self.running,
            "interval_seconds": self._settings.collector_interval_seconds,
            # What the loop is actually achieving, which is the number worth
            # watching: it only matches the configured interval while ticks fit.
            "effective_interval_seconds": self.effective_interval,
            "overrun_count": self.overrun_count,
            "sample_budget_seconds": self._sample_budget,
            "concurrency": self._settings.collector_concurrency,
            "snmp_simulated": self._settings.snmp_simulate,
            "started_at": self.started_at,
            "tick_count": self.tick_count,
            "last_tick_at": self.last_tick_at,
            "last_tick_duration_seconds": self.last_tick_duration,
            "last_inserted": self.last_inserted,
            "last_failed": self.last_failed,
            "last_tick_error": self.last_tick_error,
            "sse_subscribers": self._bus.subscriber_count,
            "machines": [s.as_dict() for s in self.statuses.values()],
        }
