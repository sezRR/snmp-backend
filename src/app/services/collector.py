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
from app.services.credentials import CredentialCache
from app.services.openstack import CachedOpenStack, normalise_mac
from app.services.snmp import SnmpSampler
from app.services.snmp.flatten import flatten

log = logging.getLogger(__name__)


class MachineStatus:
    """Per-machine outcome of the last few ticks, for /admin/collector."""

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.ipv4: str | None = None
        # The name, not the id: a UUID answers nothing for whoever reads this.
        self.credential: str | None = None
        self.ok_count = 0
        self.fail_count = 0
        self.last_ok: datetime | None = None
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ipv4": self.ipv4,
            "credential": self.credential,
            "ok_count": self.ok_count,
            "fail_count": self.fail_count,
            "last_ok": self.last_ok,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
        }

    def record_failure(self, error: str) -> None:
        self.fail_count += 1
        self.last_error = error
        self.last_error_at = datetime.now(timezone.utc)


class Collector:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        sampler: SnmpSampler,
        lookup: CachedOpenStack,
        bus: MetricBus,
        credentials: CredentialCache,
    ) -> None:
        self._settings = settings
        self._db = db
        self._sampler = sampler
        self._lookup = lookup
        self._bus = bus
        self._credentials = credentials
        self._task: asyncio.Task[None] | None = None
        self._semaphore = asyncio.Semaphore(settings.collector_concurrency)
        # Ticks must not interleave baselines, and deletion must not race a
        # tick's metric insert.
        self._tick_lock = asyncio.Lock()
        self._pending_ticks = 0

        # Observability, all in memory.
        self.started_at: datetime | None = None
        self.tick_count = 0
        self.last_tick_at: datetime | None = None
        self.last_tick_duration: float | None = None
        self.last_inserted = 0
        self.last_failed = 0
        self.last_tick_error: str | None = None
        self.overrun_count = 0
        # Smoothed tick-to-tick spacing: what the loop achieves, not what it
        # was asked for.
        self.effective_interval: float | None = None
        self._last_tick_started: float | None = None
        self.statuses: dict[str, MachineStatus] = {}
        # MAC -> last full reading. Pruned wherever `statuses` is.
        self.last_samples: dict[str, MetricSample] = {}

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
            # Read fresh each pass so a reload cannot leave it stale.
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
                # A failed tick must not kill the loop; the next may succeed.
                self.last_tick_error = f"{type(exc).__name__}: {exc}"
                log.exception("collector tick failed")
            elapsed = time.monotonic() - started
            self.last_tick_duration = elapsed

            if elapsed > interval:
                # Otherwise the loop runs back to back while still claiming the
                # configured interval.
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
        self._pending_ticks += 1
        try:
            async with self._tick_lock:
                return await self._tick()
        finally:
            self._pending_ticks -= 1

    @property
    def ticking(self) -> bool:
        """Whether a round is in flight, so a forced tick can decline instead."""
        return self._pending_ticks > 0

    async def deregister_machine(self, mac: str) -> bool:
        """Delete a machine without racing an in-flight sample insert."""
        async with self._tick_lock:
            deleted = await self._db.run_query(machines_repo.delete, mac)
            self.statuses.pop(mac, None)
            self.last_samples.pop(mac, None)
            return deleted

    async def _tick(self) -> int:
        self.tick_count += 1
        self.last_tick_at = datetime.now(timezone.utc)

        rows = await self._db.run_query(machines_repo.list_for_polling)
        polled_macs = {row["mac"] for row in rows}
        for mac in self.statuses.keys() - polled_macs:
            del self.statuses[mac]
            self.last_samples.pop(mac, None)
        if not rows:
            self.last_inserted = 0
            self.last_failed = 0
            return 0

        targets = await self._resolve_addresses(rows)

        results = await asyncio.gather(
            *(self._sample_one(row, ipv4) for row, ipv4 in targets),
            return_exceptions=False,
        )
        samples = [sample for sample in results if sample is not None]

        self.last_inserted = len(samples)
        self.last_failed = len(targets) - len(samples)

        if samples:
            await self._db.run_query(
                metrics_repo.insert_many,
                [
                    {
                        "ts": s.ts,
                        "mac": s.mac,
                        **flatten(
                            s.metrics,
                            pseudo_mount_prefixes=self._settings.pseudo_mount_prefixes,
                            virtual_iface_prefixes=self._settings.virtual_iface_prefixes,
                        ),
                    }
                    for s in samples
                ],
            )
            # After the write only, so nothing shows a sample that failed to persist.
            for sample in samples:
                self.last_samples[sample.mac] = sample
                self._bus.publish(sample)

        return len(samples)

    async def _resolve_addresses(
        self, rows: list[dict[str, Any]]
    ) -> list[tuple[dict[str, Any], str]]:
        """Pair each machine row with the address to poll, following OpenStack.

        External machines have no lookup record, so their stored address stands
        as given — the client is the only thing that can move them.
        """
        try:
            index = await self._lookup.mac_index()
        except Exception as exc:
            # Lookup down: poll the addresses we already have.
            log.warning("address refresh skipped: %s", exc)
            index = {}

        targets: list[tuple[dict[str, Any], str]] = []
        for row in rows:
            mac = row["mac"]
            ipv4 = row["ipv4"]
            server = index.get(normalise_mac(mac))
            if server is not None and row["external"]:
                # Registered as external, but OpenStack has it now, so it owns
                # the address from here on.
                log.info("machine %s is in OpenStack after all; no longer external", mac)
                await self._db.run_query(machines_repo.mark_managed, mac)
            if server is not None and server.ipv4 != ipv4:
                # The credential follows the machine: OpenStack is the address
                # authority, and a re-IP there already outranks this secret.
                log.info(
                    "machine %s moved %s -> %s (credential %s)",
                    mac,
                    ipv4,
                    server.ipv4,
                    row["credential_name"] or "none",
                )
                await self._db.run_query(machines_repo.set_ipv4, mac, server.ipv4)
                ipv4 = server.ipv4
            targets.append((row, ipv4))
            status = self.statuses.setdefault(mac, MachineStatus(mac))
            status.ipv4 = ipv4
            status.credential = row["credential_name"]
        return targets

    async def _sample_one(
        self, row: dict[str, Any], ipv4: str
    ) -> MetricSample | None:
        mac = row["mac"]
        status = self.statuses.setdefault(mac, MachineStatus(mac))

        if row["credential_id"] is None:
            # A configuration gap, not an unreachable host: reported per machine
            # so /admin/collector shows it.
            status.record_failure(
                "no credential bound: PUT /machines/{mac}/snmp-credential"
            )
            return None

        try:
            credential = await self._credentials.resolve(
                row["credential_id"], row["credential_secret_version"]
            )
        except Exception as exc:
            # Deleted credential or unopenable row: nothing to poll with, and
            # one machine must not fail the tick.
            status.record_failure(f"{type(exc).__name__}: {exc}")
            log.warning("credential unavailable for %s (%s): %s", mac, ipv4, exc)
            return None

        async with self._semaphore:
            try:
                # Baselines are keyed on the MAC so they survive a re-IP.
                metrics = await asyncio.wait_for(
                    self._sampler.sample(ipv4, mac, credential),
                    timeout=self._sample_budget,
                )
            except asyncio.TimeoutError:
                # The point is the slot: a dead host must not hold one all period.
                status.record_failure(
                    f"TimeoutError: no sample within {self._sample_budget:.1f}s"
                )
                log.warning(
                    "sample timed out for %s (%s) after %.1fs",
                    mac,
                    ipv4,
                    self._sample_budget,
                )
                return None
            except Exception as exc:
                status.record_failure(f"{type(exc).__name__}: {exc}")
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
            # What the loop achieves; matches the configured interval only
            # while ticks fit.
            "effective_interval_seconds": self.effective_interval,
            "overrun_count": self.overrun_count,
            "sample_budget_seconds": self._sample_budget,
            "concurrency": self._settings.collector_concurrency,
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
