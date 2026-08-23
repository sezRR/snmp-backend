import asyncio
import time
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock

from app.db import machines as machines_repo
from app.services.bus import MetricBus
from app.services.collector import Collector, MachineStatus


class CollectorStatusTests(IsolatedAsyncioTestCase):
    def make_collector(self, rows: list[dict[str, object]]) -> Collector:
        settings = SimpleNamespace(
            collector_concurrency=1,
            collector_enabled=True,
            collector_interval_seconds=5.0,
            collector_sample_timeout_seconds=1.0,
            collector_failure_backoff_max_seconds=600.0,
        )
        db = SimpleNamespace(run_query=AsyncMock(return_value=rows))
        lookup = SimpleNamespace(mac_index=AsyncMock(return_value={}))
        return Collector(
            settings=settings,
            db=db,
            sampler=AsyncMock(),
            lookup=lookup,
            bus=MetricBus(),
            credentials=AsyncMock(),
        )

    async def test_tick_removes_status_for_deregistered_machine(self) -> None:
        active_mac = "fa:16:3e:00:00:01"
        deleted_mac = "fa:fa:fa:fa:fa:fa"
        collector = self.make_collector(
            [
                {
                    "mac": active_mac,
                    "ipv4": "10.0.0.11",
                    "external": False,
                    "credential_id": None,
                    "credential_name": None,
                }
            ]
        )
        active_status = MachineStatus(active_mac)
        collector.statuses = {
            active_mac: active_status,
            deleted_mac: MachineStatus(deleted_mac),
        }

        await collector.tick()

        self.assertEqual(list(collector.statuses), [active_mac])
        self.assertIs(collector.statuses[active_mac], active_status)

    async def test_empty_tick_removes_all_machine_statuses(self) -> None:
        collector = self.make_collector([])
        collector.statuses["fa:fa:fa:fa:fa:fa"] = MachineStatus("fa:fa:fa:fa:fa:fa")

        await collector.tick()

        self.assertEqual(collector.statuses, {})

    async def test_deregister_machine_removes_status_without_another_tick(self) -> None:
        mac = "fa:fa:fa:fa:fa:fa"
        collector = self.make_collector([])
        collector._db.run_query.return_value = True
        collector.statuses[mac] = MachineStatus(mac)

        deleted = await collector.deregister_machine(mac)

        self.assertTrue(deleted)
        self.assertNotIn(mac, collector.statuses)

    async def test_deregister_machine_waits_for_in_flight_tick(self) -> None:
        mac = "fa:fa:fa:fa:fa:fa"
        collector = self.make_collector([])
        collector._db.run_query.return_value = True
        await collector._tick_lock.acquire()
        deregister = asyncio.create_task(collector.deregister_machine(mac))

        try:
            await asyncio.sleep(0)
            self.assertFalse(deregister.done())
            collector._db.run_query.assert_not_awaited()
        finally:
            collector._tick_lock.release()

        self.assertTrue(await deregister)
        collector._db.run_query.assert_awaited_once_with(machines_repo.delete, mac)


class FailureBackoffTests(IsolatedAsyncioTestCase):
    """A failing machine must not cost a full sample budget on every tick."""

    def status(self) -> MachineStatus:
        return MachineStatus("fa:16:3e:00:00:01")

    def test_first_failure_delays_by_one_interval(self) -> None:
        status = self.status()

        status.record_failure("boom", backoff_max_seconds=600.0, interval=10.0)

        self.assertEqual(status.consecutive_failures, 1)
        self.assertFalse(status.is_due(time.monotonic()))
        self.assertTrue(status.is_due(time.monotonic() + 10.1))

    def test_delay_doubles_with_each_consecutive_failure(self) -> None:
        status = self.status()
        delays = []
        for _ in range(4):
            before = time.monotonic()
            status.record_failure("boom", backoff_max_seconds=600.0, interval=10.0)
            delays.append(round(status.skip_until - before))

        self.assertEqual(delays, [10, 20, 40, 80])

    def test_delay_is_capped(self) -> None:
        status = self.status()
        for _ in range(20):
            status.record_failure("boom", backoff_max_seconds=60.0, interval=10.0)

        self.assertLessEqual(status.skip_until - time.monotonic(), 60.0)

    def test_a_week_of_failures_does_not_overflow(self) -> None:
        """2 ** 1024 exceeds float range, and the raise would kill the tick."""
        status = self.status()

        for _ in range(1200):
            status.record_failure("boom", backoff_max_seconds=600.0, interval=10.0)

        self.assertLessEqual(status.skip_until - time.monotonic(), 600.0)

    def test_success_clears_the_backoff(self) -> None:
        status = self.status()
        status.record_failure("boom", backoff_max_seconds=600.0, interval=10.0)

        status.record_success()

        self.assertEqual(status.consecutive_failures, 0)
        self.assertIsNone(status.skip_until)
        self.assertTrue(status.is_due(time.monotonic()))
        self.assertIsNone(status.retry_in_seconds)

    def test_zero_disables_the_backoff(self) -> None:
        status = self.status()

        status.record_failure("boom", backoff_max_seconds=0.0, interval=10.0)

        self.assertIsNone(status.skip_until)
        self.assertTrue(status.is_due(time.monotonic()))

    async def test_tick_skips_a_machine_inside_its_backoff_window(self) -> None:
        mac = "fa:16:3e:00:00:01"
        rows = [
            {
                "mac": mac,
                "ipv4": "10.0.0.11",
                "external": False,
                "credential_id": None,
                "credential_name": None,
            }
        ]
        settings = SimpleNamespace(
            collector_concurrency=1,
            collector_enabled=True,
            collector_interval_seconds=10.0,
            collector_sample_timeout_seconds=1.0,
            collector_failure_backoff_max_seconds=600.0,
        )
        collector = Collector(
            settings=settings,
            db=SimpleNamespace(run_query=AsyncMock(return_value=rows)),
            sampler=AsyncMock(),
            lookup=SimpleNamespace(mac_index=AsyncMock(return_value={})),
            bus=MetricBus(),
            credentials=AsyncMock(),
        )

        # First tick fails (no credential bound) and arms the backoff.
        await collector._tick()
        self.assertEqual(collector.last_failed, 1)
        self.assertEqual(collector.last_skipped, 0)

        # Second tick must not touch it at all.
        await collector._tick()
        self.assertEqual(collector.last_skipped, 1)
        self.assertEqual(collector.last_failed, 0)

        # A forced round ignores the backoff entirely.
        await collector.tick(force=True)
        self.assertEqual(collector.last_skipped, 0)
        self.assertEqual(collector.last_failed, 1)

        # ...and it stays visible in /admin/collector while it waits. The forced
        # attempt failed too, so it counts: two failures, a longer delay.
        entry = collector.status()["machines"][0]
        self.assertEqual(entry["consecutive_failures"], 2)
        self.assertIsNotNone(entry["retry_in_seconds"])
