import asyncio
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
