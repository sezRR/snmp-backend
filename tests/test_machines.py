from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock

from app.api.routers.machines import delete_machine


class DeleteMachineTests(IsolatedAsyncioTestCase):
    async def test_delete_forgets_collector_status(self) -> None:
        mac = "fa:fa:fa:fa:fa:fa"
        collector = SimpleNamespace(deregister_machine=AsyncMock(return_value=True))

        await delete_machine(mac, collector)

        collector.deregister_machine.assert_awaited_once_with(mac)
