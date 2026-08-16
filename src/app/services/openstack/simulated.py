"""A fake OpenStack fleet.

Selected instead of the read-only SDK adapter for local development. The fleet
is static and deterministic so the same IPv4 always resolves to the same MAC,
tenant, user and flavor across restarts — registrations survive a redeploy.
"""

from __future__ import annotations

import asyncio

from app.models.openstack import FlavorInfo, ServerInfo

_FLAVORS = {
    "m1.small": FlavorInfo(name="m1.small", vcpus=1, ram_mb=2048, disk_gb=20),
    "m1.medium": FlavorInfo(name="m1.medium", vcpus=2, ram_mb=4096, disk_gb=40),
    "m1.large": FlavorInfo(name="m1.large", vcpus=4, ram_mb=8192, disk_gb=80),
    "m1.xlarge": FlavorInfo(name="m1.xlarge", vcpus=8, ram_mb=16384, disk_gb=160),
}

# (name, tenant, user, flavor, mac, ipv4, status)
_FLEET = [
    ("web-01", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:01", "10.0.0.11", "ACTIVE"),
    ("web-02", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:02", "10.0.0.12", "ACTIVE"),
    ("api-01", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:03", "10.0.0.13", "ACTIVE"),
    ("db-01", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:04", "10.0.0.14", "ACTIVE"),
    ("batch-01", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:05", "10.0.1.21", "ACTIVE"),
    ("gpu-01", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:06", "10.0.2.31", "SHUTOFF"),
]


class SimulatedOpenStack:
    """Implements the `OpenStackLookup` protocol."""

    def __init__(self, latency_seconds: float = 0.05) -> None:
        # A real Nova/Keystone round trip is not free; keeping a little latency
        # here means the cache is doing visible work.
        self._latency_seconds = latency_seconds

    async def servers(self) -> list[ServerInfo]:
        await asyncio.sleep(self._latency_seconds)
        return [
            ServerInfo(
                server_id=f"11111111-0000-4000-8000-{i:012d}",
                name=name,
                tenant_name=tenant,
                user_name=user,
                status=status,
                mac=mac,
                ipv4=ipv4,
                flavor=_FLAVORS[flavor],
            )
            for i, (name, tenant, user, flavor, mac, ipv4, status) in enumerate(
                _FLEET, start=1
            )
        ]

    def close(self) -> None:
        pass
