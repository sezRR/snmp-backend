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

# (name, tenant, user, flavor, mac, ipv4, subnet, status)
_FLEET = [
    ("web-01", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:01", "10.0.0.11", "prod-mgmt", "ACTIVE"),
    ("web-02", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:02", "10.0.0.12", "prod-mgmt", "ACTIVE"),
    ("api-01", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:03", "10.0.0.13", "prod-mgmt", "ACTIVE"),
    ("db-01", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:04", "10.0.0.14", "prod-mgmt", "ACTIVE"),
    ("batch-01", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:05", "10.0.1.21", "staging-mgmt", "ACTIVE"),
    ("gpu-01", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:06", "10.0.2.31", "research-mgmt", "SHUTOFF"),
    # Everything below is discoverable but deliberately not registered by
    # `scripts/seed_dev.py`: the lookup knows them, `machines` does not, so
    # they exercise the unregistered half of the fleet.
    ("web-03", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:07", "10.0.0.15", "prod-mgmt", "ACTIVE"),
    ("web-04", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:08", "10.0.0.16", "prod-mgmt", "ACTIVE"),
    ("web-05", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:09", "10.0.0.17", "prod-mgmt", "ACTIVE"),
    ("web-06", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0a", "10.0.0.18", "prod-mgmt", "ACTIVE"),
    ("web-07", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0b", "10.0.0.19", "prod-mgmt", "ACTIVE"),
    ("web-08", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0c", "10.0.0.20", "prod-mgmt", "ACTIVE"),
    ("web-09", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0d", "10.0.0.21", "prod-mgmt", "ACTIVE"),
    ("web-10", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0e", "10.0.0.22", "prod-mgmt", "ACTIVE"),
    ("web-11", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:0f", "10.0.0.23", "prod-mgmt", "ACTIVE"),
    ("web-12", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:10", "10.0.0.24", "prod-mgmt", "ACTIVE"),
    ("api-02", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:11", "10.0.0.25", "prod-mgmt", "ACTIVE"),
    ("api-03", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:12", "10.0.0.26", "prod-mgmt", "ACTIVE"),
    ("api-04", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:13", "10.0.0.27", "prod-mgmt", "ACTIVE"),
    ("api-05", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:14", "10.0.0.28", "prod-mgmt", "ACTIVE"),
    ("api-06", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:15", "10.0.0.29", "prod-mgmt", "ACTIVE"),
    ("api-07", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:16", "10.0.0.30", "prod-mgmt", "ACTIVE"),
    ("api-08", "acme-prod", "bob", "m1.medium", "fa:16:3e:00:00:17", "10.0.0.31", "prod-mgmt", "ACTIVE"),
    ("db-02", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:18", "10.0.0.32", "prod-mgmt", "ACTIVE"),
    ("db-03", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:19", "10.0.0.33", "prod-mgmt", "ACTIVE"),
    ("db-04", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:1a", "10.0.0.34", "prod-mgmt", "ACTIVE"),
    ("db-05", "acme-prod", "bob", "m1.large", "fa:16:3e:00:00:1b", "10.0.0.35", "prod-mgmt", "ACTIVE"),
    ("cache-01", "acme-prod", "alice", "m1.medium", "fa:16:3e:00:00:1c", "10.0.0.36", "prod-mgmt", "ACTIVE"),
    ("cache-02", "acme-prod", "alice", "m1.medium", "fa:16:3e:00:00:1d", "10.0.0.37", "prod-mgmt", "ACTIVE"),
    ("cache-03", "acme-prod", "alice", "m1.medium", "fa:16:3e:00:00:1e", "10.0.0.38", "prod-mgmt", "ACTIVE"),
    ("cache-04", "acme-prod", "alice", "m1.medium", "fa:16:3e:00:00:1f", "10.0.0.39", "prod-mgmt", "ACTIVE"),
    ("lb-01", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:20", "10.0.0.40", "prod-mgmt", "ACTIVE"),
    ("lb-02", "acme-prod", "alice", "m1.small", "fa:16:3e:00:00:21", "10.0.0.41", "prod-mgmt", "ACTIVE"),
    ("batch-02", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:22", "10.0.1.22", "staging-mgmt", "ACTIVE"),
    ("batch-03", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:23", "10.0.1.23", "staging-mgmt", "ACTIVE"),
    ("batch-04", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:24", "10.0.1.24", "staging-mgmt", "ACTIVE"),
    ("batch-05", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:25", "10.0.1.25", "staging-mgmt", "ACTIVE"),
    ("batch-06", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:26", "10.0.1.26", "staging-mgmt", "ACTIVE"),
    ("stg-web-01", "acme-staging", "carol", "m1.small", "fa:16:3e:00:00:27", "10.0.1.27", "staging-mgmt", "ACTIVE"),
    ("stg-web-02", "acme-staging", "carol", "m1.small", "fa:16:3e:00:00:28", "10.0.1.28", "staging-mgmt", "ACTIVE"),
    ("stg-web-03", "acme-staging", "carol", "m1.small", "fa:16:3e:00:00:29", "10.0.1.29", "staging-mgmt", "ACTIVE"),
    ("stg-web-04", "acme-staging", "carol", "m1.small", "fa:16:3e:00:00:2a", "10.0.1.30", "staging-mgmt", "ACTIVE"),
    ("stg-api-01", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:2b", "10.0.1.31", "staging-mgmt", "ACTIVE"),
    ("stg-api-02", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:2c", "10.0.1.32", "staging-mgmt", "ACTIVE"),
    ("stg-api-03", "acme-staging", "carol", "m1.medium", "fa:16:3e:00:00:2d", "10.0.1.33", "staging-mgmt", "ACTIVE"),
    ("stg-db-01", "acme-staging", "carol", "m1.large", "fa:16:3e:00:00:2e", "10.0.1.34", "staging-mgmt", "SHUTOFF"),
    ("gpu-02", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:2f", "10.0.2.32", "research-mgmt", "ACTIVE"),
    ("gpu-03", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:30", "10.0.2.33", "research-mgmt", "ACTIVE"),
    ("gpu-04", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:31", "10.0.2.34", "research-mgmt", "ACTIVE"),
    ("gpu-05", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:32", "10.0.2.35", "research-mgmt", "ACTIVE"),
    ("gpu-06", "acme-research", "dave", "m1.xlarge", "fa:16:3e:00:00:33", "10.0.2.36", "research-mgmt", "SHUTOFF"),
    ("ml-01", "acme-research", "dave", "m1.large", "fa:16:3e:00:00:34", "10.0.2.37", "research-mgmt", "ACTIVE"),
    ("ml-02", "acme-research", "dave", "m1.large", "fa:16:3e:00:00:35", "10.0.2.38", "research-mgmt", "ACTIVE"),
    ("ml-03", "acme-research", "dave", "m1.large", "fa:16:3e:00:00:36", "10.0.2.39", "research-mgmt", "ACTIVE"),
    ("nb-01", "acme-research", "dave", "m1.medium", "fa:16:3e:00:00:37", "10.0.2.40", "research-mgmt", "ACTIVE"),
    ("nb-02", "acme-research", "dave", "m1.medium", "fa:16:3e:00:00:38", "10.0.2.41", "research-mgmt", "SHUTOFF"),
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
                subnet_name=subnet,
                flavor=_FLAVORS[flavor],
            )
            for i, (
                name,
                tenant,
                user,
                flavor,
                mac,
                ipv4,
                subnet,
                status,
            ) in enumerate(_FLEET, start=1)
        ]

    def close(self) -> None:
        pass
