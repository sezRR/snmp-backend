"""SNMP sampling: protocol and factory.

A sample is a plain dict, stored verbatim in the `metrics` jsonb column. Nothing
downstream declares its shape, so adding a metric here is the whole change —
no migration, no model edit.

Current shape:

    {"cpu":  {"usage_percent": 37.5, "cores": 4},
     "ram":  {"total_bytes": …, "used_bytes": …, "used_percent": …},
     "disk": [{"mount": "/", "total_bytes": …, "used_bytes": …, "used_percent": …}],
     "network": {"rx_bps": …, "tx_bps": …, "rx_bytes": …, "tx_bytes": …,
                 "interval_seconds": …,
                 "interfaces": [{"name": "eth0", "rx_bps": …, "tx_bps": …,
                                 "rx_bytes": …, "tx_bytes": …, "speed_bps": …,
                                 "rx_util_percent": …, "tx_util_percent": …}]}}

`rx_bps`/`tx_bps` are bytes per second over the interval since the previous
sample of that host, so they are null when there is no previous sample to
compare against; `rx_bytes`/`tx_bytes` are the agent's own cumulative counters.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol

from app.config import Settings

if TYPE_CHECKING:
    from app.services.openstack import CachedOpenStack

log = logging.getLogger(__name__)


class SnmpSampler(Protocol):
    async def sample(self, ipv4: str) -> dict[str, Any]: ...


class SnmpError(RuntimeError):
    """An agent did not answer, or answered with something unusable."""


def build_sampler(
    settings: Settings, lookup: "CachedOpenStack | None" = None
) -> SnmpSampler:
    if settings.snmp_simulate:
        from app.services.snmp.simulated import SimulatedSampler

        log.info("snmp: simulated sampler")
        return SimulatedSampler(hardware=_flavor_hardware(lookup) if lookup else None)

    from app.services.snmp.pysnmp_backend import PySnmpSampler

    log.info(
        "snmp: pysnmp v2c against port %s (timeout %ss, %s retries)",
        settings.snmp_port,
        settings.snmp_timeout_seconds,
        settings.snmp_retries,
    )
    return PySnmpSampler(
        community=settings.snmp_community,
        port=settings.snmp_port,
        timeout_seconds=settings.snmp_timeout_seconds,
        retries=settings.snmp_retries,
    )


def _flavor_hardware(lookup: "CachedOpenStack"):
    """Let the simulator size a host from its flavor, so the two agree.

    Only the simulator uses this; a real agent reports the guest's own hardware.
    """

    async def resolve(ipv4: str) -> tuple[int, int, int] | None:
        try:
            server = await lookup.by_ipv4(ipv4)
        except Exception:  # lookup down: fall back to seeded sizes
            return None
        if server is None:
            return None
        return (
            server.flavor.vcpus,
            server.flavor.ram_mb * 1024**2,
            server.flavor.disk_gb * 1024**3,
        )

    return resolve
