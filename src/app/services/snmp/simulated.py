"""Simulated SNMP agent.

Produces the same payload shape as the pysnmp backend, so nothing downstream can
tell the difference. Each IPv4 gets its own seeded random walk, and the walk
state persists for the process lifetime, so history looks like a machine under
load rather than white noise.

Hardware sizes come from the machine's OpenStack flavor when a lookup is
supplied, so a reported 2 cores belongs to an `m1.medium` rather than
contradicting it. A real agent reports the guest's own view of its hardware,
which is exactly what the flavor says it is.

Bandwidth is walked as a rate and the octet counters are integrated from it, the
reverse of the pysnmp backend which reads counters and differentiates them. One
consequence: here the first sample of a host already carries a rate, whereas a
real agent's first sample has nothing to subtract from and reports null.
"""

from __future__ import annotations

import random
import time
from typing import Any, Awaitable, Callable

_GIB = 1024**3
_MIB = 1024**2

# (ipv4) -> (vcpus, ram_bytes, disk_bytes) or None when the address is unknown
HardwareResolver = Callable[[str], Awaitable[tuple[int, int, int] | None]]


class SimulatedSampler:
    """Implements the `SnmpSampler` protocol."""

    def __init__(self, hardware: HardwareResolver | None = None) -> None:
        self._state: dict[str, dict[str, float]] = {}
        self._hardware = hardware

    def _profile(
        self, ipv4: str, hardware: tuple[int, int, int] | None
    ) -> dict[str, float]:
        """Stable per-host profile: flavor sizes if known, seeded sizes if not."""
        rng = random.Random(ipv4)
        if hardware is not None:
            cores, ram_total, disk_total = hardware
        else:
            cores = rng.choice([1, 2, 4, 8])
            ram_total = rng.choice([2, 4, 8, 16]) * _GIB
            disk_total = rng.choice([20, 40, 80, 160]) * _GIB
        link_bps = rng.choice([100, 1_000, 10_000]) * 1_000_000
        return {
            "cores": cores,
            "ram_total": ram_total,
            "disk_total": disk_total,
            "cpu": rng.uniform(10, 60),
            "ram_pct": rng.uniform(30, 70),
            "disk_pct": rng.uniform(20, 60),
            "link_bps": link_bps,
            # Bytes/second, walked like the others. Downstream is more egress
            # than ingress, which is the usual shape for a served workload.
            "rx_bps": rng.uniform(0.005, 0.05) * link_bps / 8,
            "tx_bps": rng.uniform(0.01, 0.10) * link_bps / 8,
            # Counters start non-zero: a real agent has been up a while.
            "rx_bytes": rng.uniform(1, 500) * _GIB,
            "tx_bytes": rng.uniform(1, 500) * _GIB,
            "at": time.monotonic(),
        }

    @staticmethod
    def _walk(value: float, step: float, low: float, high: float) -> float:
        return min(high, max(low, value + random.uniform(-step, step)))

    async def sample(self, ipv4: str) -> dict[str, Any]:
        state = self._state.get(ipv4)
        if state is None:
            hardware = await self._hardware(ipv4) if self._hardware else None
            state = self._state.setdefault(ipv4, self._profile(ipv4, hardware))

        state["cpu"] = self._walk(state["cpu"], 8.0, 0.5, 99.0)
        state["ram_pct"] = self._walk(state["ram_pct"], 2.0, 5.0, 97.0)
        # Disks fill slowly and rarely empty.
        state["disk_pct"] = self._walk(state["disk_pct"], 0.3, 5.0, 95.0)

        link_bps = state["link_bps"]
        ceiling = link_bps / 8 * 0.9  # a NIC never sustains its rated line rate
        # Traffic is burstier than the other series, so the step is a fraction
        # of the link rather than of the current value. The floor stays above
        # zero: an idle host still carries background chatter, and a series
        # pinned at 0 tells a dashboard nothing.
        step = ceiling * 0.02
        floor = ceiling * 0.001
        state["rx_bps"] = self._walk(state["rx_bps"], step, floor, ceiling)
        state["tx_bps"] = self._walk(state["tx_bps"], step, floor, ceiling)

        # Advance the counters by what the rates imply since the last sample, so
        # differentiating rx_bytes reproduces rx_bps to within one step.
        now = time.monotonic()
        elapsed = now - state["at"]
        state["at"] = now
        state["rx_bytes"] += state["rx_bps"] * elapsed
        state["tx_bytes"] += state["tx_bps"] * elapsed

        ram_total = int(state["ram_total"])
        disk_total = int(state["disk_total"])
        return {
            "cpu": {
                "usage_percent": round(state["cpu"], 2),
                "cores": int(state["cores"]),
            },
            "ram": {
                "total_bytes": ram_total,
                "used_bytes": int(ram_total * state["ram_pct"] / 100),
                "used_percent": round(state["ram_pct"], 2),
            },
            "disk": [
                {
                    "mount": "/",
                    "total_bytes": disk_total,
                    "used_bytes": int(disk_total * state["disk_pct"] / 100),
                    "used_percent": round(state["disk_pct"], 2),
                }
            ],
            "network": {
                "rx_bps": round(state["rx_bps"], 2),
                "tx_bps": round(state["tx_bps"], 2),
                "rx_bytes": int(state["rx_bytes"]),
                "tx_bytes": int(state["tx_bytes"]),
                "interval_seconds": round(elapsed, 3) if elapsed > 0 else None,
                "interfaces": [
                    {
                        "name": "eth0",
                        "rx_bytes": int(state["rx_bytes"]),
                        "tx_bytes": int(state["tx_bytes"]),
                        "rx_bps": round(state["rx_bps"], 2),
                        "tx_bps": round(state["tx_bps"], 2),
                        "speed_bps": int(link_bps),
                        "rx_util_percent": round(
                            state["rx_bps"] * 8 / link_bps * 100, 2
                        ),
                        "tx_util_percent": round(
                            state["tx_bps"] * 8 / link_bps * 100, 2
                        ),
                    }
                ],
            },
        }
