"""Simulated SNMP agent.

Produces the same payload shape as the pysnmp backend, so nothing downstream can
tell the difference. Each IPv4 gets its own seeded random walk, and the walk
state persists for the process lifetime, so history looks like a machine under
load rather than white noise.

Hardware sizes come from the machine's OpenStack flavor when a lookup is
supplied, so a reported 2 cores belongs to an `m1.medium` rather than
contradicting it. A real agent reports the guest's own view of its hardware,
which is exactly what the flavor says it is.

Bandwidth and disk I/O are walked as rates and their counters are integrated
from them, the reverse of the pysnmp backend which reads counters and
differentiates them. One consequence: here the first sample of a host already
carries a rate, whereas a real agent's first sample has nothing to subtract from
and reports null.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Awaitable, Callable
from uuid import UUID

from app.models.credential import ResolvedCredential

log = logging.getLogger(__name__)

_GIB = 1024**3
_MIB = 1024**2
_KIB = 1024

# (ipv4) -> (vcpus, ram_bytes, disk_bytes) or None when the address is unknown
HardwareResolver = Callable[[str], Awaitable[tuple[int, int, int] | None]]


class SimulatedSampler:
    """Implements the `SnmpSampler` protocol."""

    def __init__(self, hardware: HardwareResolver | None = None) -> None:
        self._state: dict[str, dict[str, float]] = {}
        self._hardware = hardware

    def forget_credential(self, credential_id: UUID) -> None:
        """Nothing to forget: this sampler holds no per-credential state."""

    def _profile(
        self, key: str, hardware: tuple[int, int, int] | None
    ) -> dict[str, float]:
        """Stable per-machine profile: flavor sizes if known, seeded if not.

        Seeded from the machine's key rather than its address, so a re-IP does
        not silently hand it different hardware.
        """
        rng = random.Random(key)
        if hardware is not None:
            cores, ram_total, disk_total = hardware
        else:
            cores = rng.choice([1, 2, 4, 8])
            ram_total = rng.choice([2, 4, 8, 16]) * _GIB
            disk_total = rng.choice([20, 40, 80, 160]) * _GIB
        link_bps = rng.choice([100, 1_000, 10_000]) * 1_000_000
        # Sustained throughput of the backing device: a spinning disk, a SATA
        # SSD or an NVMe. Everything about the disk series is scaled off this.
        disk_ceiling_bps = rng.choice([150, 500, 2_000]) * _MIB
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
            # Disk I/O. Reads dominate writes on most served workloads.
            "disk_ceiling_bps": disk_ceiling_bps,
            "read_bps": rng.uniform(0.02, 0.15) * disk_ceiling_bps,
            "write_bps": rng.uniform(0.01, 0.08) * disk_ceiling_bps,
            # Average request size, which is what turns a byte rate into an
            # operation rate. Small for a database, large for a media server.
            "read_request_bytes": rng.choice([4, 8, 16, 64, 128]) * _KIB,
            "write_request_bytes": rng.choice([4, 8, 32, 128]) * _KIB,
            "read_bytes": rng.uniform(10, 4_000) * _GIB,
            "write_bytes": rng.uniform(5, 2_000) * _GIB,
            "reads": rng.uniform(1e6, 5e8),
            "writes": rng.uniform(1e6, 2e8),
            "at": time.monotonic(),
        }

    @staticmethod
    def _walk(value: float, step: float, low: float, high: float) -> float:
        return min(high, max(low, value + random.uniform(-step, step)))

    async def sample(
        self, ipv4: str, key: str, credential: ResolvedCredential
    ) -> dict[str, Any]:
        # Accepted and ignored. There is no agent to authenticate to, so there
        # is nothing for a credential to be right or wrong against, and a
        # simulated validation would be a second implementation of the real
        # check — one that drifts from it and reports pass where pysnmp fails.
        # The binding is still exercised end to end: an unbound machine never
        # reaches this method, because the collector skips it first.
        log.debug("simulated sample of %s with credential %s", ipv4, credential.name)
        state = self._state.get(key)
        if state is None:
            hardware = await self._hardware(ipv4) if self._hardware else None
            state = self._state.setdefault(key, self._profile(key, hardware))

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

        # I/O is burstier still — a flush or a compaction moves the rate a long
        # way in one interval — so the step is a larger fraction of the device.
        io_ceiling = state["disk_ceiling_bps"]
        io_step = io_ceiling * 0.05
        io_floor = io_ceiling * 0.0005
        state["read_bps"] = self._walk(state["read_bps"], io_step, io_floor, io_ceiling)
        state["write_bps"] = self._walk(
            state["write_bps"], io_step, io_floor, io_ceiling
        )

        # Advance the counters by what the rates imply since the last sample, so
        # differentiating rx_bytes reproduces rx_bps to within one step.
        now = time.monotonic()
        elapsed = now - state["at"]
        state["at"] = now
        state["rx_bytes"] += state["rx_bps"] * elapsed
        state["tx_bytes"] += state["tx_bps"] * elapsed

        # IOPS follows from the byte rate and the average request size, which is
        # the relationship a real device has: the same 200 MB/s is 50k IOPS of
        # 4 KiB or 1.5k IOPS of 128 KiB.
        read_iops = state["read_bps"] / state["read_request_bytes"]
        write_iops = state["write_bps"] / state["write_request_bytes"]
        state["read_bytes"] += state["read_bps"] * elapsed
        state["write_bytes"] += state["write_bps"] * elapsed
        state["reads"] += read_iops * elapsed
        state["writes"] += write_iops * elapsed
        busy_percent = min(
            100.0, (state["read_bps"] + state["write_bps"]) / io_ceiling * 100
        )

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
            "disk_io": {
                "read_bps": round(state["read_bps"], 2),
                "write_bps": round(state["write_bps"], 2),
                "read_iops": round(read_iops, 2),
                "write_iops": round(write_iops, 2),
                "read_bytes": int(state["read_bytes"]),
                "write_bytes": int(state["write_bytes"]),
                "reads": int(state["reads"]),
                "writes": int(state["writes"]),
                "interval_seconds": round(elapsed, 3) if elapsed > 0 else None,
                "devices": [
                    {
                        "device": "vda",
                        "read_bytes": int(state["read_bytes"]),
                        "write_bytes": int(state["write_bytes"]),
                        "reads": int(state["reads"]),
                        "writes": int(state["writes"]),
                        "read_bps": round(state["read_bps"], 2),
                        "write_bps": round(state["write_bps"], 2),
                        "read_iops": round(read_iops, 2),
                        "write_iops": round(write_iops, 2),
                        # A real agent averages this over a minute; the
                        # simulator has no history to average, so it reports the
                        # instant value under the same name.
                        "busy_percent_1min": round(busy_percent, 2),
                        "counted": True,
                    }
                ],
            },
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
