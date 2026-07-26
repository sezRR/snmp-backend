"""Real SNMP sampling with pysnmp (v2c).

Walks HOST-RESOURCES-MIB and IF-MIB by numeric OID rather than by name, so the
image needs no compiled MIB files:

* `hrProcessorLoad` — one row per CPU, percent busy over the last minute;
* `hrStorageTable` — one row per storage area, classified by `hrStorageType`
  into physical memory and fixed disks. Sizes are in allocation units, so bytes
  are `units * hrStorageAllocationUnits`.
* `ifXTable` / `ifTable` — per-interface octet counters. SNMP reports totals,
  not rates, so bandwidth is the delta against this process's previous sample of
  the same host divided by the elapsed time. The first sample of a host has
  nothing to subtract from and reports null rates.

Selected by `SNMP_SIMULATE=false`.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_walk_cmd,
)

from app.services.snmp import SnmpError

log = logging.getLogger(__name__)

HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOCATION_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"

HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"

# IF-MIB. The 64-bit ifXTable counters are preferred: a 32-bit octet counter
# wraps in under a minute on a 10G link, which no polling interval can follow.
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"

IF_TYPE_LOOPBACK = "24"
IF_OPER_STATUS_UP = 1

_COUNTER32_MODULUS = 2**32
_COUNTER64_MODULUS = 2**64


def _percent(used: int, total: int) -> float:
    return round(used / total * 100, 2) if total else 0.0


def _rate(previous: int, current: int, seconds: float, modulus: int) -> float | None:
    """Bytes/second between two counter reads.

    A counter that went backwards either wrapped or was reset by an agent
    restart. Wrapping is corrected; a delta still implying more than a terabit
    per second is treated as a reset and reported as null, because guessing
    would put a fictional spike into the history.
    """
    if seconds <= 0:
        return None
    delta = current - previous
    if delta < 0:
        delta += modulus
    rate = delta / seconds
    if rate * 8 > 1e12:
        return None
    return round(rate, 2)


class PySnmpSampler:
    """Implements the `SnmpSampler` protocol."""

    def __init__(
        self,
        community: str,
        port: int,
        timeout_seconds: float,
        retries: int,
        max_repetitions: int = 25,
    ) -> None:
        self._auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c
        self._port = port
        self._timeout = timeout_seconds
        self._retries = retries
        self._max_repetitions = max_repetitions
        # One engine for the process; it is safe to share across concurrent
        # requests and avoids re-running engine setup every 15 seconds.
        self._engine = SnmpEngine()
        self._context = ContextData()
        # (ipv4) -> (monotonic seconds, {if index: (in_octets, out_octets)}),
        # the previous read the bandwidth deltas are taken against. In memory
        # only: after a restart the first sample of each host reports no rate.
        self._counters: dict[str, tuple[float, dict[str, tuple[int, int]]]] = {}

    async def _walk(self, target, root_oid: str) -> dict[str, Any]:
        """GETBULK-walk one column, keyed by row index (the OID suffix)."""
        values: dict[str, Any] = {}
        prefix = root_oid + "."
        async for err_indication, err_status, err_index, var_binds in bulk_walk_cmd(
            self._engine,
            self._auth,
            target,
            self._context,
            0,
            self._max_repetitions,
            ObjectType(ObjectIdentity(root_oid)),
            lexicographicMode=False,
        ):
            if err_indication:
                raise SnmpError(str(err_indication))
            if err_status:
                raise SnmpError(f"{err_status.prettyPrint()} at index {err_index}")
            for oid, value in var_binds:
                oid_str = str(oid)
                if not oid_str.startswith(prefix):
                    continue
                values[oid_str[len(prefix) :]] = value
        return values

    async def _network(self, target, ipv4: str) -> dict[str, Any]:
        """Per-interface throughput, derived from the octet counters."""
        names = await self._walk(target, IF_NAME)
        if not names:  # agents without ifXTable still have ifDescr
            names = await self._walk(target, IF_DESCR)
        types = await self._walk(target, IF_TYPE)
        oper = await self._walk(target, IF_OPER_STATUS)
        hc_in = await self._walk(target, IF_HC_IN_OCTETS)
        hc_out = await self._walk(target, IF_HC_OUT_OCTETS)
        low_in = await self._walk(target, IF_IN_OCTETS) if not hc_in else {}
        low_out = await self._walk(target, IF_OUT_OCTETS) if not hc_out else {}
        high_speed = await self._walk(target, IF_HIGH_SPEED)
        speed = await self._walk(target, IF_SPEED)

        in_octets = hc_in or low_in
        out_octets = hc_out or low_out
        modulus = _COUNTER64_MODULUS if hc_in else _COUNTER32_MODULUS

        now = time.monotonic()
        previous_at, previous = self._counters.get(ipv4, (None, {}))
        elapsed = now - previous_at if previous_at is not None else 0.0

        current: dict[str, tuple[int, int]] = {}
        interfaces: list[dict[str, Any]] = []
        for index in sorted(in_octets, key=lambda i: (len(i), i)):
            if str(types.get(index, "")) == IF_TYPE_LOOPBACK:
                continue
            if index in oper and int(oper[index]) != IF_OPER_STATUS_UP:
                continue
            rx_bytes = int(in_octets[index])
            tx_bytes = int(out_octets.get(index, 0) or 0)
            current[index] = (rx_bytes, tx_bytes)

            was = previous.get(index)
            rx_bps = tx_bps = None
            if was is not None and elapsed > 0:
                rx_bps = _rate(was[0], rx_bytes, elapsed, modulus)
                tx_bps = _rate(was[1], tx_bytes, elapsed, modulus)

            # ifHighSpeed is Mbit/s and is 0 on agents that do not implement it;
            # ifSpeed is bit/s and saturates at ~4.29 Gbit/s.
            link_bps = int(high_speed.get(index, 0) or 0) * 1_000_000
            if not link_bps:
                link_bps = int(speed.get(index, 0) or 0)

            interfaces.append(
                {
                    "name": str(names.get(index, index)),
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                    "rx_bps": rx_bps,
                    "tx_bps": tx_bps,
                    "speed_bps": link_bps or None,
                    "rx_util_percent": _percent(int(rx_bps * 8), link_bps)
                    if rx_bps is not None and link_bps
                    else None,
                    "tx_util_percent": _percent(int(tx_bps * 8), link_bps)
                    if tx_bps is not None and link_bps
                    else None,
                }
            )

        self._counters[ipv4] = (now, current)

        # Host totals sum only the interfaces that had a usable rate, so one
        # wrapped counter does not drag the total down to a partial figure.
        rated = [i for i in interfaces if i["rx_bps"] is not None]
        return {
            "rx_bps": round(sum(i["rx_bps"] for i in rated), 2) if rated else None,
            "tx_bps": round(sum(i["tx_bps"] or 0.0 for i in rated), 2)
            if rated
            else None,
            "rx_bytes": sum(i["rx_bytes"] for i in interfaces),
            "tx_bytes": sum(i["tx_bytes"] for i in interfaces),
            "interval_seconds": round(elapsed, 3) if elapsed > 0 else None,
            "interfaces": interfaces,
        }

    async def sample(self, ipv4: str) -> dict[str, Any]:
        target = await UdpTransportTarget.create(
            (ipv4, self._port), timeout=self._timeout, retries=self._retries
        )

        loads = await self._walk(target, HR_PROCESSOR_LOAD)
        types = await self._walk(target, HR_STORAGE_TYPE)
        descrs = await self._walk(target, HR_STORAGE_DESCR)
        units = await self._walk(target, HR_STORAGE_ALLOCATION_UNITS)
        sizes = await self._walk(target, HR_STORAGE_SIZE)
        used = await self._walk(target, HR_STORAGE_USED)

        if not loads and not sizes:
            raise SnmpError(f"{ipv4} returned no HOST-RESOURCES-MIB rows")

        cpu_values = [int(v) for v in loads.values()]
        cpu: dict[str, Any] = {
            "usage_percent": round(sum(cpu_values) / len(cpu_values), 2)
            if cpu_values
            else None,
            "cores": len(cpu_values),
        }

        ram: dict[str, Any] = {}
        disks: list[dict[str, Any]] = []
        for index, size in sizes.items():
            unit = int(units.get(index, 0) or 0)
            total_bytes = int(size) * unit
            used_bytes = int(used.get(index, 0) or 0) * unit
            if total_bytes <= 0:
                continue
            storage_type = str(types.get(index, ""))
            descr = str(descrs.get(index, index))
            if storage_type == HR_STORAGE_RAM and not ram:
                ram = {
                    "total_bytes": total_bytes,
                    "used_bytes": used_bytes,
                    "used_percent": _percent(used_bytes, total_bytes),
                }
            elif storage_type == HR_STORAGE_FIXED_DISK:
                disks.append(
                    {
                        "mount": descr,
                        "total_bytes": total_bytes,
                        "used_bytes": used_bytes,
                        "used_percent": _percent(used_bytes, total_bytes),
                    }
                )

        try:
            network = await self._network(target, ipv4)
        except SnmpError as exc:
            # An agent that serves HOST-RESOURCES-MIB but not IF-MIB still has a
            # usable cpu/ram/disk sample; drop the key rather than the sample.
            log.warning("no interface counters from %s: %s", ipv4, exc)
            network = {}

        return {"cpu": cpu, "ram": ram, "disk": disks, "network": network}
