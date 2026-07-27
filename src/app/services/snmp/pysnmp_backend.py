"""Real SNMP sampling with pysnmp (v2c).

Walks HOST-RESOURCES-MIB, IF-MIB and UCD's DISKIO-MIB by numeric OID rather than
by name, so the image needs no compiled MIB files:

* `hrProcessorLoad` — one row per CPU, percent busy over the last minute;
* `hrStorageTable` — one row per storage area, classified by `hrStorageType`
  into physical memory and fixed disks. Sizes are in allocation units, so bytes
  are `units * hrStorageAllocationUnits`.
* `ifXTable` / `ifTable` — per-interface octet counters;
* `diskIOTable` — per-block-device byte and operation counters.

SNMP reports totals, not rates, so every throughput and IOPS figure is the delta
against this process's previous sample of the same machine divided by the elapsed
time. The first sample of a machine has nothing to subtract from and reports null
rates.

The three tables are walked concurrently, and the columns within each table are
walked concurrently too. Done serially this is twenty-odd round trips per machine
per tick, which is what decides whether a short interval is reachable at all.

Every one of those subtrees has to be inside the agent's view, and the stock
Debian/Ubuntu view (`system` plus `hrSystem` only) contains none of them. An agent
left that way answers each walk with nothing at all, which arrives here as "no
HOST-RESOURCES-MIB rows" rather than as a permission error:

    view   fleet  included  .1.3.6.1.2.1.1            # system
    view   fleet  included  .1.3.6.1.2.1.2            # ifTable
    view   fleet  included  .1.3.6.1.2.1.25           # host resources
    view   fleet  included  .1.3.6.1.2.1.31           # ifXTable
    view   fleet  included  .1.3.6.1.4.1.2021.13.15   # diskIO

DISKIO-MIB additionally needs an snmpd that ships the `ucd-snmp/diskio` module.
Without it that walk comes back empty and the `disk_io` key is simply dropped.

Selected by `SNMP_SIMULATE=false`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
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
from pysnmp.proto import errind

from app.services.snmp import SnmpError

log = logging.getLogger(__name__)

HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOCATION_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"

HR_STORAGE_OTHER = "1.3.6.1.2.1.25.2.1.1"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"

# net-snmp files its extra memory readings under hrStorageOther and identifies
# them only by description, so these strings are the whole contract. An agent
# that names them differently falls back to the raw hrStorageUsed figure.
MEM_AVAILABLE_DESCR = "Available memory"
MEM_BUFFERS_DESCR = "Memory buffers"
MEM_CACHED_DESCR = "Cached memory"

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

# UCD DISKIO-MIB. Same 32-vs-64-bit story as IF-MIB, and worse: a 32-bit *byte*
# counter wraps every 8.6 seconds on a device sustaining 500 MB/s, so the X
# columns are strongly preferred. There is no 64-bit variant of the operation
# counters, but those wrap after 4.29 billion operations, which no realistic
# interval can miss.
DISK_IO_DEVICE = "1.3.6.1.4.1.2021.13.15.1.1.2"
DISK_IO_NREAD = "1.3.6.1.4.1.2021.13.15.1.1.3"
DISK_IO_NWRITTEN = "1.3.6.1.4.1.2021.13.15.1.1.4"
DISK_IO_READS = "1.3.6.1.4.1.2021.13.15.1.1.5"
DISK_IO_WRITES = "1.3.6.1.4.1.2021.13.15.1.1.6"
DISK_IO_LA1 = "1.3.6.1.4.1.2021.13.15.1.1.9"
DISK_IO_NREADX = "1.3.6.1.4.1.2021.13.15.1.1.12"
DISK_IO_NWRITTENX = "1.3.6.1.4.1.2021.13.15.1.1.13"

IF_TYPE_LOOPBACK = "24"
IF_OPER_STATUS_UP = 1

_COUNTER32_MODULUS = 2**32
_COUNTER64_MODULUS = 2**64

# Devices excluded from the host totals. The kernel reports a device-mapper or
# md device *and* the disks underneath it, and a partition *and* its whole disk,
# so summing every row would count the same I/O two or three times. They still
# appear in `devices` with their own rates — they are just not added up.
_VIRTUAL_DEVICE_PREFIXES = ("loop", "ram", "sr", "fd", "dm-", "md")
_PARTITION_RE = re.compile(r"^(?:[hsvx]v?d[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$")

# Counter baselines for a machine that has not been sampled in this long are
# dropped. Long enough that a machine merely disabled for a while keeps its
# baseline; short enough that a fleet with churn does not leak.
_COUNTER_TTL_SECONDS = 3600.0
_PRUNE_EVERY_SECONDS = 300.0


class _WalkTimeout(SnmpError):
    """No response at all — as opposed to an answer we could not use.

    Separated from the rest because it is the one failure the bulk size can do
    something about; every other error means the agent replied.
    """


def _percent(used: int, total: int) -> float:
    return round(used / total * 100, 2) if total else 0.0


def _apply_reclaimable_memory(
    ram: dict[str, Any], memory_rows: dict[str, tuple[int, int]]
) -> None:
    """Restate memory usage the way the kernel does, in place.

    `hrStorageUsed` for physical memory is `MemTotal - MemFree`, so every page
    the kernel is using as page cache counts as used. On a host that has been up
    for a while that reads as ~95% used while several hundred megabytes are in
    fact free for the asking, which is not what the number is taken to mean.

    net-snmp publishes `MemAvailable` as a separate storage row — the kernel's
    own estimate of what a new allocation could get, cache eviction included —
    and `total - available` is then exactly the "used" column of `free`. Where
    that row is missing (older agents), buffers and cache are subtracted
    directly, which is the same idea and a slightly worse estimate. Where
    neither is there, the raw figure stands.

    `used_bytes` and `used_percent` keep their names because they keep their
    meaning; the components are added beside them so the reading can be
    reconstructed rather than taken on faith.
    """
    total = ram["total_bytes"]
    available = memory_rows.get(MEM_AVAILABLE_DESCR, (0, 0))[0]
    buffers = memory_rows.get(MEM_BUFFERS_DESCR, (0, 0))[1]
    cached = memory_rows.get(MEM_CACHED_DESCR, (0, 0))[1]

    if available > 0:
        used = max(0, total - available)
    elif buffers or cached:
        used = max(0, ram["used_bytes"] - buffers - cached)
        available = max(0, total - used)
    else:
        return

    ram["used_bytes"] = used
    ram["used_percent"] = _percent(used, total)
    ram["available_bytes"] = available
    ram["buffers_bytes"] = buffers or None
    ram["cached_bytes"] = cached or None


def _counts_toward_total(device: str) -> bool:
    name = device.strip()
    if name.startswith(_VIRTUAL_DEVICE_PREFIXES):
        return False
    return not _PARTITION_RE.match(name)


def _rate(
    previous: int,
    current: int,
    seconds: float,
    modulus: int,
    wrap_is_ambiguous: bool = False,
) -> float | None:
    """Units per second between two counter reads.

    A counter that went backwards either wrapped or was reset by an agent
    restart. Wrapping is corrected; a delta still implying more than a terabit
    per second is treated as a reset and reported as null, because guessing
    would put a fictional spike into the history.

    `wrap_is_ambiguous` is for counters narrow enough to wrap more than once
    within one interval — a 32-bit byte counter on a fast disk. There a single
    correction is no more likely to be right than any other multiple, so the
    sample reports null instead of inventing a number.
    """
    if seconds <= 0:
        return None
    delta = current - previous
    if delta < 0:
        if wrap_is_ambiguous:
            return None
        delta += modulus
    rate = delta / seconds
    if rate * 8 > 1e12:
        return None
    return round(rate, 2)


@dataclass
class _CounterState:
    """The previous counter read a machine's rates are taken against.

    Each table carries its own timestamp. A tick where IF-MIB answered but
    DISKIO-MIB did not must not reset the disk baseline: keeping them separate
    means the next successful disk walk measures across the real elapsed span
    rather than reporting null all over again.

    In memory only: after a restart the first sample of each machine reports no
    rates.
    """

    interfaces_at: float | None = None
    interfaces: dict[str, tuple[int, int]] = field(default_factory=dict)
    disks_at: float | None = None
    # device -> (read_bytes, write_bytes, reads, writes)
    disks: dict[str, tuple[int, int, int, int]] = field(default_factory=dict)

    @property
    def seen_at(self) -> float:
        return max(self.interfaces_at or 0.0, self.disks_at or 0.0)


class PySnmpSampler:
    """Implements the `SnmpSampler` protocol."""

    def __init__(
        self,
        community: str,
        port: int,
        timeout_seconds: float,
        retries: int,
        max_repetitions: int = 25,
        diskio_enabled: bool = True,
    ) -> None:
        self._auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c
        self._port = port
        self._timeout = timeout_seconds
        self._retries = retries
        self._max_repetitions = max_repetitions
        self._diskio_enabled = diskio_enabled
        # One engine for the process; it is safe to share across concurrent
        # requests and avoids re-running engine setup every interval.
        self._engine = SnmpEngine()
        self._context = ContextData()
        # Machine key (its MAC, not its address) -> previous counter read.
        self._counters: dict[str, _CounterState] = {}
        # Address -> bulk size that host's path was found to tolerate. Keyed on
        # the address rather than the MAC because it describes the network
        # between here and there, which is what a re-IP actually changes.
        self._repetitions: dict[str, int] = {}
        self._last_prune = time.monotonic()
        # Hosts already warned about, so a permanent condition logs once rather
        # than every interval.
        self._warned_diskio32: set[str] = set()

    # ---- transport ----------------------------------------------------------

    async def _walk_once(self, target, root_oid: str, repetitions: int) -> dict[str, Any]:
        """GETBULK-walk one column, keyed by row index (the OID suffix)."""
        values: dict[str, Any] = {}
        prefix = root_oid + "."
        async for err_indication, err_status, err_index, var_binds in bulk_walk_cmd(
            self._engine,
            self._auth,
            target,
            self._context,
            0,
            repetitions,
            ObjectType(ObjectIdentity(root_oid)),
            lexicographicMode=False,
        ):
            if err_indication:
                if isinstance(err_indication, errind.RequestTimedOut):
                    raise _WalkTimeout(str(err_indication))
                raise SnmpError(str(err_indication))
            if err_status:
                raise SnmpError(f"{err_status.prettyPrint()} at index {err_index}")
            for oid, value in var_binds:
                oid_str = str(oid)
                if not oid_str.startswith(prefix):
                    continue
                values[oid_str[len(prefix) :]] = value
        return values

    async def _walk(self, target, host: str, root_oid: str) -> dict[str, Any]:
        """Walk one column, backing off the bulk size if the reply never arrives.

        A response too large for the smallest MTU on the path is fragmented, and a
        path that drops fragments — a tunnel, a NAT — turns that into a plain
        timeout. Which tables are affected depends on the agent's data, not on its
        configuration: the same twenty-five rows fit comfortably for one host and
        do not for another whose mount points happen to be long.

        So the size is not a constant to be guessed right once. On a timeout the
        walk halves it and tries again, and the result is remembered for the host,
        so the cost is paid once rather than every tick. It is never raised again
        within the process: the condition that forced it down is a property of the
        path, and probing for its disappearance every interval would reintroduce
        exactly the timeout it is avoiding. A restart re-reads the configured value.
        """
        repetitions = self._repetitions.get(host, self._max_repetitions)
        while True:
            try:
                return await self._walk_once(target, root_oid, repetitions)
            except _WalkTimeout:
                if repetitions <= 1:
                    # One row per response and it still does not arrive: this is
                    # not a size problem, so report it as the timeout it is.
                    raise
                repetitions = max(1, repetitions // 2)
                self._repetitions[host] = repetitions
                log.warning(
                    "%s: walk of %s timed out; retrying with max-repetitions %s "
                    "(likely an oversized response on a path that drops fragments)",
                    host,
                    root_oid,
                    repetitions,
                )

    async def _walk_all(self, target, host: str, *root_oids: str) -> list[dict[str, Any]]:
        """Walk several columns at once. One round trip's latency, not N."""
        return list(
            await asyncio.gather(*(self._walk(target, host, oid) for oid in root_oids))
        )

    # ---- host resources -----------------------------------------------------

    async def _host_resources(self, target, host: str) -> dict[str, Any]:
        """CPU load and the storage table: memory and mounted filesystems."""
        loads, types, descrs, units, sizes, used = await self._walk_all(
            target,
            host,
            HR_PROCESSOR_LOAD,
            HR_STORAGE_TYPE,
            HR_STORAGE_DESCR,
            HR_STORAGE_ALLOCATION_UNITS,
            HR_STORAGE_SIZE,
            HR_STORAGE_USED,
        )

        if not loads and not sizes:
            raise SnmpError("no HOST-RESOURCES-MIB rows")

        cpu_values = [int(v) for v in loads.values()]
        cpu: dict[str, Any] = {
            "usage_percent": round(sum(cpu_values) / len(cpu_values), 2)
            if cpu_values
            else None,
            "cores": len(cpu_values),
        }

        # The memory rows net-snmp reports outside hrStorageRam, keyed by their
        # description, so the physical-memory row can be corrected below.
        memory_rows: dict[str, tuple[int, int]] = {}

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
            if storage_type == HR_STORAGE_OTHER:
                memory_rows[descr] = (total_bytes, used_bytes)
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

        if ram:
            _apply_reclaimable_memory(ram, memory_rows)

        return {"cpu": cpu, "ram": ram, "disk": disks}

    # ---- network ------------------------------------------------------------

    async def _network(
        self, target, host: str, now: float, state: _CounterState
    ) -> tuple[dict[str, Any], dict[str, tuple[int, int]]]:
        """Per-interface throughput, derived from the octet counters.

        Returns the payload and the counter snapshot to remember. It does not
        write `self._counters` itself: this runs concurrently with the disk walk
        and the two would clobber each other's half of the state.
        """
        names, types, oper, hc_in, hc_out, high_speed, speed = await self._walk_all(
            target,
            host,
            IF_NAME,
            IF_TYPE,
            IF_OPER_STATUS,
            IF_HC_IN_OCTETS,
            IF_HC_OUT_OCTETS,
            IF_HIGH_SPEED,
            IF_SPEED,
        )

        # Second round, only for what the first round did not answer. Modern
        # agents skip it entirely, and asking for the 32-bit counters
        # unconditionally would put load on every agent to serve the minority.
        fallbacks: list[str] = []
        if not names:  # agents without ifXTable still have ifDescr
            fallbacks.append(IF_DESCR)
        if not hc_in:
            fallbacks.extend((IF_IN_OCTETS, IF_OUT_OCTETS))
        if fallbacks:
            answered = dict(
                zip(fallbacks, await self._walk_all(target, host, *fallbacks))
            )
            names = names or answered.get(IF_DESCR, {})
            low_in = answered.get(IF_IN_OCTETS, {})
            low_out = answered.get(IF_OUT_OCTETS, {})
        else:
            low_in = low_out = {}

        in_octets = hc_in or low_in
        out_octets = hc_out or low_out
        modulus = _COUNTER64_MODULUS if hc_in else _COUNTER32_MODULUS

        previous = state.interfaces
        elapsed = now - state.interfaces_at if state.interfaces_at is not None else 0.0

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

        # Host totals sum only the interfaces that had a usable rate, so one
        # wrapped counter does not drag the total down to a partial figure.
        rated = [i for i in interfaces if i["rx_bps"] is not None]
        payload = {
            "rx_bps": round(sum(i["rx_bps"] for i in rated), 2) if rated else None,
            "tx_bps": round(sum(i["tx_bps"] or 0.0 for i in rated), 2)
            if rated
            else None,
            "rx_bytes": sum(i["rx_bytes"] for i in interfaces),
            "tx_bytes": sum(i["tx_bytes"] for i in interfaces),
            "interval_seconds": round(elapsed, 3) if elapsed > 0 else None,
            "interfaces": interfaces,
        }
        return payload, current

    # ---- disk i/o -----------------------------------------------------------

    async def _disk_io(
        self, target, ipv4: str, now: float, state: _CounterState
    ) -> tuple[dict[str, Any], dict[str, tuple[int, int, int, int]]]:
        """Per-device throughput and IOPS, derived from the diskIO counters.

        Same contract as `_network`: returns the payload and the snapshot to
        remember, without touching `self._counters`.
        """
        devices, read_x, written_x, reads_c, writes_c, la1 = await self._walk_all(
            target,
            ipv4,
            DISK_IO_DEVICE,
            DISK_IO_NREADX,
            DISK_IO_NWRITTENX,
            DISK_IO_READS,
            DISK_IO_WRITES,
            DISK_IO_LA1,
        )

        if not devices:
            raise SnmpError("no DISKIO-MIB rows")

        # The 32-bit byte columns are a last resort: they wrap every 4.29 GB,
        # which a device doing 500 MB/s manages in under nine seconds.
        narrow_bytes = not read_x
        if narrow_bytes:
            read_x, written_x = await self._walk_all(
                target, ipv4, DISK_IO_NREAD, DISK_IO_NWRITTEN
            )
            if ipv4 not in self._warned_diskio32:
                self._warned_diskio32.add(ipv4)
                log.warning(
                    "%s serves no 64-bit diskIO counters; throughput will be "
                    "reported as null whenever the 32-bit counters wrap",
                    ipv4,
                )

        byte_modulus = _COUNTER32_MODULUS if narrow_bytes else _COUNTER64_MODULUS
        previous = state.disks
        elapsed = now - state.disks_at if state.disks_at is not None else 0.0

        current: dict[str, tuple[int, int, int, int]] = {}
        entries: list[dict[str, Any]] = []
        for index in sorted(devices, key=lambda i: (len(i), i)):
            name = str(devices[index]).strip()
            if not name:
                continue
            read_bytes = int(read_x.get(index, 0) or 0)
            write_bytes = int(written_x.get(index, 0) or 0)
            reads = int(reads_c.get(index, 0) or 0)
            writes = int(writes_c.get(index, 0) or 0)
            current[name] = (read_bytes, write_bytes, reads, writes)

            was = previous.get(name)
            read_bps = write_bps = read_iops = write_iops = None
            if was is not None and elapsed > 0:
                read_bps = _rate(
                    was[0], read_bytes, elapsed, byte_modulus, narrow_bytes
                )
                write_bps = _rate(
                    was[1], write_bytes, elapsed, byte_modulus, narrow_bytes
                )
                # Operation counters are 32-bit with no wide variant, but they
                # wrap only after 4.29 billion operations — hours even on NVMe.
                read_iops = _rate(was[2], reads, elapsed, _COUNTER32_MODULUS)
                write_iops = _rate(was[3], writes, elapsed, _COUNTER32_MODULUS)

            busy = la1.get(index)
            entries.append(
                {
                    "device": name,
                    "read_bytes": read_bytes,
                    "write_bytes": write_bytes,
                    "reads": reads,
                    "writes": writes,
                    "read_bps": read_bps,
                    "write_bps": write_bps,
                    "read_iops": read_iops,
                    "write_iops": write_iops,
                    # diskIOLA1 is a one-minute average, so at a short interval
                    # it lags the rates beside it by design. Named for what it
                    # is rather than as a plain "busy_percent".
                    "busy_percent_1min": float(busy) if busy is not None else None,
                    "counted": _counts_toward_total(name),
                }
            )

        counted = [e for e in entries if e["counted"]]
        rated = [e for e in counted if e["read_bps"] is not None]
        payload = {
            "read_bps": round(sum(e["read_bps"] for e in rated), 2) if rated else None,
            "write_bps": round(sum(e["write_bps"] or 0.0 for e in rated), 2)
            if rated
            else None,
            "read_iops": round(sum(e["read_iops"] or 0.0 for e in rated), 2)
            if rated
            else None,
            "write_iops": round(sum(e["write_iops"] or 0.0 for e in rated), 2)
            if rated
            else None,
            "read_bytes": sum(e["read_bytes"] for e in counted),
            "write_bytes": sum(e["write_bytes"] for e in counted),
            "reads": sum(e["reads"] for e in counted),
            "writes": sum(e["writes"] for e in counted),
            "interval_seconds": round(elapsed, 3) if elapsed > 0 else None,
            "devices": entries,
        }
        return payload, current

    # ---- state --------------------------------------------------------------

    def _prune(self, now: float) -> None:
        """Drop baselines for machines that stopped being polled."""
        if now - self._last_prune < _PRUNE_EVERY_SECONDS:
            return
        self._last_prune = now
        cutoff = now - _COUNTER_TTL_SECONDS
        stale = [k for k, s in self._counters.items() if s.seen_at < cutoff]
        for key in stale:
            del self._counters[key]
        if stale:
            log.info("dropped %s stale counter baseline(s)", len(stale))

    # ---- entry point --------------------------------------------------------

    async def sample(self, ipv4: str, key: str) -> dict[str, Any]:
        target = await UdpTransportTarget.create(
            (ipv4, self._port), timeout=self._timeout, retries=self._retries
        )

        # One clock read for the whole sample, taken before any walk, so the two
        # rate groups agree on when this observation happened.
        now = time.monotonic()
        state = self._counters.get(key) or _CounterState()

        tasks: list[Any] = [
            self._host_resources(target, ipv4),
            self._network(target, ipv4, now, state),
        ]
        if self._diskio_enabled:
            tasks.append(self._disk_io(target, ipv4, now, state))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        host_result, net_result = results[0], results[1]
        dio_result = results[2] if self._diskio_enabled else None

        # Host resources are the sample. Without them there is nothing to store,
        # which is the one failure that propagates.
        if isinstance(host_result, BaseException):
            raise host_result
        payload: dict[str, Any] = dict(host_result)

        updated = _CounterState(
            interfaces_at=state.interfaces_at,
            interfaces=state.interfaces,
            disks_at=state.disks_at,
            disks=state.disks,
        )

        # An agent that serves HOST-RESOURCES-MIB but not IF-MIB or DISKIO-MIB
        # still has a usable sample; drop the key rather than the sample. The
        # failing table's baseline is left untouched so the next success
        # measures across the real span instead of starting over.
        if isinstance(net_result, BaseException):
            log.warning("no interface counters from %s: %s", ipv4, net_result)
            payload["network"] = {}
        else:
            payload["network"], updated.interfaces = net_result
            updated.interfaces_at = now

        if dio_result is not None:
            if isinstance(dio_result, BaseException):
                log.warning("no disk i/o counters from %s: %s", ipv4, dio_result)
            else:
                payload["disk_io"], updated.disks = dio_result
                updated.disks_at = now

        self._counters[key] = updated
        self._prune(now)
        return payload
