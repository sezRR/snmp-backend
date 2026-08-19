"""The payload/column mapping, in both directions.

The sampler produces a nested reading with one entry per mount, per block
device and per network interface. The database stores one flat row of scalars.
This module is the only place that knows how one becomes the other, which is
what keeps the translation testable without a database and keeps the column
list from being spelled out in four files.

Why the per-entity arrays are not stored: their members are ephemeral. A
Kubernetes node has one `veth` per pod and the names change on every restart,
so they can never become stable columns; `loop0`-`loop7` carry zeros; and ten
of eleven mounts on a typical host are tmpfs under `/run`. They are still
collected and still streamed live over SSE — `nest()` is only used for rows
read back out of the database, where they no longer exist.

Two of the aggregates here are recomputations rather than copies, and
deliberately disagree with the scalars the sampler wrote:

* Network totals sum physical interfaces only. `network.rx_bps` in the payload
  sums every interface that is up and not loopback, which on a container host
  counts the same packet once for the veth, once for the bridge and once for
  the uplink.
* `disk_max_used_pct` skips pseudo filesystems. A 100% full
  `/run/credentials/getty@tty1.service` is not a full disk.
"""

from __future__ import annotations

from typing import Any

# Every metric column, in table order. `insert_many` binds exactly these, the
# repository selects exactly these, and the migration backfills exactly these,
# so adding a metric means editing this tuple and the two mappings below.
COLUMNS: tuple[str, ...] = (
    "cpu_usage_pct",
    "cpu_cores",
    "ram_total_bytes",
    "ram_used_bytes",
    "ram_used_pct",
    "ram_available_bytes",
    "disk_root_total_bytes",
    "disk_root_used_bytes",
    "disk_root_used_pct",
    "disk_max_used_pct",
    "dio_read_bps",
    "dio_write_bps",
    "dio_read_iops",
    "dio_write_iops",
    "dio_read_bytes",
    "dio_write_bytes",
    "dio_reads",
    "dio_writes",
    "dio_busy_pct",
    "net_rx_bps",
    "net_tx_bps",
    "net_rx_bytes",
    "net_tx_bytes",
    "net_rx_util_pct",
    "net_tx_util_pct",
    "net_speed_bps",
    "interval_ms",
)

ROOT_MOUNT = "/"


def is_pseudo_mount(mount: str, prefixes: tuple[str, ...]) -> bool:
    """Whether a mount's usage says nothing about a real filesystem.

    Prefix matching, because the interesting cases are whole subtrees:
    systemd generates a fresh `/run/credentials/<unit>` per service and each one
    is its own tmpfs.
    """
    return mount.startswith(prefixes)


def is_physical_interface(name: str, prefixes: tuple[str, ...]) -> bool:
    """Whether an interface can move a packet off the machine by itself.

    Everything a virtual interface carries also crosses a physical one, so the
    host total must count only the latter or it double counts.
    """
    return not name.startswith(prefixes)


def _num(value: Any) -> float | int | None:
    """Coerce a JSON scalar to a number, or None.

    Booleans are rejected on purpose: `True` is an `int` in Python and would
    silently store as 1.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def _int(value: Any) -> int | None:
    number = _num(value)
    return None if number is None else int(number)


def _max(values: list[Any]) -> float | int | None:
    present = [v for v in (_num(v) for v in values) if v is not None]
    return max(present) if present else None


def _sum(values: list[Any]) -> float | int | None:
    """Sum, or None when nothing contributed.

    None rather than 0 matters: a machine whose every interface counter wrapped
    this tick has an *unknown* throughput, not a zero one, and an average over
    the bucket must skip it rather than be dragged toward zero.
    """
    present = [v for v in (_num(v) for v in values) if v is not None]
    return round(sum(present), 2) if present else None


def flatten(
    payload: dict[str, Any],
    *,
    pseudo_mount_prefixes: tuple[str, ...] = (),
    virtual_iface_prefixes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """One nested sample to one row of scalars.

    Total: every column in `COLUMNS` is present in the result, None where the
    payload has nothing to say. The sampler omits whole sections — `network` is
    `{}` when the IF-MIB walk failed, `disk_io` is absent when the agent serves
    no DISKIO-MIB — so partial payloads are the normal case, not the error case.
    """
    cpu = payload.get("cpu") or {}
    ram = payload.get("ram") or {}
    disks = payload.get("disk") or []
    disk_io = payload.get("disk_io") or {}
    network = payload.get("network") or {}

    root = next(
        (d for d in disks if (d or {}).get("mount") == ROOT_MOUNT),
        {},
    )
    real_mounts = [
        d
        for d in disks
        if d and not is_pseudo_mount(str(d.get("mount", "")), pseudo_mount_prefixes)
    ]
    # Falling back to every mount rather than to nothing: a host whose only
    # filesystems all look pseudo is more likely to be one this list does not
    # describe than one with no disks.
    if not real_mounts:
        real_mounts = [d for d in disks if d]

    counted_devices = [
        d for d in (disk_io.get("devices") or []) if d and d.get("counted")
    ]

    interfaces = [i for i in (network.get("interfaces") or []) if i]
    physical = [
        i
        for i in interfaces
        if is_physical_interface(str(i.get("name", "")), virtual_iface_prefixes)
    ]
    # Rates sum only the interfaces that produced one, so a single wrapped
    # counter does not drag the total down to a partial figure; byte counters
    # sum the same physical set. Before this the two used different sets, which
    # made the totals disagree with each other.
    rx_rated = [i for i in physical if _num(i.get("rx_bps")) is not None]
    tx_rated = [i for i in physical if _num(i.get("tx_bps")) is not None]

    interval_seconds = _num(disk_io.get("interval_seconds"))
    if interval_seconds is None:
        interval_seconds = _num(network.get("interval_seconds"))

    # Falling back to the section's own scalars when there is no array to reduce
    # over. Two things arrive that way: a row read back out of the database and
    # re-nested, which carries the totals and nothing else, and an agent that
    # answers the totals but serves no interface or device table. Reducing an
    # empty list would report None for a machine that did tell us the answer.
    #
    # The fallback cannot reintroduce the over-counting it replaces: it only
    # fires when `interfaces` is empty, and the inflated scalar is only produced
    # alongside a populated one.
    if interfaces:
        net_rx_bps = _sum([i.get("rx_bps") for i in rx_rated])
        net_tx_bps = _sum([i.get("tx_bps") for i in tx_rated])
        net_rx_bytes = _int(_sum([i.get("rx_bytes") for i in physical]))
        net_tx_bytes = _int(_sum([i.get("tx_bytes") for i in physical]))
        net_rx_util = _max([i.get("rx_util_percent") for i in physical])
        net_tx_util = _max([i.get("tx_util_percent") for i in physical])
        net_speed = _int(_max([i.get("speed_bps") for i in physical]))
    else:
        net_rx_bps = _num(network.get("rx_bps"))
        net_tx_bps = _num(network.get("tx_bps"))
        net_rx_bytes = _int(network.get("rx_bytes"))
        net_tx_bytes = _int(network.get("tx_bytes"))
        net_rx_util = _num(network.get("rx_util_percent"))
        net_tx_util = _num(network.get("tx_util_percent"))
        net_speed = _int(network.get("speed_bps"))

    devices = disk_io.get("devices") or []
    dio_busy = (
        _max([d.get("busy_percent_1min") for d in counted_devices])
        if devices
        else _num(disk_io.get("busy_percent_1min"))
    )

    # A payload that already states the machine-level figure is believed over a
    # reduction of the mounts it ships, which is what makes `nest` an exact
    # inverse: a stored row knows its own maximum but carries only root.
    disk_max = _num(payload.get("disk_max_used_percent"))
    if disk_max is None:
        disk_max = _max([d.get("used_percent") for d in real_mounts])

    return {
        "cpu_usage_pct": _num(cpu.get("usage_percent")),
        "cpu_cores": _int(cpu.get("cores")),
        "ram_total_bytes": _int(ram.get("total_bytes")),
        "ram_used_bytes": _int(ram.get("used_bytes")),
        "ram_used_pct": _num(ram.get("used_percent")),
        "ram_available_bytes": _int(ram.get("available_bytes")),
        "disk_root_total_bytes": _int(root.get("total_bytes")),
        "disk_root_used_bytes": _int(root.get("used_bytes")),
        "disk_root_used_pct": _num(root.get("used_percent")),
        "disk_max_used_pct": disk_max,
        "dio_read_bps": _num(disk_io.get("read_bps")),
        "dio_write_bps": _num(disk_io.get("write_bps")),
        "dio_read_iops": _num(disk_io.get("read_iops")),
        "dio_write_iops": _num(disk_io.get("write_iops")),
        "dio_read_bytes": _int(disk_io.get("read_bytes")),
        "dio_write_bytes": _int(disk_io.get("write_bytes")),
        "dio_reads": _int(disk_io.get("reads")),
        "dio_writes": _int(disk_io.get("writes")),
        "dio_busy_pct": dio_busy,
        "net_rx_bps": net_rx_bps,
        "net_tx_bps": net_tx_bps,
        "net_rx_bytes": net_rx_bytes,
        "net_tx_bytes": net_tx_bytes,
        "net_rx_util_pct": net_rx_util,
        "net_tx_util_pct": net_tx_util,
        "net_speed_bps": net_speed,
        "interval_ms": None
        if interval_seconds is None
        else round(interval_seconds * 1000),
    }


def _section(fields: dict[str, Any]) -> dict[str, Any]:
    """A section, or `{}` when the row knew nothing about it.

    An all-null section and an absent one mean the same thing to every consumer,
    and `{}` is what the sampler itself emits for a walk that failed.
    """
    return fields if any(v is not None for v in fields.values()) else {}


def nest(row: dict[str, Any]) -> dict[str, Any]:
    """One stored row back to the nested wire shape.

    The inverse of `flatten` for everything a row still carries. `disk` comes
    back as a single element holding the root filesystem, and the `devices` and
    `interfaces` keys are absent rather than empty — an empty array asserts that
    the machine has no interfaces, which is a different claim from not knowing.
    """
    interval_ms = row.get("interval_ms")
    interval_seconds = None if interval_ms is None else round(interval_ms / 1000, 3)

    disk_io = _section(
        {
            "read_bps": row.get("dio_read_bps"),
            "write_bps": row.get("dio_write_bps"),
            "read_iops": row.get("dio_read_iops"),
            "write_iops": row.get("dio_write_iops"),
            "read_bytes": row.get("dio_read_bytes"),
            "write_bytes": row.get("dio_write_bytes"),
            "reads": row.get("dio_reads"),
            "writes": row.get("dio_writes"),
            "busy_percent_1min": row.get("dio_busy_pct"),
        }
    )
    if disk_io:
        disk_io["interval_seconds"] = interval_seconds

    network = _section(
        {
            "rx_bps": row.get("net_rx_bps"),
            "tx_bps": row.get("net_tx_bps"),
            "rx_bytes": row.get("net_rx_bytes"),
            "tx_bytes": row.get("net_tx_bytes"),
            "rx_util_percent": row.get("net_rx_util_pct"),
            "tx_util_percent": row.get("net_tx_util_pct"),
            "speed_bps": row.get("net_speed_bps"),
        }
    )
    if network:
        network["interval_seconds"] = interval_seconds

    root = _section(
        {
            "total_bytes": row.get("disk_root_total_bytes"),
            "used_bytes": row.get("disk_root_used_bytes"),
            "used_percent": row.get("disk_root_used_pct"),
        }
    )

    payload: dict[str, Any] = {
        "cpu": _section(
            {
                "usage_percent": row.get("cpu_usage_pct"),
                "cores": row.get("cpu_cores"),
            }
        ),
        "ram": _section(
            {
                "total_bytes": row.get("ram_total_bytes"),
                "used_bytes": row.get("ram_used_bytes"),
                "used_percent": row.get("ram_used_pct"),
                "available_bytes": row.get("ram_available_bytes"),
            }
        ),
        "disk": [{"mount": ROOT_MOUNT, **root}] if root else [],
        "network": network,
    }
    # Matching the sampler, which omits the key entirely rather than emitting an
    # empty object when DISKIO is off.
    if disk_io:
        payload["disk_io"] = disk_io
    # The fullest real filesystem, which is not necessarily root and has no
    # place in the per-mount array — it is a machine-level reading.
    if row.get("disk_max_used_pct") is not None:
        payload["disk_max_used_percent"] = row["disk_max_used_pct"]
    return payload
