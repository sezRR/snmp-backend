"""SNMP sampling: protocol and factory.

A sample is a plain dict, stored verbatim in the `metrics` jsonb column. Nothing
downstream declares its shape, so adding a metric here is the whole change —
no migration, no model edit.

Current shape:

    {"cpu":  {"usage_percent": 37.5, "cores": 4},
     "ram":  {"total_bytes": …, "used_bytes": …, "used_percent": …,
              "available_bytes": …, "buffers_bytes": …, "cached_bytes": …},
     "disk": [{"mount": "/", "total_bytes": …, "used_bytes": …, "used_percent": …}],
     "disk_io": {"read_bps": …, "write_bps": …, "read_iops": …, "write_iops": …,
                 "read_bytes": …, "write_bytes": …, "reads": …, "writes": …,
                 "interval_seconds": …,
                 "devices": [{"device": "vda", "read_bps": …, "write_bps": …,
                              "read_iops": …, "write_iops": …,
                              "read_bytes": …, "write_bytes": …,
                              "reads": …, "writes": …,
                              "busy_percent_1min": …, "counted": true}]},
     "network": {"rx_bps": …, "tx_bps": …, "rx_bytes": …, "tx_bytes": …,
                 "interval_seconds": …,
                 "interfaces": [{"name": "eth0", "rx_bps": …, "tx_bps": …,
                                 "rx_bytes": …, "tx_bytes": …, "speed_bps": …,
                                 "rx_util_percent": …, "tx_util_percent": …}]}}

Every `*_bps` and `*_iops` is a rate over the interval since the previous sample
of that machine, so they are null when there is no previous sample to compare
against; the plain counters beside them (`rx_bytes`, `read_bytes`, `reads`, …)
are the agent's own cumulative values, kept so any window can be recomputed from
history rather than only from the rate we happened to derive at the time.

`disk` is capacity per mount point and `disk_io` is throughput per block device.
They are separate keys because nothing joins them: the mount comes from
hrStorageTable and the device from DISKIO-MIB, and on LVM, RAID or any
multi-mount device the mapping between them is many-to-many. `disk_io` totals
sum only the devices marked `counted`, because the kernel reports both a
device-mapper device and the disk underneath it, and both a partition and its
whole disk — summing everything would double-count.

Any key may be missing: an agent that answers HOST-RESOURCES-MIB but not IF-MIB
or DISKIO-MIB still yields a usable sample, minus that key.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol
from uuid import UUID

from app.config import Settings
from app.models.credential import ResolvedCredential

log = logging.getLogger(__name__)


class SnmpSampler(Protocol):
    async def sample(
        self, ipv4: str, key: str, credential: ResolvedCredential
    ) -> dict[str, Any]:
        """Sample the agent at `ipv4`, remembering counters under `key`.

        `key` is the machine's stable identity (its MAC), not its address:
        rates are deltas against this process's previous sample, and OpenStack
        may re-IP a machine between two ticks. Keying the counter state on the
        address would silently discard the baseline every time that happened.

        `credential` is passed in rather than looked up here, so a sampler needs
        no database reach at all. The collector already holds the machine rows;
        decryption and caching live in `app.services.credentials`.
        """
        ...

    def forget_credential(self, credential_id: UUID) -> None:
        """Drop whatever this sampler is holding for a credential.

        Called when one is deleted, and after a one-off test with an unsaved
        credential — otherwise every dry run would leak an `SnmpEngine` and the
        decrypted USM keys inside it, for a credential that may not even exist.
        """
        ...


class SnmpError(RuntimeError):
    """An agent did not answer, or answered with something unusable."""


def build_sampler(settings: Settings) -> SnmpSampler:
    from app.services.snmp.pysnmp_backend import PySnmpSampler

    log.info(
        "snmp: pysnmp against port %s, credentials per machine (timeout %ss, "
        "%s retries, max-repetitions %s, disk i/o %s)",
        settings.snmp_port,
        settings.snmp_timeout_seconds,
        settings.snmp_retries,
        settings.snmp_max_repetitions,
        "on" if settings.snmp_diskio_enabled else "off",
    )
    return PySnmpSampler(
        port=settings.snmp_port,
        timeout_seconds=settings.snmp_timeout_seconds,
        retries=settings.snmp_retries,
        max_repetitions=settings.snmp_max_repetitions,
        diskio_enabled=settings.snmp_diskio_enabled,
        virtual_iface_prefixes=settings.virtual_iface_prefixes,
    )
