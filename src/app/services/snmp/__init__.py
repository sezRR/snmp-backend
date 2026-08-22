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
