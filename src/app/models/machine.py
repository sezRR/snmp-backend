from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address
from uuid import UUID

from pydantic import BaseModel, Field, computed_field

from app.models.openstack import ServerInfo


class MachineCreate(BaseModel):
    """Registration payload.

    The address to poll, plus the client's own label. The MAC — the machine's
    identity here — is resolved from OpenStack when OpenStack knows the address.
    A machine outside the OpenStack fleet has no such record, so for those the
    client supplies the MAC itself and the machine is registered as external.

    Supplying a MAC for an address OpenStack does know is allowed but must
    agree with it: the fleet, not the client, names those machines.
    """

    ipv4: IPv4Address
    mac: str | None = Field(
        default=None,
        description="Required only for machines outside OpenStack",
    )
    label: str | None = Field(default=None, max_length=200)


class MachineUpdate(BaseModel):
    """All fields optional; omitted ones are left alone.

    `ipv4` is patchable on external machines only. OpenStack owns the address of
    a managed machine and the collector re-reads it every tick, so a patch there
    would be overwritten within one interval.
    """

    label: str | None = Field(default=None, max_length=200)
    enabled: bool | None = None
    ipv4: IPv4Address | None = None


class MachineRow(BaseModel):
    """A row of `machines` — the only machine state we own."""

    mac: str
    ipv4: IPv4Address
    label: str | None
    enabled: bool
    external: bool
    # What the collector polls this machine with. None means not polled: there
    # is no fallback community string. Bound through
    # PUT /machines/{mac}/snmp-credential, never PATCH.
    credential_id: UUID | None = None
    created_at: datetime
    updated_at: datetime


class Machine(MachineRow):
    """A machine as the API returns it: our row plus the OpenStack lookup.

    `openstack` is None for every external machine, and for a managed one whose
    MAC the lookup no longer has — deleted or moved in OpenStack after
    registration. That is reported rather than hidden, since we keep no fallback
    copy of its details. `external` is what tells the two cases apart.
    """

    openstack: ServerInfo | None = None

    @computed_field
    @property
    def openstack_found(self) -> bool:
        """Serialised too, for clients that prefer a flag to a null check."""
        return self.openstack is not None
