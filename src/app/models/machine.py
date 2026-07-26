from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address

from pydantic import BaseModel, Field, computed_field

from app.models.openstack import ServerInfo


class MachineCreate(BaseModel):
    """Registration payload.

    Only the address the client wants polled, plus its own label. The MAC — the
    machine's identity here — is resolved from OpenStack, never supplied.
    """

    ipv4: IPv4Address
    label: str | None = Field(default=None, max_length=200)


class MachineUpdate(BaseModel):
    """Both fields optional; omitted ones are left alone."""

    label: str | None = Field(default=None, max_length=200)
    enabled: bool | None = None


class MachineRow(BaseModel):
    """A row of `machines` — the only machine state we own."""

    mac: str
    ipv4: IPv4Address
    label: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime


class Machine(MachineRow):
    """A machine as the API returns it: our row plus the OpenStack lookup.

    `openstack` is None when the lookup has no record of the MAC — the machine
    was deleted or moved in OpenStack after registration. That is reported
    rather than hidden, since we keep no fallback copy of its details.
    """

    openstack: ServerInfo | None = None

    @computed_field
    @property
    def openstack_found(self) -> bool:
        """Serialised too, for clients that prefer a flag to a null check."""
        return self.openstack is not None
