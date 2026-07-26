"""Machine registration and reads.

The database row is half the answer; the rest — tenant, user, flavor and its
specs — comes from the OpenStack lookup on every read, so nothing here can go
stale against the real fleet.
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2
from fastapi import APIRouter, HTTPException, status

from app.api.deps import DbDep, LookupDep
from app.db import machines as machines_repo
from app.models.machine import Machine, MachineCreate, MachineUpdate
from app.services.openstack import CachedOpenStack, normalise_mac

log = logging.getLogger(__name__)

router = APIRouter(prefix="/machines", tags=["machines"])


def parse_mac(mac: str) -> str:
    """Accept any common MAC spelling, reject anything that is not one."""
    normalised = normalise_mac(mac)
    if len(normalised) != 17 or normalised.count(":") != 5:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"not a MAC address: {mac!r}",
        )
    return normalised


async def enrich(row: dict[str, Any], lookup: CachedOpenStack) -> Machine:
    """Attach the OpenStack record for this MAC, if it still has one."""
    try:
        server = await lookup.by_mac(row["mac"])
    except Exception as exc:
        # The lookup being down degrades the response rather than failing it:
        # the machine is still registered and still being polled.
        log.warning("openstack lookup unavailable: %s", exc)
        server = None
    return Machine(**row, openstack=server)


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_machine(
    payload: MachineCreate, db: DbDep, lookup: LookupDep
) -> Machine:
    """Register a machine by address.

    The MAC is resolved from OpenStack and becomes the machine's identity, so an
    address OpenStack does not know cannot be registered.
    """
    ipv4 = str(payload.ipv4)
    try:
        server = await lookup.by_ipv4(ipv4)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"openstack lookup unavailable: {exc}",
        ) from exc

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OpenStack has no server with address {ipv4}",
        )

    mac = normalise_mac(server.mac)
    try:
        row = await db.run_query(machines_repo.insert, mac, ipv4, payload.label)
    except psycopg2.errors.UniqueViolation as exc:
        # The MAC is free but the address is taken — same host registered under
        # a MAC that has since changed in OpenStack.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"address {ipv4} is already registered",
        ) from exc

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"machine {mac} is already registered",
        )
    log.info("registered machine %s (%s)", mac, ipv4)
    return Machine(**row, openstack=server)


@router.get("")
async def list_machines(
    db: DbDep, lookup: LookupDep, enabled_only: bool = False
) -> list[Machine]:
    rows = await db.run_query(machines_repo.list_all, enabled_only)
    try:
        index = await lookup.mac_index()
    except Exception as exc:
        log.warning("openstack lookup unavailable: %s", exc)
        index = {}
    return [Machine(**row, openstack=index.get(row["mac"])) for row in rows]


@router.get("/{mac}")
async def get_machine(mac: str, db: DbDep, lookup: LookupDep) -> Machine:
    row = await db.run_query(machines_repo.get, parse_mac(mac))
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return await enrich(row, lookup)


@router.patch("/{mac}")
async def update_machine(
    mac: str, payload: MachineUpdate, db: DbDep, lookup: LookupDep
) -> Machine:
    """Patch the two client-owned fields. Omitted fields are left alone."""
    row = await db.run_query(
        machines_repo.update,
        parse_mac(mac),
        payload.label,
        payload.enabled,
        "label" in payload.model_fields_set,
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return await enrich(row, lookup)


@router.delete("/{mac}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_machine(mac: str, db: DbDep) -> None:
    """Deregister a machine. Its metric history is cascaded away with it."""
    deleted = await db.run_query(machines_repo.delete, parse_mac(mac))
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    log.info("deleted machine %s and its metrics", mac)
