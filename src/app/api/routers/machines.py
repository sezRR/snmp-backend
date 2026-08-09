"""Machine registration and reads.

The database row is half the answer; the rest — tenant, user, flavor and its
specs — comes from the OpenStack lookup on every read, so nothing here can go
stale against the real fleet.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbDep, LookupDep
from app.api.security import requires
from app.security.scopes import Scope
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


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[requires(Scope.MACHINES_WRITE)],
)
async def register_machine(
    payload: MachineCreate, db: DbDep, lookup: LookupDep
) -> Machine:
    """Register a machine by address.

    For a machine in the OpenStack fleet the MAC is resolved from the lookup and
    becomes its identity. A machine outside the fleet has no record to resolve,
    so the client supplies the MAC and the machine is stored as external: no
    OpenStack details on reads, and the collector will not move its address.

    A supplied MAC for an address OpenStack does know must match what OpenStack
    says, otherwise the two would disagree about what is being polled.
    """
    ipv4 = str(payload.ipv4)
    supplied_mac = parse_mac(payload.mac) if payload.mac is not None else None

    try:
        server = await lookup.by_ipv4(ipv4)
    except Exception as exc:
        # Without a MAC there is nothing to register: identity comes from the
        # lookup. With one, the client has supplied everything we need, so the
        # outage only costs us the classification — see below.
        if supplied_mac is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"openstack lookup unavailable: {exc}",
            ) from exc
        log.warning(
            "openstack lookup unavailable (%s); registering %s as external", exc, ipv4
        )
        server = None

    if server is None and supplied_mac is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"OpenStack has no server with address {ipv4}; supply `mac` to "
                "register it as a machine outside OpenStack"
            ),
        )

    if server is not None and supplied_mac is not None:
        resolved = normalise_mac(server.mac)
        if resolved != supplied_mac:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"OpenStack says address {ipv4} is {resolved}, "
                    f"not {supplied_mac}"
                ),
            )

    # External when OpenStack produced no record. If that was only because the
    # lookup was down, the collector clears the flag on the first tick that
    # resolves the MAC.
    external = server is None
    mac = normalise_mac(server.mac) if server is not None else supplied_mac
    try:
        row = await db.run_query(
            machines_repo.insert, mac, ipv4, payload.label, external
        )
    except IntegrityError as exc:
        # The MAC is free but the address is taken — same host registered under
        # a MAC that has since changed in OpenStack. SQLAlchemy wraps psycopg2's
        # UniqueViolation, so this is the exception to catch.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"address {ipv4} is already registered",
        ) from exc

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"machine {mac} is already registered",
        )
    log.info(
        "registered %s machine %s (%s)", "external" if external else "openstack", mac, ipv4
    )
    return Machine(**row, openstack=server)


@router.get("", dependencies=[requires(Scope.MACHINES_READ)])
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


@router.get("/{mac}", dependencies=[requires(Scope.MACHINES_READ)])
async def get_machine(mac: str, db: DbDep, lookup: LookupDep) -> Machine:
    row = await db.run_query(machines_repo.get, parse_mac(mac))
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return await enrich(row, lookup)


@router.patch("/{mac}", dependencies=[requires(Scope.MACHINES_WRITE)])
async def update_machine(
    mac: str, payload: MachineUpdate, db: DbDep, lookup: LookupDep
) -> Machine:
    """Patch the client-owned fields. Omitted fields are left alone.

    `ipv4` is one of them only for an external machine — nothing else knows
    where it moved. OpenStack owns a managed machine's address and the collector
    re-reads it every tick, so accepting a patch there would be a lie that lasts
    one interval.
    """
    parsed = parse_mac(mac)
    ipv4 = str(payload.ipv4) if payload.ipv4 is not None else None

    if ipv4 is not None:
        current = await db.run_query(machines_repo.get, parsed)
        if current is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine"
            )
        if not current["external"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"machine {parsed} is an OpenStack server; its address comes "
                    "from the lookup and cannot be patched"
                ),
            )

    try:
        row = await db.run_query(
            machines_repo.update,
            parsed,
            payload.label,
            payload.enabled,
            ipv4,
            "label" in payload.model_fields_set,
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"address {ipv4} is already registered",
        ) from exc

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    return await enrich(row, lookup)


@router.delete(
    "/{mac}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[requires(Scope.MACHINES_WRITE)],
)
async def delete_machine(mac: str, db: DbDep) -> None:
    """Deregister a machine. Its metric history is cascaded away with it."""
    deleted = await db.run_query(machines_repo.delete, parse_mac(mac))
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine")
    log.info("deleted machine %s and its metrics", mac)
