from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from app.api.deps import CipherDep, CredentialCacheDep, DbDep, SamplerDep, SettingsDep
from app.api.routers.machines import parse_mac
from app.api.security import Principal, requires
from app.db import credentials as credentials_repo
from app.db import machines as machines_repo
from app.models.credential import (
    CredentialBind,
    CredentialTestRequest,
    CredentialTestResult,
    ResolvedCredential,
    SnmpCredential,
    SnmpCredentialBase,
    SnmpCredentialCreate,
    SnmpCredentialUpdate,
    SnmpVersion,
)
from app.security.crypto import CredentialCipher, CredentialCryptoError
from app.security.scopes import Scope
from app.services.credentials import resolve_row

log = logging.getLogger(__name__)

router = APIRouter(prefix="/snmp-credentials", tags=["snmp credentials"])
# Same prefix as the machines router: a machine sub-resource, gated on the
# credential scopes rather than the machine ones.
machine_router = APIRouter(prefix="/machines", tags=["snmp credentials"])


def _as_credential(row: dict[str, Any]) -> SnmpCredential:
    return SnmpCredential(**row)


def _seal(
    cipher: CredentialCipher, credential_id: UUID, secret_version: int, spec: SnmpCredentialBase
) -> tuple[bytes, str, str]:
    """Encrypt a payload and fingerprint it. Returns `(secret, key_id, fingerprint)`."""
    payload = spec.secret_payload()
    secret, key_id = cipher.encrypt(credential_id, secret_version, payload)
    return secret, key_id, cipher.fingerprint(payload)


# --- Profiles ----------------------------------------------------------------


@router.get("", dependencies=[requires(Scope.CREDENTIALS_READ)])
async def list_credentials(db: DbDep) -> list[SnmpCredential]:
    rows = await db.run_query(credentials_repo.list_all)
    return [_as_credential(row) for row in rows]


@router.post(
    "", status_code=status.HTTP_201_CREATED
)
async def create_credential(
    payload: SnmpCredentialCreate,
    db: DbDep,
    cipher: CipherDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> SnmpCredential:
    """Create a profile. The secret is encrypted here and never read back.

    The id is generated client-side rather than by the database default, because
    it is sealed into the ciphertext as additional authenticated data and so has
    to exist before the encryption, not after the insert.
    """
    credential_id = uuid4()
    secret, key_id, fingerprint = _seal(cipher, credential_id, 1, payload)

    row = await db.run_query(
        credentials_repo.insert,
        credential_id,
        payload.name,
        payload.description,
        str(payload.snmp_version),
        payload.username,
        str(payload.security_level) if payload.security_level else None,
        str(payload.auth_protocol) if payload.auth_protocol else None,
        str(payload.priv_protocol) if payload.priv_protocol else None,
        secret,
        key_id,
        fingerprint,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a credential named {payload.name!r} already exists",
        )
    log.info(
        "credential %r (%s) created by %s",
        payload.name,
        f"SNMPv{payload.snmp_version}",
        principal.username,
    )
    return _as_credential(row)


@router.get("/{credential_id}", dependencies=[requires(Scope.CREDENTIALS_READ)])
async def get_credential(credential_id: UUID, db: DbDep) -> SnmpCredential:
    row = await db.run_query(credentials_repo.get, credential_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
        )
    return _as_credential(row)


@router.patch("/{credential_id}")
async def update_credential(
    credential_id: UUID,
    payload: SnmpCredentialUpdate,
    db: DbDep,
    cipher: CipherDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> SnmpCredential:
    """Patch a profile in place. Every bound machine picks it up next tick.

    A patch that touches any USM field must send the whole shape, not just the
    field that changed. Half a change is not repairable: moving `security_level`
    from authNoPriv to authPriv without a priv passphrase would leave a row no
    validator could fix, and guessing which of the old values still apply is
    worse than asking. So the fields are re-validated together through
    `SnmpCredentialBase` and the result replaces the secret wholesale.
    """
    current = await db.run_query(credentials_repo.get, credential_id)
    if current is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
        )

    if payload.touches_secret:
        try:
            spec = SnmpCredentialBase(
                snmp_version=payload.snmp_version or SnmpVersion(current["snmp_version"]),
                community=payload.community,
                username=payload.username,
                security_level=payload.security_level,
                auth_protocol=payload.auth_protocol,
                auth_passphrase=payload.auth_passphrase,
                priv_protocol=payload.priv_protocol,
                priv_passphrase=payload.priv_passphrase,
                allow_weak=payload.allow_weak,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

        # Sealed against the version the update lands on: the AAD must match
        # what the row will say.
        next_version = current["secret_version"] + 1
        secret, key_id, fingerprint = _seal(cipher, credential_id, next_version, spec)
        row = await db.run_query(
            credentials_repo.update_secret,
            credential_id,
            str(spec.snmp_version),
            spec.username,
            str(spec.security_level) if spec.security_level else None,
            str(spec.auth_protocol) if spec.auth_protocol else None,
            str(spec.priv_protocol) if spec.priv_protocol else None,
            secret,
            key_id,
            fingerprint,
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
            )
        log.warning(
            "credential %r secret rotated to v%s by %s",
            row["name"],
            row["secret_version"],
            principal.username,
        )
        current = row

    if payload.name is not None or "description" in payload.model_fields_set:
        try:
            row = await db.run_query(
                credentials_repo.update_metadata,
                credential_id,
                payload.name,
                payload.description,
                "description" in payload.model_fields_set,
            )
        except IntegrityError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"a credential named {payload.name!r} already exists",
            ) from exc
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
            )
        log.info("credential %r edited by %s", row["name"], principal.username)
        current = row

    return _as_credential(current)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: UUID,
    db: DbDep,
    credentials: CredentialCacheDep,
    sampler: SamplerDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> None:
    """Delete a profile. 409 while any machine is still bound to it.

    The FK is RESTRICT, so the database would refuse this anyway; checking first
    is what turns that into a 409 naming the machines rather than a 500.
    """
    bound = await db.run_query(credentials_repo.bound_macs, credential_id)
    if bound:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"credential is bound to {len(bound)} machine(s): "
                f"{', '.join(bound)} — unbind them first"
            ),
        )
    deleted = await db.run_query(credentials_repo.delete, credential_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
        )
    # Drop the plaintext and the engine holding its USM keys now.
    credentials.forget(credential_id)
    sampler.forget_credential(credential_id)
    log.warning("credential %s deleted by %s", credential_id, principal.username)


# --- Binding -----------------------------------------------------------------


@machine_router.put("/{mac}/snmp-credential")
async def bind_credential(
    mac: str,
    payload: CredentialBind,
    db: DbDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> dict[str, Any]:
    parsed = parse_mac(mac)
    credential = await db.run_query(credentials_repo.get, payload.credential_id)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
        )
    row = await db.run_query(
        machines_repo.bind_credential, parsed, payload.credential_id
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine"
        )
    log.warning(
        "credential %r bound to machine %s (%s) by %s",
        credential["name"],
        parsed,
        row["ipv4"],
        principal.username,
    )
    return {"mac": parsed, "credential": _as_credential(credential)}


@machine_router.delete(
    "/{mac}/snmp-credential", status_code=status.HTTP_204_NO_CONTENT
)
async def unbind_credential(
    mac: str,
    db: DbDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> None:
    """Unbind. The machine stops being polled until something is bound again."""
    parsed = parse_mac(mac)
    row = await db.run_query(machines_repo.unbind_credential, parsed)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine"
        )
    log.warning("credential unbound from machine %s by %s", parsed, principal.username)


@machine_router.post("/{mac}/snmp-credential/test")
async def test_credential(
    mac: str,
    payload: CredentialTestRequest,
    db: DbDep,
    cipher: CipherDep,
    credentials: CredentialCacheDep,
    sampler: SamplerDep,
    settings: SettingsDep,
    principal: Annotated[Principal, requires(Scope.CREDENTIALS_WRITE)],
) -> CredentialTestResult:
    """Poll one machine once, to check a credential works.

    **The address comes from the machine's row and from nowhere else.** An
    endpoint that accepted an address in the body would be the credential-relay
    attack as a supported API — point a shared credential at a host you control,
    capture the authenticated exchange, attack the passphrase offline — and
    synchronous into the bargain, so the attacker would not even have to wait
    for a tick. Registration stays the choke point.

    An unsaved credential in the body is fine: the caller supplied the secret, so
    there is nothing here they did not already have.
    """
    parsed = parse_mac(mac)
    machine = await db.run_query(machines_repo.get, parsed)
    if machine is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="unknown machine"
        )
    ipv4 = machine["ipv4"]

    ad_hoc = payload.credential is not None
    if ad_hoc:
        # A throwaway id for the sampler's cache key; dropped in the `finally`.
        credential = _ad_hoc_credential(payload.credential)
    else:
        if machine["credential_id"] is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "machine has no credential bound; bind one first or send a "
                    "credential in the request body"
                ),
            )
        row = await db.run_query(
            credentials_repo.get_secret, machine["credential_id"]
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown credential"
            )
        try:
            credential = resolve_row(cipher, row)
        except CredentialCryptoError as exc:
            # Almost always a key dropped from the ring too early. Without this
            # it reaches the operator as an opaque 500.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc

    started = time.monotonic()
    try:
        await asyncio.wait_for(
            sampler.sample(ipv4, parsed, credential),
            timeout=max(1.0, settings.collector_sample_timeout_seconds or 10.0),
        )
    except asyncio.TimeoutError:
        return CredentialTestResult(
            ok=False,
            ipv4=ipv4,
            credential_id=None if ad_hoc else credential.id,
            duration_seconds=round(time.monotonic() - started, 3),
            detail="no answer within the sample budget",
        )
    except Exception as exc:
        # pysnmp names the cause ("wrongDigests", "unknownUserName") without
        # carrying the passphrase.
        return CredentialTestResult(
            ok=False,
            ipv4=ipv4,
            credential_id=None if ad_hoc else credential.id,
            duration_seconds=round(time.monotonic() - started, 3),
            detail=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if ad_hoc:
            sampler.forget_credential(credential.id)

    log.info(
        "credential test against %s (%s) by %s: ok",
        parsed,
        ipv4,
        principal.username,
    )
    return CredentialTestResult(
        ok=True,
        ipv4=ipv4,
        credential_id=None if ad_hoc else credential.id,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _ad_hoc_credential(spec: SnmpCredentialBase) -> ResolvedCredential:
    """An unsaved credential, for a dry run. Never stored, never encrypted."""
    return ResolvedCredential(
        id=uuid4(),
        name="(unsaved)",
        secret_version=0,
        snmp_version=spec.snmp_version,
        community=spec.community,
        username=spec.username,
        security_level=spec.security_level,
        auth_protocol=spec.auth_protocol,
        priv_protocol=spec.priv_protocol,
        auth_passphrase=spec.auth_passphrase,
        priv_passphrase=spec.priv_passphrase,
    )
