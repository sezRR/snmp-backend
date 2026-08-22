from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbDep
from app.api.security import Principal, requires
from app.db import roles as roles_repo
from app.db import users as users_repo
from app.db.tables import Role
from app.models.auth import RoleCreate, RoleOut, RoleScopes, RoleUpdate, ScopeInfo
from app.security.scopes import SCOPE_DESCRIPTIONS, Scope

log = logging.getLogger(__name__)

router = APIRouter(tags=["roles"])

ReadDep = Annotated[Principal, requires(Scope.ROLES_READ)]
WriteDep = Annotated[Principal, requires(Scope.ROLES_WRITE)]


def _load(session, name: str) -> Role:
    role = roles_repo.get_by_name(session, name)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown role")
    return role


def _refuse_amplification(scopes: list[str], caller: Principal) -> None:
    excess = set(scopes) - caller.scopes
    if excess:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"cannot grant scope(s) you do not hold: {', '.join(sorted(excess))}"
            ),
        )


def _refuse_editing_privileged_role(role: Role, caller: Principal) -> None:
    """Refuse touching a role that carries more authority than the caller.

    `_refuse_amplification` guards what goes into a role; this guards what is
    already there. Both are needed: rewriting the scopes of a role you do not
    hold is an edit to somebody else's authority even when every scope you write
    is one of your own.
    """
    excess = role.scope_set - caller.scopes
    if excess:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"cannot edit the {role.name} role: it holds "
                f"{', '.join(sorted(excess))}, which you do not"
            ),
        )


@router.get("/scopes")
async def list_scopes(_: ReadDep) -> list[ScopeInfo]:
    """The permission vocabulary. Fixed in code, so this never changes at runtime."""
    return [
        ScopeInfo(name=name, description=description)
        for name, description in sorted(SCOPE_DESCRIPTIONS.items())
    ]


@router.get("/roles")
async def list_roles(db: DbDep, _: ReadDep) -> list[RoleOut]:
    rows = await db.run_session(roles_repo.list_all)
    return [RoleOut.from_row(r) for r in rows]


@router.get("/roles/{name}")
async def get_role(name: str, db: DbDep, _: ReadDep) -> RoleOut:
    role = await db.run_session(_load, name)
    return RoleOut.from_row(role)


@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(payload: RoleCreate, db: DbDep, principal: WriteDep) -> RoleOut:
    """Create a role. Unknown scope names are rejected by the model as a 422."""
    _refuse_amplification(payload.scopes, principal)
    try:
        role = await db.run_session(
            roles_repo.create, payload.name, payload.description, payload.scopes
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a role named {payload.name!r} already exists",
        ) from exc

    log.info(
        "%r created role %r with [%s]",
        principal.username,
        role.name,
        ", ".join(sorted(role.scope_set)),
    )
    return RoleOut.from_row(role)


@router.patch("/roles/{name}")
async def update_role(
    name: str, payload: RoleUpdate, db: DbDep, principal: WriteDep
) -> RoleOut:
    """Edit the description. Scopes go through `PUT /roles/{name}/scopes`.

    Allowed on system roles — a description is documentation, not authority —
    but not on a role holding scopes the caller does not: the admin role's
    description is still the admin role's.
    """

    def _update(session) -> Role:
        role = _load(session, name)
        _refuse_editing_privileged_role(role, principal)
        roles_repo.set_description(session, role, payload.description)
        return role

    role = await db.run_session(_update)
    return RoleOut.from_row(role)


@router.put("/roles/{name}/scopes")
async def set_role_scopes(
    name: str, payload: RoleScopes, db: DbDep, principal: WriteDep
) -> RoleOut:
    """Replace a role's scopes.

    Refused on the built-in admin role, on any role holding scopes the caller
    does not, and if the result would leave nobody able to administer users —
    editing a widely-granted role is the other way to lock everyone out.
    """
    _refuse_amplification(payload.scopes, principal)

    def _set(session) -> Role:
        role = _load(session, name)
        _refuse_editing_privileged_role(role, principal)
        roles_repo.set_scopes(session, role, payload.scopes)
        return role

    try:
        role = await db.run_session(_set)
    except roles_repo.SystemRoleError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except users_repo.LastAdminError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    log.info(
        "%r set role %r to [%s]",
        principal.username,
        role.name,
        ", ".join(sorted(role.scope_set)),
    )
    return RoleOut.from_row(role)


@router.delete("/roles/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(name: str, db: DbDep, principal: WriteDep) -> None:
    """Delete a role. Refused if it is built in, still granted, or above you."""

    def _delete(session) -> None:
        role = _load(session, name)
        _refuse_editing_privileged_role(role, principal)
        roles_repo.delete(session, role)

    try:
        await db.run_session(_delete)
    except (roles_repo.SystemRoleError, roles_repo.RoleInUseError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    log.warning("%r deleted role %r", principal.username, name)
