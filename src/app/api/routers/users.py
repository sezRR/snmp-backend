from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from app.api.deps import DbDep, SessionEpochsDep, SettingsDep
from app.api.routers.auth import check_password_policy, refuse_password_reuse
from app.api.security import Principal, requires
from app.db import roles as roles_repo
from app.db import users as users_repo
from app.db.tables import Role, User
from app.models.auth import PasswordReset, UserCreate, UserOut, UserRoles, UserUpdate
from app.security.scopes import Scope
from app.services.auth import hash_password

log = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])

ReadDep = Annotated[Principal, requires(Scope.USERS_READ)]
WriteDep = Annotated[Principal, requires(Scope.USERS_WRITE)]


def _resolve_roles(session, names: list[str], caller: Principal) -> list[Role]:
    """Names to roles, refusing any the caller could not grant."""
    roles, missing = roles_repo.resolve(session, names)
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown role(s): {', '.join(missing)}",
        )
    for role in roles:
        excess = role.scope_set - caller.scopes
        if excess:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"cannot grant the {role.name} role: it holds "
                    f"{', '.join(sorted(excess))}, which you do not"
                ),
            )
    return roles


def _load(session, user_id: uuid.UUID) -> User:
    user = users_repo.get(session, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown user")
    return user


def _refuse_privileged_target(principal: Principal, target: User, action: str) -> None:
    """Refuse an edit aimed at somebody who outranks the caller.

    The mirror of the no-amplification rule, and the half that was missing: that
    one stops you handing out authority you do not hold, this one stops you
    taking it away from — or borrowing it from — someone who does. Without it
    `users:write` was still every permission by another route: reset the admin's
    password and log in as them.

    A subset test rather than a check for the admin role, because the role is
    not special anywhere else in the checker — it is an ordinary role that
    happens to hold every scope. So an admin can edit anyone (nobody holds a
    scope they lack), peers can edit peers, and nobody can edit upwards.

    The caller's scopes come from their access token and the target's from the
    row just read, so a caller demoted in the last few minutes may still pass
    this. That is the same staleness every scope check on this API accepts, and
    it is bounded by ACCESS_TOKEN_TTL_SECONDS.
    """
    excess = target.scopes - principal.scopes
    if excess:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"cannot {action} {target.username!r}: they hold "
                f"{', '.join(sorted(excess))}, which you do not"
            ),
        )


def _refuse_self(principal: Principal, user_id: uuid.UUID, action: str) -> None:
    if principal.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"you cannot {action} your own account; ask another administrator",
        )


def _last_admin(exc: users_repo.LastAdminError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get("")
async def list_users(db: DbDep, _: ReadDep) -> list[UserOut]:
    rows = await db.run_session(users_repo.list_all)
    return [UserOut.from_row(u) for u in rows]


@router.get("/{user_id}")
async def get_user(user_id: uuid.UUID, db: DbDep, _: ReadDep) -> UserOut:
    user = await db.run_session(_load, user_id)
    return UserOut.from_row(user)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate, db: DbDep, settings: SettingsDep, principal: WriteDep
) -> UserOut:
    """Create an account, optionally with roles.

    A user with no roles can authenticate and read `/auth/me` and nothing else,
    which is a reasonable thing to want — grant the roles later.
    """
    check_password_policy(settings, payload.password)
    password_hash = await hash_password(payload.password)

    def _create(session) -> User:
        roles = _resolve_roles(session, payload.roles, principal)
        return users_repo.create(session, payload.username, password_hash, roles)

    try:
        user = await db.run_session(_create)
    except IntegrityError as exc:
        # The unique index is on lower(username), so case differences fire too.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"username {payload.username!r} is taken",
        ) from exc

    log.info("%r created user %r", principal.username, user.username)
    return UserOut.from_row(user)


@router.patch("/{user_id}")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: DbDep,
    epochs: SessionEpochsDep,
    principal: WriteDep,
) -> UserOut:
    """Activate or deactivate an account.

    Deactivating ends every session it has: the refresh tokens are revoked and
    the session epoch moves, which refuses the access tokens already out there
    and closes any stream they opened.
    """
    if payload.is_active is False:
        _refuse_self(principal, user_id, "deactivate")

    def _update(session) -> User:
        user = _load(session, user_id)
        _refuse_privileged_target(principal, user, "change the status of")
        if payload.is_active is not None:
            users_repo.set_active(session, user, payload.is_active)
        return user

    try:
        user = await db.run_session(_update)
    except users_repo.LastAdminError as exc:
        raise _last_admin(exc) from exc

    if payload.is_active is False:
        epochs.remember(user.id, user.session_epoch)

    log.info("%r updated user %r", principal.username, user.username)
    return UserOut.from_row(user)


@router.put("/{user_id}/roles")
async def set_user_roles(
    user_id: uuid.UUID, payload: UserRoles, db: DbDep, principal: WriteDep
) -> UserOut:
    """Replace a user's roles wholesale."""
    _refuse_self(principal, user_id, "change the roles on")

    def _set(session) -> User:
        user = _load(session, user_id)
        # Both directions: no stripping the admin's roles here, no granting a
        # role you could not hold in _resolve_roles.
        _refuse_privileged_target(principal, user, "change the roles on")
        roles = _resolve_roles(session, payload.roles, principal)
        users_repo.set_roles(session, user, roles)
        return user

    try:
        user = await db.run_session(_set)
    except users_repo.LastAdminError as exc:
        raise _last_admin(exc) from exc

    log.info(
        "%r set %r's roles to [%s]",
        principal.username,
        user.username,
        ", ".join(sorted(r.name for r in user.roles)),
    )
    return UserOut.from_row(user)


@router.put("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_user_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    db: DbDep,
    settings: SettingsDep,
    epochs: SessionEpochsDep,
    principal: WriteDep,
) -> None:
    """Administrative reset. Ends every session that user has.

    Refused if the new password is the one already in force — the reset would
    end every session that user has and change nothing, which is an outage
    rather than a reset.
    """
    check_password_policy(settings, payload.new_password)
    password_hash = await hash_password(payload.new_password)

    def _reset(session) -> tuple[str, int]:
        user = _load(session, user_id)
        # Resetting a password is worth exactly the scopes that account holds.
        _refuse_privileged_target(principal, user, "reset the password of")
        try:
            refuse_password_reuse(payload.new_password, user.password_hash)
        except HTTPException:
            # Logged: this answer tells the caller something about the password.
            log.warning(
                "%r proposed %r's current password as its new one",
                principal.username,
                user.username,
            )
            raise
        users_repo.set_password(session, user, password_hash)
        return user.username, user.session_epoch

    username, epoch = await db.run_session(_reset)
    # Drops this process's cached epoch; others find out on the next token.
    epochs.remember(user_id, epoch)
    log.warning("%r reset %r's password", principal.username, username)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID, db: DbDep, epochs: SessionEpochsDep, principal: WriteDep
) -> None:
    """Delete an account. Its refresh tokens go with it, via ON DELETE CASCADE."""
    _refuse_self(principal, user_id, "delete")

    def _delete(session) -> str:
        user = _load(session, user_id)
        _refuse_privileged_target(principal, user, "delete")
        username = user.username
        users_repo.delete(session, user)
        return username

    try:
        username = await db.run_session(_delete)
    except users_repo.LastAdminError as exc:
        raise _last_admin(exc) from exc

    # A cached epoch would keep accepting a deleted account's tokens for the
    # rest of the window.
    epochs.forget(user_id)
    log.warning("%r deleted user %r", principal.username, username)
