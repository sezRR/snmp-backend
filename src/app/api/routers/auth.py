from __future__ import annotations

import logging
import math
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import (
    ClientIpDep,
    DbDep,
    LoginLimiterDep,
    SessionEpochsDep,
    SettingsDep,
)
from app.api.security import (
    AuthenticatedDep,
    Principal,
    StreamTicketsDep,
    requires,
)
from app.config import Settings
from app.db import tokens as tokens_repo
from app.db import users as users_repo
from app.db.pool import Database
from app.db.tables import User
from app.models.auth import (
    Me,
    PasswordChange,
    RefreshRequest,
    StreamTicket,
    TokenPair,
)
from app.security.scopes import Scope
from app.services.auth import (
    REFRESH,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_password_blocking,
    verify_password,
    verify_password_blocking,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Verified against when the username does not exist, so a login costs the same
# either way. Never a real password's hash.
_DUMMY_HASH = hash_password_blocking(uuid.uuid4().hex)

_BAD_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="incorrect username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


_SAME_PASSWORD = HTTPException(
    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    detail="the new password must be different from the current one",
)


def check_password_policy(settings: Settings, password: str) -> None:
    if len(password) < settings.password_min_length:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"password must be at least {settings.password_min_length} characters",
        )


def refuse_password_reuse(new_password: str, current_hash: str) -> None:
    """Refuse a password change that changes nothing. Blocking.

    For the administrative reset, which never sees the current plaintext and so
    has to ask the hash. Blocking on purpose: the caller is `users`' `_reset`,
    which already runs inside `run_session`'s worker thread, and doing it there
    keeps the check in the same transaction as the write it guards.

    A hash this build cannot parse verifies as False, so an unreadable one lets
    the reset through — which is right: that account needs a new password more
    than most.
    """
    ok, _ = verify_password_blocking(new_password, current_hash)
    if ok:
        raise _SAME_PASSWORD


async def issue_pair(db: Database, settings: Settings, user: User) -> TokenPair:
    """Mint an access/refresh pair and record the refresh token's jti.

    Scopes are read from the user's roles here, which is the point at which a
    role change becomes visible: a refresh picks it up even though the previous
    access token carried the old set.

    The session epoch is read from the same row, so a pair minted after an epoch
    bump belongs to the surviving session and a pair minted before it does not.
    """
    refresh_token, jti, expires_at = create_refresh_token(
        settings, user.id, user.username
    )
    await db.run_session(tokens_repo.record, jti, user.id, expires_at)
    access_token = create_access_token(
        settings, user.id, user.username, user.scopes, user.session_epoch
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/login")
async def login(
    db: DbDep,
    settings: SettingsDep,
    limiter: LoginLimiterDep,
    client_ip: ClientIpDep,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> TokenPair:
    """Exchange a username and password for an access/refresh pair.

    Rejected attempts are counted per username and per client address; past
    either limit this answers 429 with `Retry-After` and does no work. Checked
    before the password is verified, so a throttled attempt costs a dictionary
    lookup rather than an Argon2 hash — the limit bounds CPU as well as guesses.
    """
    wait = limiter.retry_after(form.username, client_ip)
    if wait is not None:
        # Same answer either way: a counter that only appeared for real
        # accounts would enumerate them.
        log.warning(
            "throttled login for %r from %s (%.0fs remaining)",
            form.username,
            client_ip or "an unknown address",
            wait,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed login attempts; try again later",
            headers={"Retry-After": str(math.ceil(wait))},
        )

    user = await db.run_session(users_repo.get_by_username, form.username)
    stored_hash = user.password_hash if user is not None else _DUMMY_HASH
    ok, new_hash = await verify_password(form.password, stored_hash)

    if user is None or not ok:
        log.info("failed login for %r", form.username)
        limiter.record_failure(form.username, client_ip)
        raise _BAD_CREDENTIALS
    if not user.is_active:
        # Same response as a wrong password, and counted: a disabled account is
        # what a stolen password looks like.
        log.info("login refused for inactive user %r", user.username)
        limiter.record_failure(form.username, client_ip)
        raise _BAD_CREDENTIALS

    # The address keeps its count: clearing it would give one valid account an
    # unlimited budget against every other.
    limiter.record_success(form.username)

    if new_hash is not None:
        # Upgrade the hash while the plaintext is here, which is the only
        # moment possible. Not `set_password`: the password did not change.
        await db.run_session(users_repo.store_password_hash, user, new_hash)

    log.info("login for %r", user.username)
    return await issue_pair(db, settings, user)


@router.post("/refresh")
async def refresh(db: DbDep, settings: SettingsDep, payload: RefreshRequest) -> TokenPair:
    """Rotate a refresh token, returning a fresh pair.

    The presented token is revoked and linked to its successor. Presenting one
    twice means a copy escaped — the legitimate client would already hold the
    successor — so the response is to revoke every session this user has rather
    than to fail one request.
    """
    try:
        decoded = decode_token(settings, payload.refresh_token, REFRESH)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid refresh token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    new_token, new_jti, new_expires = create_refresh_token(
        settings, decoded.user_id, decoded.username
    )

    def _rotate(session) -> User:
        old = tokens_repo.redeem(session, decoded.jti)
        user = users_repo.get(session, old.user_id)
        if user is None or not user.is_active:
            raise tokens_repo.TokenReplayed("account is no longer active")
        tokens_repo.rotate(session, old, new_jti, new_expires)
        return user

    try:
        user = await db.run_session(_rotate)
    except tokens_repo.TokenReplayed as exc:
        if exc.burn_user_id is not None:
            # A second transaction: the one above rolled back, this must survive.
            burned = await db.run_session(users_repo.revoke_all_tokens, exc.burn_user_id)
            log.warning(
                "refresh token replayed for %r; revoked %s live session(s)",
                decoded.username,
                burned,
            )
        log.warning("refresh refused for %r: %s", decoded.username, exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    access_token = create_access_token(
        settings, user.id, user.username, user.scopes, user.session_epoch
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=new_token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    db: DbDep, settings: SettingsDep, principal: AuthenticatedDep, payload: RefreshRequest
) -> None:
    """End one session by revoking its refresh token.

    The access token stays valid until it expires — nothing can recall it — so a
    client should discard it too.
    """
    try:
        decoded = decode_token(settings, payload.refresh_token, REFRESH)
    except TokenError:
        # Already unusable, and logging out is idempotent.
        return

    def _revoke(session) -> None:
        token = tokens_repo.get(session, decoded.jti)
        if token is not None and token.user_id == principal.user_id:
            tokens_repo.revoke(session, token)

    await db.run_session(_revoke)


@router.get("/me")
async def me(db: DbDep, principal: AuthenticatedDep) -> Me:
    """The caller's account, roles and effective scopes.

    Read from the database rather than from the token, so this shows the current
    truth even when the presented token predates a role change.
    """
    user = await db.run_session(users_repo.get, principal.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="account no longer exists"
        )
    # Me subclasses UserOut, and from_row builds `cls`, so this is a Me.
    return Me.from_row(user)


@router.patch("/me/password")
async def change_own_password(
    db: DbDep,
    settings: SettingsDep,
    epochs: SessionEpochsDep,
    principal: AuthenticatedDep,
    payload: PasswordChange,
) -> TokenPair:
    """Change your own password. Requires the current one, and a different one.

    Every other session is ended — refresh tokens revoked, access tokens refused
    from the next request, open streams closed — and a fresh pair is returned so
    the caller is not logged out of the session they made the change from.
    """
    check_password_policy(settings, payload.new_password)
    # Plaintext comparison, not a second Argon2 verify: both strings came from
    # this caller, and equal plaintexts mean the change is a no-op.
    if payload.new_password == payload.current_password:
        raise _SAME_PASSWORD

    user = await db.run_session(users_repo.get, principal.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="account no longer exists"
        )

    ok, _ = await verify_password(payload.current_password, user.password_hash)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="current password is incorrect"
        )

    new_hash = await hash_password(payload.new_password)
    # set_password revokes every token and bumps the epoch, the caller's own
    # included — hence the fresh pair below.
    await db.run_session(users_repo.set_password, user, new_hash)
    # Before the pair is minted, so this response's token is never measured
    # against the epoch it replaced.
    epochs.remember(user.id, user.session_epoch)
    log.info("%r changed their password", user.username)
    return await issue_pair(db, settings, user)


@router.post("/stream-ticket")
async def create_stream_ticket(
    tickets: StreamTicketsDep,
    principal: Annotated[Principal, requires(Scope.METRICS_READ)],
) -> StreamTicket:
    """A single-use credential for `EventSource`, which cannot send headers.

    Redeem it as `?ticket=` on either stream endpoint. It is worth one
    connection and a few seconds, so a copy left in an access log is inert.
    """
    ticket, ttl = tickets.issue(principal)
    return StreamTicket(ticket=ticket, expires_in=ttl)
