"""Login, token rotation, and self-service account management.

`/auth/login` takes a form body rather than JSON because that is what OAuth2's
password grant specifies, and following it is what makes Swagger's Authorize
button work and any OAuth2 client library work unmodified.

Two habits run through this module:

* **Failures do not distinguish "no such user" from "wrong password".** Both
  answer 401 with the same text, and the no-such-user path still pays for a
  password verification, so the response time does not leak which it was.
* **Anything that invalidates a credential revokes refresh tokens in the same
  transaction.** Access tokens cannot be revoked, so a few minutes of residual
  authority is unavoidable; leaving a refresh token alive would make it
  indefinite.
* **Failed logins are counted, and past a limit answered 429 without doing the
  work.** The counters live in `app.services.ratelimit`; the reason they exist
  is that a constant-time 401 is still an invitation to keep guessing.
"""

from __future__ import annotations

import logging
import math
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import ClientIpDep, DbDep, LoginLimiterDep, SettingsDep
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

# Verified against when the username does not exist, so a login attempt costs
# the same either way. Computed once at import; the value is never a real
# password's hash.
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
    """
    refresh_token, jti, expires_at = create_refresh_token(
        settings, user.id, user.username
    )
    await db.run_session(tokens_repo.record, jti, user.id, expires_at)
    access_token = create_access_token(settings, user.id, user.username, user.scopes)
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
        # Same answer whether or not the username exists, like _BAD_CREDENTIALS:
        # a counter that only ever appeared for real accounts would enumerate
        # them.
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
        # Same response as a wrong password: whether an account is disabled is
        # not something an unauthenticated caller needs to learn. Counted too —
        # a disabled account is exactly what a stolen password looks like.
        log.info("login refused for inactive user %r", user.username)
        limiter.record_failure(form.username, client_ip)
        raise _BAD_CREDENTIALS

    # The password was right, so the failures before it were this user's own
    # typing. The address keeps its count: clearing it would give anyone holding
    # one valid account an unlimited budget against every other.
    limiter.record_success(form.username)

    if new_hash is not None:
        # The stored hash predates a cost increase; upgrade it while we have the
        # plaintext, which is the only moment it is possible.
        await db.run_session(users_repo.set_password, user, new_hash)

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
            # A second transaction on purpose: the one above rolled back, and
            # this revocation must survive.
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

    access_token = create_access_token(settings, user.id, user.username, user.scopes)
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
        # Already unusable. Logging out is idempotent by nature; a client
        # clearing its state should not have to handle an error here.
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
    db: DbDep, settings: SettingsDep, principal: AuthenticatedDep, payload: PasswordChange
) -> TokenPair:
    """Change your own password. Requires the current one, and a different one.

    Every other session is ended, and a fresh pair is returned so the caller is
    not logged out of the session they made the change from.
    """
    check_password_policy(settings, payload.new_password)
    # Plaintext comparison rather than a second Argon2 verify: the current
    # password is checked against the stored hash below, so two equal plaintexts
    # is exactly the case where the change is a no-op. Both strings came from
    # this caller, so there is nothing to leak by comparing them directly.
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
    # set_password revokes every refresh token for this user, including the one
    # the caller is holding — hence the fresh pair below.
    await db.run_session(users_repo.set_password, user, new_hash)
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
