"""Turning a request into a principal, and a scope requirement into a 403.

The pattern throughout the routers is::

    @router.get("/machines", dependencies=[requires(Scope.MACHINES_READ)])

or, where the handler needs to know who is calling::

    async def handler(principal: Annotated[Principal, requires(Scope.USERS_WRITE)]):

`requires` is FastAPI's `Security(...)`, so the scopes it names appear on each
operation in the OpenAPI document and Swagger's Authorize dialog lists them.

**Almost no database access.** Scopes are carried in the access token, so
authorisation costs zero queries — which is what makes this affordable on the
SSE routes, where the alternative is a join per reconnect. The staleness that
buys is bounded by the token's TTL.

The one thing that cannot wait out a TTL is a session the user has *ended*: a
password changed after a phone was lost is worth nothing if the phone keeps
reading for another fifteen minutes. So every request also asks whether the
token's session epoch is still current, which is a cached read of one integer
and, on the rare disagreement, one indexed row. See `app.services.sessions`.

**Streams are the exception to Bearer.** A browser's `EventSource` cannot set an
`Authorization` header, and the usual workaround — the access token in the query
string — puts a credential with full API authority into proxy access logs,
the browser's history, and every proxy in between. Instead a client exchanges
its token for a single-use ticket that is worth thirty seconds and one
connection.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

from app.api.deps import SessionEpochsDep, SettingsDep
from app.config import Settings
from app.security.scopes import SCOPE_DESCRIPTIONS, Scope
from app.services.auth import ACCESS, TokenError, decode_token
from app.services.sessions import SessionEpochs

log = logging.getLogger(__name__)

# auto_error=False so a missing header produces this module's 401 with a
# scope-bearing WWW-Authenticate, rather than FastAPI's bare one.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/login", scopes=dict(SCOPE_DESCRIPTIONS), auto_error=False
)


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    username: str
    scopes: frozenset[str]
    # The session epoch the token was minted under. Kept on the principal so a
    # long-lived stream can re-ask the question its connect request answered.
    epoch: int = 0

    def has(self, *scopes: str) -> bool:
        return self.scopes.issuperset(scopes)


def _unauthorized(detail: str, scopes: list[str] | None = None) -> HTTPException:
    challenge = "Bearer"
    if scopes:
        challenge = f'Bearer scope="{" ".join(scopes)}"'
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": challenge},
    )


def _principal_from_token(settings: Settings, token: str) -> Principal:
    try:
        decoded = decode_token(settings, token, ACCESS)
    except TokenError as exc:
        raise _unauthorized(f"invalid access token: {exc}") from exc
    return Principal(
        user_id=decoded.user_id,
        username=decoded.username,
        scopes=decoded.scopes,
        epoch=decoded.epoch,
    )


SESSION_ENDED_DETAIL = (
    "this session has ended; sign in again "
    "(the password changed, or the account was disabled)"
)


async def _require_live_session(epochs: SessionEpochs, principal: Principal) -> None:
    """401 if the token belongs to a session that has since been ended.

    401 rather than 403 on purpose: re-authenticating is exactly what fixes
    this, and the client's refresh will be refused too — the same change that
    bumped the epoch revoked the refresh tokens — so the browser reaches the
    login page instead of retrying forever.
    """
    if not await epochs.matches(principal.user_id, principal.epoch):
        raise _unauthorized(SESSION_ENDED_DETAIL)


async def get_current_principal(
    security_scopes: SecurityScopes,
    settings: SettingsDep,
    epochs: SessionEpochsDep,
    token: Annotated[str | None, Depends(oauth2_scheme)] = None,
) -> Principal:
    if token is None:
        raise _unauthorized("not authenticated", security_scopes.scopes)
    principal = _principal_from_token(settings, token)
    await _require_live_session(epochs, principal)
    _require_scopes(principal, security_scopes.scopes)
    return principal


def _require_scopes(principal: Principal, required: list[str]) -> None:
    missing = [s for s in required if s not in principal.scopes]
    if missing:
        # 403, not 401: the caller is who they say they are, they simply may not
        # do this. Re-authenticating would not help, so do not invite it.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing required scope(s): {', '.join(missing)}",
        )


def requires(*scopes: Scope | str) -> Security:
    """`Security(get_current_principal, scopes=[...])`, spelled shorter."""
    return Security(get_current_principal, scopes=[str(s) for s in scopes])


# Any valid token, no particular scope — /auth/me, /auth/logout.
AuthenticatedDep = Annotated[Principal, Security(get_current_principal)]


# --- Stream tickets ----------------------------------------------------------


class StreamTickets:
    """Single-use, short-lived credentials for `EventSource`.

    In-process, on `app.state`. That is not the limitation it looks like: the
    `MetricBus` a stream reads from is per-process already, so a subscriber is
    pinned to the process it connected to whatever we do here. If the bus ever
    becomes shared, this moves with it.
    """

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._issued: dict[str, tuple[float, Principal]] = {}

    def issue(self, principal: Principal) -> tuple[str, float]:
        self._evict_expired()
        ticket = secrets.token_urlsafe(32)
        self._issued[ticket] = (time.monotonic() + self._ttl, principal)
        return ticket, self._ttl

    def redeem(self, ticket: str) -> Principal | None:
        """Consume a ticket. A second attempt with the same one fails."""
        self._evict_expired()
        entry = self._issued.pop(ticket, None)
        if entry is None:
            return None
        expires_at, principal = entry
        return principal if expires_at > time.monotonic() else None

    def _evict_expired(self) -> None:
        now = time.monotonic()
        for ticket, (expires_at, _) in list(self._issued.items()):
            if expires_at <= now:
                del self._issued[ticket]


def get_stream_tickets(request: Request) -> StreamTickets:
    return request.app.state.stream_tickets


StreamTicketsDep = Annotated[StreamTickets, Depends(get_stream_tickets)]


async def get_stream_principal(
    settings: SettingsDep,
    tickets: StreamTicketsDep,
    epochs: SessionEpochsDep,
    # Security rather than Depends purely so metrics:read shows up on these two
    # operations in the OpenAPI document; auto_error is off either way, and the
    # actual check below covers the ticket path too.
    token: Annotated[
        str | None, Security(oauth2_scheme, scopes=[str(Scope.METRICS_READ)])
    ] = None,
    ticket: Annotated[
        str | None,
        Query(description="Single-use ticket from POST /auth/stream-ticket"),
    ] = None,
) -> Principal:
    """Bearer header or `?ticket=`, in that order.

    The header path is kept so `curl -N -H 'Authorization: ...'` and anything
    else that can set headers needs no ticket dance.
    """
    if token is not None:
        principal = _principal_from_token(settings, token)
    elif ticket is not None:
        redeemed = tickets.redeem(ticket)
        if redeemed is None:
            raise _unauthorized("stream ticket is unknown, expired or already used")
        principal = redeemed
    else:
        raise _unauthorized(
            "not authenticated: send a Bearer token, or ?ticket= from "
            "POST /auth/stream-ticket",
            [str(Scope.METRICS_READ)],
        )
    # Checked on the ticket path too: a ticket outlives the request that minted
    # it by up to thirty seconds, which is long enough for a password change to
    # land in between.
    await _require_live_session(epochs, principal)
    _require_scopes(principal, [str(Scope.METRICS_READ)])
    return principal


StreamPrincipalDep = Annotated[Principal, Depends(get_stream_principal)]
