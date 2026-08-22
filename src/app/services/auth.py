from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from starlette.concurrency import run_in_threadpool

from app.config import Settings

log = logging.getLogger(__name__)

ACCESS = "access"
REFRESH = "refresh"

_hasher = PasswordHash((Argon2Hasher(time_cost=2, memory_cost=19_456, parallelism=1),))


class TokenError(Exception):
    """A token that will not decode, verify, or is not the type expected."""


@dataclass(frozen=True, slots=True)
class DecodedToken:
    user_id: uuid.UUID
    username: str
    scopes: frozenset[str]
    jti: uuid.UUID
    token_type: str
    expires_at: datetime
    # users.session_epoch at minting. Absent on older tokens, which read as 0
    # and keep working until they expire.
    epoch: int = 0


# --- Passwords ---------------------------------------------------------------


def hash_password_blocking(password: str) -> str:
    return _hasher.hash(password)


async def hash_password(password: str) -> str:
    """Argon2 is CPU-bound by design; keep it off the event loop."""
    return await run_in_threadpool(hash_password_blocking, password)


def verify_password_blocking(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Returns (ok, new_hash). `new_hash` is set when the cost has been raised."""
    try:
        return _hasher.verify_and_update(password, password_hash)
    except Exception:
        # An unparseable hash is a failed login, not a 500.
        log.warning("could not verify a stored password hash")
        return False, None


async def verify_password(password: str, password_hash: str) -> tuple[bool, str | None]:
    return await run_in_threadpool(verify_password_blocking, password, password_hash)


# --- Tokens ------------------------------------------------------------------


def _encode(
    settings: Settings,
    *,
    user_id: uuid.UUID,
    username: str,
    token_type: str,
    ttl_seconds: int,
    scopes: frozenset[str] | None = None,
    epoch: int | None = None,
) -> tuple[str, uuid.UUID, datetime]:
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=ttl_seconds)
    jti = uuid.uuid4()
    claims: dict[str, object] = {
        "sub": str(user_id),
        "username": username,
        "type": token_type,
        "jti": str(jti),
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if scopes is not None:
        claims["scopes"] = sorted(scopes)
    if epoch is not None:
        claims["ep"] = epoch
    token = jwt.encode(
        claims,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, jti, expires_at


def create_access_token(
    settings: Settings,
    user_id: uuid.UUID,
    username: str,
    scopes: frozenset[str],
    epoch: int = 0,
) -> str:
    """Scopes are baked in at mint time.

    The alternative — re-reading roles on every request — would make a role
    change take effect instantly at the cost of a join per request, including
    per SSE reconnect. Baking them in bounds the staleness at the access token's
    TTL instead, and `/auth/refresh` re-reads from the database, so a revoked
    role is gone within minutes without a permanent query cost.

    `epoch` is the exception to that bargain, for the one change that cannot
    wait out a TTL: ending a session. It is checked on every request against a
    cached copy of the column — see `app.services.sessions`.
    """
    token, _, _ = _encode(
        settings,
        user_id=user_id,
        username=username,
        token_type=ACCESS,
        ttl_seconds=settings.access_token_ttl_seconds,
        scopes=scopes,
        epoch=epoch,
    )
    return token


def create_refresh_token(
    settings: Settings, user_id: uuid.UUID, username: str
) -> tuple[str, uuid.UUID, datetime]:
    """Returns the token and the (jti, expires_at) its database row needs.

    No scopes: a refresh token authorises nothing but the minting of a new pair,
    whose scopes are read fresh from the user's roles.
    """
    return _encode(
        settings,
        user_id=user_id,
        username=username,
        token_type=REFRESH,
        ttl_seconds=settings.refresh_token_ttl_seconds,
    )


def decode_token(settings: Settings, token: str, expected_type: str) -> DecodedToken:
    """Verify signature, issuer, expiry and type. Raises `TokenError` otherwise."""
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc

    if claims.get("type") != expected_type:
        # Otherwise an access token would pass /auth/refresh, and a scopeless
        # refresh token would 403 instead of 401.
        raise TokenError(f"expected a {expected_type} token")

    try:
        user_id = uuid.UUID(claims["sub"])
        jti = uuid.UUID(claims["jti"])
    except (KeyError, ValueError) as exc:
        raise TokenError("malformed token subject or id") from exc

    return DecodedToken(
        user_id=user_id,
        username=claims.get("username", ""),
        scopes=frozenset(claims.get("scopes") or ()),
        jti=jti,
        token_type=expected_type,
        expires_at=datetime.fromtimestamp(claims["exp"], UTC),
        # A token minted before the epoch existed reads as 0, the column default.
        epoch=int(claims.get("ep", 0)),
    )
