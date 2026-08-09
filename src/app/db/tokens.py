"""Refresh token repository.

The access token is stateless and this table does not know about it. What lives
here is the one credential long-lived enough to be worth revoking.

Rotation is the reason for `replaced_by`. Every refresh mints a new token and
marks the old one replaced, so a token presented twice is proof that a copy
escaped — the legitimate client would already have moved on to its successor.
The response to that is not to reject one request but to revoke the user's whole
chain, since there is no way to tell the thief from the victim.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.db.tables import RefreshToken


class TokenReplayed(RuntimeError):
    """A refresh token that was already used, revoked, or has expired.

    `burn_user_id` is set only for a genuine replay — a token presented after it
    was already exchanged. The caller must then revoke that user's whole chain,
    and must do it *in a new transaction*: this one is about to roll back, which
    would take the revocation with it.
    """

    def __init__(self, message: str, burn_user_id: uuid.UUID | None = None) -> None:
        super().__init__(message)
        self.burn_user_id = burn_user_id


def record(
    session: Session, jti: uuid.UUID, user_id: uuid.UUID, expires_at: datetime
) -> RefreshToken:
    token = RefreshToken(jti=jti, user_id=user_id, expires_at=expires_at)
    session.add(token)
    session.flush()
    return token


def get(session: Session, jti: uuid.UUID) -> RefreshToken | None:
    return session.get(RefreshToken, jti)


def redeem(session: Session, jti: uuid.UUID) -> RefreshToken:
    """Claim a refresh token for rotation, or refuse and burn the chain.

    A token unknown to this table was signed by us but never issued, or belongs
    to a user who has since been deleted — either way it is not redeemable.
    """
    token = session.get(RefreshToken, jti)
    if token is None:
        raise TokenReplayed("unknown refresh token")
    if token.revoked_at is not None:
        # Already spent. The holder is either replaying or is the victim of one;
        # both are answered by ending every session this user has — but not from
        # here, because raising rolls this transaction back. The caller burns the
        # chain separately; see TokenReplayed.
        raise TokenReplayed(
            "refresh token has already been used", burn_user_id=token.user_id
        )
    if token.expires_at <= datetime.now(UTC):
        raise TokenReplayed("refresh token has expired")
    return token


def rotate(
    session: Session,
    old: RefreshToken,
    new_jti: uuid.UUID,
    expires_at: datetime,
) -> RefreshToken:
    """Revoke `old`, issue its successor, and link the two."""
    successor = record(session, new_jti, old.user_id, expires_at)
    # Python-side rather than func.now(), for the same reason `updated_at` is —
    # see app.db.tables._now.
    old.revoked_at = datetime.now(UTC)
    old.replaced_by = successor.jti
    return successor


def revoke(session: Session, token: RefreshToken) -> None:
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
