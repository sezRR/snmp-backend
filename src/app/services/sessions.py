from __future__ import annotations

import logging
import time
import uuid

from sqlalchemy import select
from sqlalchemy.engine import Connection

from app.db.pool import Database
from app.db.tables import User

log = logging.getLogger(__name__)


def _read_epoch(conn: Connection, user_id: uuid.UUID) -> int | None:
    row = conn.execute(
        select(User.__table__.c.session_epoch).where(User.__table__.c.id == user_id)
    ).first()
    return None if row is None else int(row[0])


class SessionEpochs:
    """Cache of `users.session_epoch`, keyed by user id."""

    def __init__(self, db: Database, ttl_seconds: float) -> None:
        self._db = db
        self._ttl = ttl_seconds
        self._cached: dict[uuid.UUID, tuple[float, int]] = {}

    async def matches(self, user_id: uuid.UUID, epoch: int) -> bool:
        """Is a token minted under `epoch` still current for this user?"""
        cached = self._fresh(user_id)
        if cached is not None and cached == epoch:
            return True
        # Nothing cached, or a disagreement — rare, and too consequential to guess.
        live = await self._db.run_query(_read_epoch, user_id)
        if live is None:
            return False
        self.remember(user_id, live)
        return live == epoch

    def remember(self, user_id: uuid.UUID, epoch: int) -> None:
        """Record an epoch this process just wrote or read.

        Called straight after a bump so the tokens minted in the same request
        are accepted without waiting out the TTL. Other processes find out on
        their next mismatch, which the token they are being shown guarantees.
        """
        self._cached[user_id] = (time.monotonic() + self._ttl, epoch)

    def forget(self, user_id: uuid.UUID) -> None:
        self._cached.pop(user_id, None)

    def _fresh(self, user_id: uuid.UUID) -> int | None:
        entry = self._cached.get(user_id)
        if entry is None:
            return None
        expires_at, epoch = entry
        if expires_at <= time.monotonic():
            del self._cached[user_id]
            return None
        return epoch
