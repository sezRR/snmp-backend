from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from app.config import DatabaseSettings

log = logging.getLogger(__name__)

T = TypeVar("T")


class Database:
    """Owns the engine and hands out connections and sessions."""

    def __init__(self, settings: DatabaseSettings) -> None:
        self._settings = settings
        self._engine: Engine | None = None
        self._sessionmaker: sessionmaker[Session] | None = None

    def connect(self) -> None:
        if self._engine is not None:
            return
        settings = self._settings
        self._engine = create_engine(
            settings.sqlalchemy_url,
            # pool_size plus max_overflow cap total connections at DB_POOL_MAX.
            pool_size=settings.db_pool_min,
            max_overflow=max(0, settings.db_pool_max - settings.db_pool_min),
            # A cheap round trip, so a reaped connection reconnects instead of
            # failing the request.
            pool_pre_ping=True,
            pool_recycle=1800,
            # executemany -> execute_values, which keeps the batch insert to
            # one round trip.
            executemany_mode="values_plus_batch",
            connect_args=settings.connect_args,
            future=True,
        )
        self._sessionmaker = sessionmaker(bind=self._engine, expire_on_commit=False)
        log.info(
            "database engine opened (%s+%s connections to %s:%s/%s)",
            settings.db_pool_min,
            max(0, settings.db_pool_max - settings.db_pool_min),
            settings.pghost,
            settings.pgport,
            settings.pgdatabase,
        )

    def close(self) -> None:
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._sessionmaker = None
            log.info("database engine closed")

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            raise RuntimeError("database engine is not open")
        return self._engine

    async def run_query(self, fn: Callable[..., T], *args: Any) -> T:
        """Run a blocking function against a `Connection`, in the threadpool.

        `fn` receives the connection as its first argument:

            rows = await db.run_query(lambda conn: conn.execute(text(...)))

        `engine.begin()` commits when `fn` returns and rolls back if it raises.
        """

        def _call() -> T:
            with self.engine.begin() as conn:
                return fn(conn, *args)

        return await run_in_threadpool(_call)

    async def run_session(self, fn: Callable[..., T], *args: Any) -> T:
        """Same, but `fn` receives an ORM `Session` inside a transaction."""

        def _call() -> T:
            if self._sessionmaker is None:
                raise RuntimeError("database engine is not open")
            with self._sessionmaker() as session, session.begin():
                return fn(session, *args)

        return await run_in_threadpool(_call)

    async def healthcheck(self) -> str | None:
        """Returns the installed TimescaleDB version, or raises."""

        def _check(conn: Connection) -> str | None:
            row = conn.execute(
                text(
                    "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
                )
            ).first()
            return row[0] if row else None

        return await self.run_query(_check)
