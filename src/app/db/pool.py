"""SQLAlchemy engine over psycopg2, usable from async endpoints.

psycopg2 is synchronous and stays that way — SQLAlchemy is here for the schema
(Alembic diffs `Base.metadata`) and for the auth code's ORM, not to make the
database layer async. Every call still runs in Starlette's worker threadpool,
which keeps the event loop free (see `run_query`). Two sizing rules follow:

* `DB_POOL_MAX` must exceed `COLLECTOR_CONCURRENCY` plus whatever the request
  path needs, or the collector will starve request handlers of connections;
* AnyIO's default worker limit (40 threads) caps how many queries can be in
  flight at once, regardless of pool size.

Two seams are exposed, and which one to use is a property of the caller:

* `run_query(fn, conn_args...)` hands `fn` a `Connection`. The fleet and metric
  repositories use it — their SQL is hand-tuned around TimescaleDB and there is
  nothing for an identity map to do.
* `run_session(fn, ...)` hands `fn` a `Session`. The auth repositories use it,
  where relationships and cascades earn their keep.

Both commit on a clean return and roll back on an exception.
"""

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
            # pool_size is the persistent pool and max_overflow is what may be
            # opened past it, so the two together cap total connections at
            # DB_POOL_MAX — the same ceiling the psycopg2 pool enforced.
            pool_size=settings.db_pool_min,
            max_overflow=max(0, settings.db_pool_max - settings.db_pool_min),
            # Cheap round-trip before handing out a connection, so a database
            # restart or an idle connection reaped by a firewall surfaces as a
            # reconnect rather than as a failed request.
            pool_pre_ping=True,
            pool_recycle=1800,
            # Compiles executemany into psycopg2's execute_values, which is what
            # the collector's batch insert relies on to stay one round trip.
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
