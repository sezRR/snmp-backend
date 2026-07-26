"""psycopg2 connection pool, usable from async endpoints.

psycopg2 is synchronous, so every call here runs in Starlette's worker
threadpool. That keeps the event loop free without giving up psycopg2 (see
`run_query`). Two sizing rules follow from it:

* `DB_POOL_MAX` must exceed `COLLECTOR_CONCURRENCY` plus whatever the request
  path needs, or the collector will starve request handlers of connections;
* AnyIO's default worker limit (40 threads) caps how many queries can be in
  flight at once, regardless of pool size.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, TypeVar

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.extras import RealDictCursor
from starlette.concurrency import run_in_threadpool

from app.config import Settings

log = logging.getLogger(__name__)

T = TypeVar("T")


class Database:
    """Owns the pool and hands out connections."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: pg_pool.ThreadedConnectionPool | None = None

    def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = pg_pool.ThreadedConnectionPool(
            minconn=self._settings.db_pool_min,
            maxconn=self._settings.db_pool_max,
            dsn=self._settings.dsn,
            # A runaway query holds a pooled connection hostage; bound it.
            options=f"-c statement_timeout={self._settings.db_statement_timeout_ms}",
        )
        log.info(
            "database pool opened (%s..%s connections to %s:%s/%s)",
            self._settings.db_pool_min,
            self._settings.db_pool_max,
            self._settings.pghost,
            self._settings.pgport,
            self._settings.pgdatabase,
        )

    def close(self) -> None:
        if self._pool is not None:
            self._pool.closeall()
            self._pool = None
            log.info("database pool closed")

    @contextmanager
    def connection(self):
        """Check a connection out, commit on success, roll back on failure.

        Blocking: call it inside `run_query`, not directly from a coroutine.
        """
        if self._pool is None:
            raise RuntimeError("database pool is not open")
        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    @contextmanager
    def cursor(self):
        """Dict-returning cursor on a pooled connection. Also blocking."""
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur

    async def run_query(self, fn: Callable[..., T], *args: Any) -> T:
        """Run a blocking DB function in the threadpool.

        `fn` receives a `RealDictCursor` as its first argument:

            rows = await db.run_query(lambda cur: cur.execute(...) or cur.fetchall())
        """

        def _call() -> T:
            with self.cursor() as cur:
                return fn(cur, *args)

        return await run_in_threadpool(_call)

    async def healthcheck(self) -> str | None:
        """Returns the installed TimescaleDB version, or raises."""

        def _check(cur) -> str | None:
            cur.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
            )
            row = cur.fetchone()
            return row["extversion"] if row else None

        return await self.run_query(_check)


class DatabaseUnavailable(RuntimeError):
    """Raised when the pool cannot be opened or a connection cannot be had."""


def is_connection_error(exc: BaseException) -> bool:
    """True for errors worth retrying (server not up yet, connection dropped)."""
    return isinstance(exc, (psycopg2.OperationalError, psycopg2.InterfaceError))
