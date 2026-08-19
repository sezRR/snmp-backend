"""Bring the database up to the latest revision.

Runnable two ways, exactly as `schema.sql` was before it:

* from the app's lifespan when `DB_AUTO_MIGRATE=true` (the default), reusing the
  application's own engine, and
* standalone, `python -m app.db.migrate`, for an installation that would rather
  not have its application processes touch DDL at all.

Two things wrap the upgrade.

**Retries.** On a cold start the app may run before Postgres finishes `initdb`,
so a refused connection is expected rather than fatal for the first few seconds.

**An advisory lock.** `alembic upgrade` is not safe to run concurrently: two
processes starting together both read the same current revision, both run the
same migration, and the loser gets a duplicate key on `alembic_version` — or,
worse, half-applies DDL that the first replica already applied. A session-level
advisory lock serialises them, and the process that waits finds the work already
done and does nothing. There is one process today; the lock costs a round trip
and removes the trap before someone scales up.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from starlette.concurrency import run_in_threadpool

from app.config import DatabaseSettings, get_database_settings

log = logging.getLogger(__name__)

MIGRATIONS_PATH = Path(__file__).with_name("migrations")

# Arbitrary but fixed: any other process taking this same key is, by definition,
# also migrating this database.
ADVISORY_LOCK_KEY = 8891274401


def alembic_config(settings: DatabaseSettings) -> Config:
    """The equivalent of alembic.ini, built in code.

    The image's runtime stage copies only `src/`, so nothing at the repository
    root is available at runtime — including alembic.ini.
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_PATH))
    cfg.set_main_option("sqlalchemy.url", settings.sqlalchemy_url)
    return cfg


def upgrade_to_head_blocking(engine: Engine, settings: DatabaseSettings) -> None:
    """Take the lock, upgrade, release. Blocking."""
    cfg = alembic_config(settings)
    with engine.connect() as lock_conn:
        # Session-level, so it outlives the upgrade's own transaction and is
        # released explicitly below rather than at the first commit.
        lock_conn.execute(
            text("SELECT pg_advisory_lock(:key)"), {"key": ADVISORY_LOCK_KEY}
        )
        lock_conn.commit()
        try:
            with engine.begin() as conn:
                cfg.attributes["connection"] = conn
                command.upgrade(cfg, "head")
        finally:
            lock_conn.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": ADVISORY_LOCK_KEY}
            )
            lock_conn.commit()


def upgrade_with_retries(engine: Engine, settings: DatabaseSettings) -> None:
    """Upgrade, waiting out a database that is still starting."""
    attempts = max(1, settings.db_init_max_attempts)
    for attempt in range(1, attempts + 1):
        try:
            upgrade_to_head_blocking(engine, settings)
            log.info("database at head (attempt %s)", attempt)
            return
        except OperationalError as exc:
            if attempt == attempts:
                raise
            log.warning(
                "database not ready (attempt %s/%s): %s",
                attempt,
                attempts,
                str(exc).strip().splitlines()[0],
            )
            time.sleep(settings.db_init_retry_seconds)


async def run_migrations(engine: Engine, settings: DatabaseSettings) -> None:
    """Async wrapper for use from the app's lifespan."""
    await run_in_threadpool(upgrade_with_retries, engine, settings)


def main() -> None:
    from app.db.pool import Database

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # DatabaseSettings, not Settings: a migration process should not need the API's
    # signing key or an admin password to do its one job.
    settings = get_database_settings()
    db = Database(settings)
    db.connect()
    try:
        upgrade_with_retries(db.engine, settings)
    finally:
        db.close()


if __name__ == "__main__":
    main()
