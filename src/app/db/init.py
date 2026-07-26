"""Apply `schema.sql`.

Runnable two ways:

* from the app's lifespan when `DB_AUTO_INIT=true` (the default), and
* standalone, `python -m app.db.init`, e.g. as a Kubernetes Job.

The whole file goes through in one transaction and is safe to re-run. Startup
retries, because on a cold cluster the app is up before Postgres finishes
`initdb`.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psycopg2
from starlette.concurrency import run_in_threadpool

from app.config import Settings, get_settings

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def apply_schema_blocking(settings: Settings) -> None:
    """Open a dedicated connection and apply the schema. Blocking."""
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = psycopg2.connect(settings.dsn)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
    finally:
        conn.close()


def apply_schema_with_retries(settings: Settings) -> None:
    """Apply the schema, waiting out a database that is still starting."""
    attempts = max(1, settings.db_init_max_attempts)
    for attempt in range(1, attempts + 1):
        try:
            apply_schema_blocking(settings)
            log.info("schema applied (attempt %s)", attempt)
            return
        except psycopg2.OperationalError as exc:
            if attempt == attempts:
                raise
            log.warning(
                "database not ready (attempt %s/%s): %s",
                attempt,
                attempts,
                str(exc).strip(),
            )
            time.sleep(settings.db_init_retry_seconds)


async def apply_schema(settings: Settings) -> None:
    """Async wrapper for use from the app's lifespan."""
    await run_in_threadpool(apply_schema_with_retries, settings)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    apply_schema_with_retries(get_settings())


if __name__ == "__main__":
    main()
