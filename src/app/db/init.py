"""Apply `schema.sql`.

Runnable two ways:

* from the app's lifespan when `DB_AUTO_INIT=true` (the default), and
* standalone, `python -m app.db.init`, e.g. as a Kubernetes Job.

The whole file goes through in one transaction and is safe to re-run, followed
by the compression and retention policies, which are settings-driven and so
cannot live in the SQL file. Startup retries, because on a cold cluster the app
is up before Postgres finishes `initdb`.
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
        apply_policies_blocking(conn, settings)
    finally:
        conn.close()


def apply_policies_blocking(conn, settings: Settings) -> None:
    """Schedule compression and retention on the metrics hypertable.

    These live here rather than in `schema.sql` because both windows are
    settings, and a policy is a scheduled background job rather than a schema
    object: `add_*_policy(..., if_not_exists => TRUE)` would keep whatever
    window was first installed and quietly ignore a changed setting. Dropping
    and re-adding makes the configuration authoritative on every startup, and is
    what keeps re-running this file idempotent.

    A failure here is logged rather than raised. The schema is already applied
    and the app is functional without the policies — but say so loudly, because
    an unnoticed missing retention policy is how a disk fills up.
    """
    jobs = (
        (
            "compression",
            "remove_compression_policy('metrics', if_exists => TRUE)",
            "add_compression_policy('metrics', INTERVAL %s)",
            f"{settings.metrics_compress_after_hours} hours",
            settings.metrics_compress_after_hours > 0,
        ),
        (
            "retention",
            "remove_retention_policy('metrics', if_exists => TRUE)",
            "add_retention_policy('metrics', INTERVAL %s)",
            f"{settings.metrics_retention_days} days",
            settings.metrics_retention_days > 0,
        ),
    )
    for name, remove_sql, add_sql, window, enabled in jobs:
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT {remove_sql}")
                    if enabled:
                        cur.execute(f"SELECT {add_sql}", (window,))
        except psycopg2.Error as exc:
            log.error("could not set the %s policy: %s", name, str(exc).strip())
            continue
        log.info(
            "%s policy %s", name, f"set to {window}" if enabled else "disabled"
        )


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
