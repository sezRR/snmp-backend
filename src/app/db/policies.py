"""Compression and retention on the metrics hypertable.

These stay out of Alembic on purpose. Both windows are settings
(`METRICS_COMPRESS_AFTER_HOURS`, `METRICS_RETENTION_DAYS`), and a policy is a
scheduled background job rather than a schema object: a migration would pin
whichever window happened to be configured the day it was written, and
`add_*_policy(..., if_not_exists => TRUE)` would then keep that first window and
quietly ignore the changed setting. Dropping and re-adding on every boot makes
the configuration authoritative, and is what keeps this safe to re-run.

A failure here is logged rather than raised. The schema is already applied and
the app is functional without the policies — but say so loudly, because an
unnoticed missing retention policy is how a disk fills up.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from app.config import Settings

log = logging.getLogger(__name__)


def apply_policies_blocking(engine: Engine, settings: Settings) -> None:
    jobs = (
        (
            "compression",
            "remove_compression_policy('metrics', if_exists => TRUE)",
            "add_compression_policy('metrics', CAST(:window AS interval))",
            f"{settings.metrics_compress_after_hours} hours",
            settings.metrics_compress_after_hours > 0,
        ),
        (
            "retention",
            "remove_retention_policy('metrics', if_exists => TRUE)",
            "add_retention_policy('metrics', CAST(:window AS interval))",
            f"{settings.metrics_retention_days} days",
            settings.metrics_retention_days > 0,
        ),
    )
    for name, remove_sql, add_sql, window, enabled in jobs:
        try:
            with engine.begin() as conn:
                conn.execute(text(f"SELECT {remove_sql}"))
                if enabled:
                    conn.execute(text(f"SELECT {add_sql}"), {"window": window})
        except SQLAlchemyError as exc:
            log.error("could not set the %s policy: %s", name, str(exc).strip())
            continue
        log.info("%s policy %s", name, f"set to {window}" if enabled else "disabled")


async def apply_policies(engine: Engine, settings: Settings) -> None:
    """Async wrapper for use from the app's lifespan."""
    await run_in_threadpool(apply_policies_blocking, engine, settings)
