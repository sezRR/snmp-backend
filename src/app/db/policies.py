"""Background jobs on the metrics hypertable and its rollups.

These stay out of Alembic on purpose. Every window here is a setting, and a
policy is a scheduled background job rather than a schema object: a migration
would pin whichever window happened to be configured the day it was written, and
`add_*_policy(..., if_not_exists => TRUE)` would then keep that first window and
quietly ignore the changed setting. Dropping and re-adding on every boot makes
the configuration authoritative, and is what keeps this safe to re-run.

What is *not* here: the aggregates themselves, and the `timescaledb.compress`
setting on each of them. Those are schema — they change what the database
contains rather than when it is tidied — so revision 0004 owns them.

A failure here is logged rather than raised. The schema is already applied and
the app is functional without the policies — but say so loudly, because an
unnoticed missing retention policy is how a disk fills up.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from app.config import Settings

log = logging.getLogger(__name__)

# When each rollup's own chunks are compressed. Not settings: unlike the raw
# window these are not a storage/detail tradeoff anyone tunes, they are just far
# enough back that nothing is still writing to the chunk.
ROLLUP_1M_COMPRESS_AFTER = "7 days"
ROLLUP_1H_COMPRESS_AFTER = "30 days"

# How wide each rollup's own chunks are. TimescaleDB defaults a continuous
# aggregate to ten times its source's chunk interval, which here means both
# rollups inherit 40 hours from the raw table's 4. That is roughly right for the
# minute rollup and badly wrong for the hourly one: 40 hours of hourly buckets
# is 40 rows per machine per chunk, so a two year retention would accumulate
# ~440 chunks whose per-chunk overhead dwarfs what they hold, and a query
# spanning the full window has to plan across every one of them.
#
# Sized instead by how much each holds: a day of minute buckets is 1440 rows per
# machine, a month of hourly buckets is 720.
ROLLUP_1M_CHUNK_INTERVAL = "1 day"
ROLLUP_1H_CHUNK_INTERVAL = "30 days"


@dataclass(frozen=True)
class _Job:
    name: str
    remove: str
    add: str
    params: dict[str, str]
    enabled: bool


def _refresh_lag_days(settings: Settings) -> float:
    """How far back a rollup refresh reaches, clamped inside the raw window.

    A refresh that reaches further back than retention is asked to re-read
    chunks that have already been dropped, and the rollup develops holes exactly
    where the raw data used to be. Retention is the harder constraint of the
    two, so the lag yields to it.
    """
    lag = settings.metrics_rollup_refresh_lag_days
    retention = settings.metrics_retention_days
    if retention <= 0:
        return lag
    ceiling = max(retention * 0.75, 0.0)
    if lag > ceiling:
        log.warning(
            "rollup refresh lag %.2fd exceeds what a %.2fd retention can feed; "
            "using %.2fd",
            lag,
            retention,
            ceiling,
        )
        return ceiling
    return lag


def _jobs(settings: Settings) -> tuple[_Job, ...]:
    lag = f"{_refresh_lag_days(settings)} days"
    rollups = (
        ("metrics_1m", "1 minute", "1 minute", ROLLUP_1M_COMPRESS_AFTER,
         settings.metrics_rollup_1m_retention_days),
        ("metrics_1h", "1 hour", "10 minutes", ROLLUP_1H_COMPRESS_AFTER,
         settings.metrics_rollup_1h_retention_days),
    )

    jobs: list[_Job] = [
        _Job(
            "compression",
            "remove_compression_policy('metrics', if_exists => TRUE)",
            "add_compression_policy('metrics', CAST(:window AS interval))",
            {"window": f"{settings.metrics_compress_after_hours} hours"},
            settings.metrics_compress_after_hours > 0,
        ),
        _Job(
            "retention",
            "remove_retention_policy('metrics', if_exists => TRUE)",
            "add_retention_policy('metrics', CAST(:window AS interval))",
            {"window": f"{settings.metrics_retention_days} days"},
            settings.metrics_retention_days > 0,
        ),
    ]

    for view, end_offset, schedule, compress_after, retention_days in rollups:
        jobs.extend(
            (
                _Job(
                    f"{view} refresh",
                    f"remove_continuous_aggregate_policy('{view}', if_exists => TRUE)",
                    f"""add_continuous_aggregate_policy(
                        '{view}',
                        start_offset => CAST(:start_offset AS interval),
                        end_offset => CAST(:end_offset AS interval),
                        schedule_interval => CAST(:schedule AS interval)
                    )""",
                    {
                        "start_offset": lag,
                        "end_offset": end_offset,
                        "schedule": schedule,
                    },
                    True,
                ),
                _Job(
                    f"{view} compression",
                    f"remove_compression_policy('{view}', if_exists => TRUE)",
                    f"add_compression_policy('{view}', CAST(:window AS interval))",
                    {"window": compress_after},
                    True,
                ),
                _Job(
                    f"{view} retention",
                    f"remove_retention_policy('{view}', if_exists => TRUE)",
                    f"add_retention_policy('{view}', CAST(:window AS interval))",
                    {"window": f"{retention_days} days"},
                    retention_days > 0,
                ),
            )
        )
    return tuple(jobs)


def _chunk_intervals(settings: Settings) -> tuple[tuple[str, str], ...]:
    hours = settings.metrics_chunk_interval_hours
    rollups = (
        ("metrics_1m", ROLLUP_1M_CHUNK_INTERVAL),
        ("metrics_1h", ROLLUP_1H_CHUNK_INTERVAL),
    )
    if hours <= 0:
        return rollups
    return (("metrics", f"{hours} hours"), *rollups)


def _apply_chunk_intervals(engine: Engine, settings: Settings) -> None:
    """Re-assert every chunk interval on every boot.

    Tuning rather than schema, for the same reason the policies are, and safe to
    re-apply because `set_chunk_time_interval` only affects chunks created from
    here on. Existing chunks keep the interval they were made with and age out.

    A rollup is named by its view here; TimescaleDB resolves that to the
    materialization hypertable underneath, whose generated name is not stable
    enough to hardcode.
    """
    for relation, window in _chunk_intervals(settings):
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "SELECT set_chunk_time_interval(CAST(:relation AS regclass), "
                        "CAST(:window AS interval))"
                    ),
                    {"relation": relation, "window": window},
                )
        except SQLAlchemyError as exc:
            log.error(
                "could not set the %s chunk interval: %s", relation, str(exc).strip()
            )
            continue
        log.info("%s chunk interval set to %s", relation, window)


def apply_policies_blocking(engine: Engine, settings: Settings) -> None:
    _apply_chunk_intervals(engine, settings)
    for job in _jobs(settings):
        try:
            with engine.begin() as conn:
                conn.execute(text(f"SELECT {job.remove}"))
                if job.enabled:
                    conn.execute(text(f"SELECT {job.add}"), job.params)
        except SQLAlchemyError as exc:
            log.error("could not set the %s policy: %s", job.name, str(exc).strip())
            continue
        if job.enabled:
            log.info("%s policy set to %s", job.name, ", ".join(job.params.values()))
        else:
            log.info("%s policy disabled", job.name)


async def apply_policies(engine: Engine, settings: Settings) -> None:
    """Async wrapper for use from the app's lifespan."""
    await run_in_threadpool(apply_policies_blocking, engine, settings)
