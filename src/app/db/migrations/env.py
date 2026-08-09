"""Alembic environment.

Two ways in:

* the host CLI (`uv run alembic ...`), which lands here with no connection and
  builds its own engine from `Settings`; and
* `app.db.migrate`, which hands over a live `Connection` through
  `config.attributes["connection"]` so the app reuses its own engine — and, with
  it, the advisory lock that serialises replicas.

The `include_object` filter is the load-bearing part. TimescaleDB keeps chunks
and catalogues in schemas of its own, and every chunk of the `metrics`
hypertable is a real table. Without the filter, autogenerate sees hundreds of
tables that are not in `Base.metadata` and cheerfully proposes dropping them.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config import get_database_settings
from app.db.base import Base

# Importing for the side effect of registering every table on Base.metadata.
from app.db import tables  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

TIMESCALE_SCHEMAS = {
    "_timescaledb_internal",
    "_timescaledb_catalog",
    "_timescaledb_config",
    "_timescaledb_cache",
    "_timescaledb_functions",
    "timescaledb_information",
    "timescaledb_experimental",
}


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Keep TimescaleDB's own objects out of the diff."""
    if getattr(obj, "schema", None) in TIMESCALE_SCHEMAS:
        return False
    if type_ == "table" and name.startswith(("_hyper_", "compress_hyper_")):
        return False
    return True


def _url() -> str:
    """The DSN, from alembic.ini if set and from the environment otherwise.

    `DatabaseSettings` rather than `Settings`: a migration needs credentials for
    one database and nothing else, and requiring `JWT_SECRET` to run
    `alembic history` would be absurd.
    """
    return (
        config.get_main_option("sqlalchemy.url")
        or get_database_settings().sqlalchemy_url
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it — `alembic upgrade head --sql`."""
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _url()
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as conn:
        _run(conn)
        conn.commit()


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_object=include_object,
        # Catches a column whose Python type changed without its name changing,
        # which is otherwise invisible to autogenerate.
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
