"""Application settings.

Values are read from the process environment first and from a `.env` file
second, so the Kubernetes ConfigMap and Secret always win over a developer's
local file. See `.env.example` for the full list with defaults.

Split in two on purpose. `DatabaseSettings` is everything needed to reach the
database and nothing else; `Settings` adds the rest of the application. Alembic
and `python -m app.db.migrate` load only the former, so a migration does not
have to be handed a JWT signing key it will never use — and `make check` works
on a developer's machine without one.
"""

from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """How to reach Postgres, and how to migrate it. No application config."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Database -----------------------------------------------------------
    # Names match libpq's own variables, which is also what the TigerData
    # Kubernetes guide puts in its Secret.
    pghost: str = "timescaledb"
    pgport: int = 5432
    pgdatabase: str = "app"
    pguser: str = "app"
    pgpassword: str = ""
    pgsslmode: str = "prefer"

    # SQLAlchemy's pool_size is the *persistent* pool, not a floor to grow from:
    # anything past it is opened and closed per checkout. 1 would mean a single
    # kept connection and 15 churned ones, so the floor is higher than the
    # psycopg2 pool's was.
    db_pool_min: int = 5
    db_pool_max: int = 16
    db_connect_timeout_seconds: int = 5
    db_statement_timeout_ms: int = 15_000
    # Run `alembic upgrade head` on startup. Turn off to migrate out of band,
    # e.g. from a Kubernetes Job running `python -m app.db.migrate`.
    # The old name is still accepted so an unupdated ConfigMap keeps working.
    db_auto_migrate: bool = Field(
        default=True, validation_alias=AliasChoices("DB_AUTO_MIGRATE", "DB_AUTO_INIT")
    )
    # How long the migration step waits out a database that is still doing
    # initdb. 30 x 2s covers a cold cluster comfortably.
    db_init_max_attempts: int = 30
    db_init_retry_seconds: float = 2.0

    @property
    def dsn(self) -> str:
        """libpq connection string, per the TigerData Python quickstart."""
        return (
            f"postgresql://{self.pguser}:{self.pgpassword}"
            f"@{self.pghost}:{self.pgport}/{self.pgdatabase}"
            f"?sslmode={self.pgsslmode}"
            f"&connect_timeout={self.db_connect_timeout_seconds}"
        )

    @property
    def sqlalchemy_url(self) -> str:
        """The same database, for `create_engine` and Alembic.

        No query string: `sslmode`, `connect_timeout` and `statement_timeout`
        are passed as `connect_args` instead, so a password containing `@`, `/`
        or `?` cannot corrupt the URL.
        """
        user = quote_plus(self.pguser)
        password = quote_plus(self.pgpassword)
        return (
            f"postgresql+psycopg2://{user}:{password}"
            f"@{self.pghost}:{self.pgport}/{self.pgdatabase}"
        )

    @property
    def connect_args(self) -> dict[str, object]:
        """libpq options that are not part of the URL."""
        return {
            "sslmode": self.pgsslmode,
            "connect_timeout": self.db_connect_timeout_seconds,
            # A runaway query holds a pooled connection hostage; bound it.
            "options": f"-c statement_timeout={self.db_statement_timeout_ms}",
        }


class Settings(DatabaseSettings):
    """Everything else: the collector, SNMP, OpenStack, the API and auth."""

    # ---- Collector ----------------------------------------------------------
    collector_enabled: bool = True
    collector_interval_seconds: float = 5.0
    # Gates SNMP calls only, not database connections: a tick issues two or three
    # queries in total regardless of how many machines it samples, so this is
    # sized against the fleet and the interval, not against `db_pool_max`.
    collector_concurrency: int = 32
    # Wall-clock ceiling on one machine's sample, so a slow agent can never hold
    # a concurrency slot for longer than the interval. 0 derives it from the
    # interval, which is the sane default; set it explicitly to override.
    collector_sample_timeout_seconds: float = 0.0

    # ---- SNMP ---------------------------------------------------------------
    # With no real SNMP agents around, the simulator is the default. Flipping
    # this to false uses pysnmp against the machines' IPv4 addresses.
    snmp_simulate: bool = True
    snmp_community: str = "public"
    snmp_port: int = 161
    # Worst case per machine is timeout * (retries + 1) = 3.0s, inside the 4.0s
    # sample budget a 5 second interval derives.
    snmp_timeout_seconds: float = 1.5
    snmp_retries: int = 1
    # Rows an agent may pack into one GETBULK response. The ceiling is not SNMP's
    # but the path's: a response larger than the smallest MTU between here and the
    # agent is fragmented, and a fragment lost to a NAT or a tunnel takes the whole
    # response with it — the walk simply times out. Twenty-five rows of a table
    # with long string columns (hrStorageDescr on a container host) is enough to
    # cross that line over a 1280-byte tunnel, so the default is deliberately low.
    # The sampler halves it per agent whenever a walk times out anyway.
    snmp_max_repetitions: int = 10
    # DISKIO-MIB costs about six extra walks per machine and needs an snmpd that
    # both ships the diskio module and exposes 1.3.6.1.4.1.2021.13.15 in its
    # view. Turn it off for agents that have neither.
    snmp_diskio_enabled: bool = True

    # ---- Metric retention ----------------------------------------------------
    # Applied as TimescaleDB background jobs by `app.db.policies`. Either at 0
    # disables that policy and leaves the data alone. Compression works on
    # batches of up to a thousand rows, so the ratio it achieves depends on how
    # full a chunk is — a busy day compresses far better than a quiet one.
    metrics_compress_after_hours: float = 24.0
    metrics_retention_days: float = 30.0

    # ---- OpenStack ----------------------------------------------------------
    # Only the simulated lookup ships today; the real client goes behind the
    # same Protocol and is selected by flipping this to false.
    openstack_simulate: bool = True
    openstack_cache_ttl_seconds: float = 300.0
    os_auth_url: str = ""
    os_project_name: str = ""
    os_username: str = ""
    os_password: str = ""
    os_region_name: str = ""
    os_user_domain_name: str = "Default"
    os_project_domain_name: str = "Default"

    # ---- Auth ---------------------------------------------------------------
    # JWT_SECRET has no default and no fallback. Generating one would be worse
    # than failing: it would differ between replicas, so a token minted by one
    # pod would be rejected by the next, and it would rotate on every restart,
    # logging every user out on every rollout. Generate one with
    # `openssl rand -hex 32` and put it in the Secret.
    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "snmp-metrics-api"
    # Short, because an access token cannot be revoked — see services/auth.py.
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 1_209_600
    password_min_length: int = 12
    # EventSource cannot send an Authorization header, so a stream is opened
    # with a single-use ticket instead of a token in the query string. Thirty
    # seconds is enough to redeem one and short enough that a ticket leaked into
    # an access log is inert by the time anyone reads it.
    stream_ticket_ttl_seconds: float = 30.0

    # ---- Admin bootstrap ----------------------------------------------------
    # Both required: without an admin account nothing can be administered, so a
    # backend that cannot create one must not start.
    admin_username: str
    admin_password: SecretStr
    # One-shot recovery for a forgotten admin password. Off by default so a
    # password changed through the API is not silently reverted on every restart
    # by a stale value in the environment.
    admin_password_reset: bool = False

    # ---- API ----------------------------------------------------------------
    # Traefik strips /api before the request arrives; this puts the prefix back
    # into the URLs FastAPI generates (docs, OpenAPI `servers`).
    root_path: str = ""
    sse_heartbeat_seconds: float = 15.0
    sse_queue_maxsize: int = 100
    log_level: str = Field(default="INFO", pattern="(?i)^(debug|info|warning|error|critical)$")

    @model_validator(mode="after")
    def _required_secrets_are_not_blank(self) -> "Settings":
        """Reject blank required values, which typing alone cannot.

        A required `str` field is satisfied by an empty string, and an empty
        string is exactly what an unfilled ConfigMap key or a `KEY=` line in a
        `.env` produces. Without this, `ADMIN_PASSWORD=` starts the backend with
        an admin account whose password is "".
        """
        blank = [
            name
            for name, value in (
                ("JWT_SECRET", self.jwt_secret.get_secret_value()),
                ("ADMIN_USERNAME", self.admin_username),
                ("ADMIN_PASSWORD", self.admin_password.get_secret_value()),
            )
            if not value.strip()
        ]
        if blank:
            hint = (
                " Generate a signing key with: openssl rand -hex 32"
                if "JWT_SECRET" in blank
                else ""
            )
            raise ValueError(
                f"{', '.join(blank)} must be set and non-blank.{hint}"
            )
        if len(self.jwt_secret.get_secret_value()) < 32:
            raise ValueError(
                "JWT_SECRET must be at least 32 characters; "
                "generate one with: openssl rand -hex 32"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_database_settings() -> DatabaseSettings:
    """For Alembic and the standalone migrator, which need nothing else."""
    return DatabaseSettings()
