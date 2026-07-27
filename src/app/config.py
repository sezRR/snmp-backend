"""Application settings.

Values are read from the process environment first and from a `.env` file
second, so the Kubernetes ConfigMap and Secret always win over a developer's
local file. See `.env.example` for the full list with defaults.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
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

    db_pool_min: int = 1
    db_pool_max: int = 16
    db_connect_timeout_seconds: int = 5
    db_statement_timeout_ms: int = 15_000
    # Apply schema.sql on startup. Turn off if a migration tool owns the schema.
    db_auto_init: bool = True
    db_init_max_attempts: int = 30
    db_init_retry_seconds: float = 2.0

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
    # DISKIO-MIB costs about six extra walks per machine and needs an snmpd that
    # both ships the diskio module and exposes 1.3.6.1.4.1.2021.13.15 in its
    # view. Turn it off for agents that have neither.
    snmp_diskio_enabled: bool = True

    # ---- Metric retention ----------------------------------------------------
    # Applied as TimescaleDB background jobs by `app.db.init`. Either at 0
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

    # ---- API ----------------------------------------------------------------
    # Traefik strips /api before the request arrives; this puts the prefix back
    # into the URLs FastAPI generates (docs, OpenAPI `servers`).
    root_path: str = ""
    sse_heartbeat_seconds: float = 15.0
    sse_queue_maxsize: int = 100
    log_level: str = Field(default="INFO", pattern="(?i)^(debug|info|warning|error|critical)$")

    @property
    def dsn(self) -> str:
        """libpq connection string, per the TigerData Python quickstart."""
        return (
            f"postgresql://{self.pguser}:{self.pgpassword}"
            f"@{self.pghost}:{self.pgport}/{self.pgdatabase}"
            f"?sslmode={self.pgsslmode}"
            f"&connect_timeout={self.db_connect_timeout_seconds}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
