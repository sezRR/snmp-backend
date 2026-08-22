import json
from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# AES-256: a shorter value is a mistake, not a request for AES-128.
CREDENTIAL_KEY_BYTES = 32


def parse_key_ring(raw: str) -> dict[str, bytes]:
    """`{"k1": "<hex>"}` -> `{"k1": b"..."}`. Raises ValueError on anything else.

    Shared with `python -m app.db.reencrypt`, which needs the same parse without
    the rest of `Settings`.
    """
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SNMP_CREDENTIAL_KEYS is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError(
            'SNMP_CREDENTIAL_KEYS must be a non-empty JSON object, e.g. {"k1": "<hex>"}'
        )

    ring: dict[str, bytes] = {}
    for key_id, value in parsed.items():
        if not isinstance(value, str):
            raise ValueError(f"SNMP_CREDENTIAL_KEYS[{key_id!r}] must be a hex string")
        try:
            material = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(
                f"SNMP_CREDENTIAL_KEYS[{key_id!r}] is not hex: {exc}"
            ) from exc
        if len(material) != CREDENTIAL_KEY_BYTES:
            raise ValueError(
                f"SNMP_CREDENTIAL_KEYS[{key_id!r}] is {len(material)} bytes; "
                f"it must be {CREDENTIAL_KEY_BYTES}. "
                "Generate one with: openssl rand -hex 32"
            )
        ring[key_id] = material
    return ring


def _csv_tuple(raw: str) -> tuple[str, ...]:
    """Split a comma separated list, dropping blanks and surrounding space.

    A tuple rather than a list because `str.startswith` takes one directly for
    the prefix lists below, and because those are read on every sample and must
    not be mutable by accident.
    """
    return tuple(part.strip() for part in raw.split(",") if part.strip())


class DatabaseSettings(BaseSettings):
    """How to reach Postgres, and how to migrate it. No application config."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Database -----------------------------------------------------------
    # Names match libpq's own environment variables.
    pghost: str = "timescaledb"
    pgport: int = 5432
    # Required, no defaults: a guessed name, user or password reaches the wrong
    # database, or none at all.
    pgdatabase: str
    pguser: str
    pgpassword: str
    pgsslmode: str = "prefer"

    # pool_size is the persistent pool, not a floor: anything past it churns.
    db_pool_min: int = 5
    db_pool_max: int = 16
    db_connect_timeout_seconds: int = 5
    db_statement_timeout_ms: int = 15_000
    # `alembic upgrade head` on startup; DB_AUTO_INIT is the legacy name.
    db_auto_migrate: bool = Field(
        default=True, validation_alias=AliasChoices("DB_AUTO_MIGRATE", "DB_AUTO_INIT")
    )
    # 30 x 2s covers a database still running initdb.
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

    @model_validator(mode="after")
    def _connection_settings_are_not_blank(self) -> "DatabaseSettings":
        """Reject blank required values, which typing alone cannot.

        A required `str` field is satisfied by an empty string, and an empty
        string is exactly what an unfilled `KEY=` line in `.env` produces. A
        missing variable is already a pydantic error; this covers the line that
        is present and empty.
        """
        blank = [
            name
            for name, value in (
                ("PGDATABASE", self.pgdatabase),
                ("PGUSER", self.pguser),
                ("PGPASSWORD", self.pgpassword),
            )
            if not value.strip()
        ]
        if blank:
            raise ValueError(
                f"{', '.join(blank)} must be set and non-blank. "
                "Generate a password with: openssl rand -hex 16"
            )
        return self


class Settings(DatabaseSettings):
    """Everything else: the collector, SNMP, OpenStack, the API and auth."""

    # ---- Collector ----------------------------------------------------------
    collector_enabled: bool = True
    collector_interval_seconds: float = 5.0
    # Bounds SNMP calls, not database connections: a tick issues two or three
    # queries either way.
    collector_concurrency: int = 32
    # Ceiling on one machine's sample; 0 derives it from the interval.
    collector_sample_timeout_seconds: float = 0.0

    # ---- SNMP ---------------------------------------------------------------
    # Seeds the `default-v2c` profile once, on the first boot that finds none.
    # There is no fallback community string after that.
    snmp_community: str = "public"
    snmp_port: int = 161
    # Worst case per machine is timeout * (retries + 1) = 3.0s.
    snmp_timeout_seconds: float = 1.5
    snmp_retries: int = 1
    # Rows per GETBULK reply. Low on purpose: a reply past the path MTU
    # fragments, and one lost fragment times the whole walk out.
    snmp_max_repetitions: int = 10
    # ~6 extra walks per machine; needs an snmpd exposing 1.3.6.1.4.1.2021.13.15.
    snmp_diskio_enabled: bool = True

    # ---- SNMP credential encryption -----------------------------------------
    # A key ring, `{"k1": "<64 hex chars>", ...}`: every row records the id it
    # was sealed with, so rotation is rolling. Required — without it nothing
    # decrypts and every v3 machine fails every tick.
    snmp_credential_keys: SecretStr
    snmp_credential_active_key: str

    # ---- Metric retention ----------------------------------------------------
    # TimescaleDB background jobs from `app.db.policies`; 0 disables one. The
    # raw window is short by design — older reads come from the rollups. A chunk
    # compresses only once its *end* is `compress_after` old, so these three
    # figures are tied to each other.
    metrics_compress_after_hours: float = 8.0
    metrics_retention_days: float = 3.0
    # New chunks only; existing ones keep their interval and age out.
    metrics_chunk_interval_hours: float = 4.0

    # ---- Metric rollups -------------------------------------------------------
    # Raise these, not `metrics_retention_days`, if long-range history is missing.
    metrics_rollup_1m_retention_days: float = 90.0
    metrics_rollup_1h_retention_days: float = 730.0
    # Must stay shorter than `metrics_retention_days` or rollups develop holes.
    metrics_rollup_refresh_lag_days: float = 2.0

    # ---- Metric entity classification -----------------------------------------
    # Comma separated prefixes, case sensitive. hrStorageTable gives tmpfs the
    # same type as a real disk, so the path is the only signal. Excluded from
    # `disk_max_used_pct` only; `/tmp` is absent because it is often real.
    metrics_pseudo_mount_prefixes: str = (
        "/run,/dev/shm,/sys,/proc,/snap,/var/lib/docker/overlay2,/var/lib/kubelet/pods"
    )
    # Excluded from host network totals: a veth's traffic also crosses a real
    # NIC, so counting both counts it twice. Still listed per interface live.
    metrics_virtual_iface_prefixes: str = (
        "veth,cni,flannel,docker,br-,virbr,kube-ipvs,tunl,gre,sit,ip6tnl,"
        "tailscale,wg,weave,cali,nomad"
    )

    @property
    def pseudo_mount_prefixes(self) -> tuple[str, ...]:
        return _csv_tuple(self.metrics_pseudo_mount_prefixes)

    @property
    def virtual_iface_prefixes(self) -> tuple[str, ...]:
        return _csv_tuple(self.metrics_virtual_iface_prefixes)

    # ---- OpenStack ----------------------------------------------------------
    # Read-only: Nova servers plus Keystone names, first fixed IPv4/MAC pair
    # per server. False: no Keystone call, empty fleet, `OS_*` unread, and
    # machines are registered with an explicit `mac` as external.
    openstack_enabled: bool = True
    openstack_cache_ttl_seconds: float = 300.0
    openstack_api_timeout_seconds: float = Field(default=10.0, gt=0)
    # All required while OPENSTACK_ENABLED is true, checked below so a blank
    # line fails like a missing one. OS_USER_ID is what goes on the wire.
    os_auth_url: str = ""
    os_username: str = ""
    os_user_id: str = ""
    os_password: SecretStr = SecretStr("")
    os_project_id: str = ""
    os_user_domain_id: str = ""
    os_region_name: str = ""
    # Empty leaves the choice to the service catalog's own default.
    os_interface: str = Field(default="", pattern="^(|public|internal|admin)$")
    os_cacert: str = ""

    # ---- Auth ---------------------------------------------------------------
    # No default and no fallback: a generated secret would differ per process
    # and rotate on restart, logging everyone out. `openssl rand -hex 32`.
    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "snmp-metrics-api"
    # Short, because an access token cannot be revoked — see services/auth.py.
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 1_209_600
    password_min_length: int = 12
    # EventSource cannot send Authorization, so a stream opens on a single-use
    # ticket; short enough that one left in an access log is already useless.
    stream_ticket_ttl_seconds: float = 30.0
    # How long a process trusts its cached users.session_epoch. Not how long a
    # revoked session survives: a disagreeing token is always re-read.
    session_epoch_cache_ttl_seconds: float = 10.0

    # ---- Login rate limiting -------------------------------------------------
    # Counted per username and per client address; either limit blocks the rest
    # of the window. Both are needed — see app/services/ratelimit.py.
    login_rate_limit_enabled: bool = True
    login_rate_limit_window_seconds: float = Field(default=300.0, gt=0)
    login_rate_limit_max_per_user: int = Field(default=5, ge=0)
    login_rate_limit_max_per_ip: int = Field(default=20, ge=0)

    # ---- Admin bootstrap ----------------------------------------------------
    # Both required: a backend that cannot create an admin must not start.
    admin_username: str
    admin_password: SecretStr
    # One-shot recovery, off by default so an API password change is not
    # reverted on every restart.
    admin_password_reset: bool = False

    # ---- API ----------------------------------------------------------------
    # Restores a prefix stripped by a reverse proxy in URLs FastAPI generates.
    root_path: str = ""
    # Matched exactly on scheme, host and port. `*` is honoured but poor here:
    # responses carry credentials, so the caller's origin is echoed back.
    cors_allow_origins: str = "http://localhost:8080"
    sse_heartbeat_seconds: float = 15.0
    sse_queue_maxsize: int = 100
    log_level: str = Field(default="INFO", pattern="(?i)^(debug|info|warning|error|critical)$")

    @property
    def allowed_origins(self) -> list[str]:
        """`CORS_ALLOW_ORIGINS` as the list CORSMiddleware wants."""
        return list(_csv_tuple(self.cors_allow_origins))

    @model_validator(mode="after")
    def _required_secrets_are_not_blank(self) -> "Settings":
        """Reject blank required values, which typing alone cannot.

        A required `str` field is satisfied by an empty string, and an empty
        string is exactly what an unfilled `KEY=` line in `.env` produces.
        Without this, `ADMIN_PASSWORD=` starts the backend with an admin
        account whose password is "", and `OS_PASSWORD=` starts one whose fleet
        lookup fails on its first call rather than at startup.
        """
        blank = [
            name
            for name, value in (
                ("JWT_SECRET", self.jwt_secret.get_secret_value()),
                ("ADMIN_USERNAME", self.admin_username),
                ("ADMIN_PASSWORD", self.admin_password.get_secret_value()),
                (
                    "SNMP_CREDENTIAL_KEYS",
                    self.snmp_credential_keys.get_secret_value(),
                ),
                ("SNMP_CREDENTIAL_ACTIVE_KEY", self.snmp_credential_active_key),
            )
            if not value.strip()
        ]
        if self.openstack_enabled:
            blank += [
                name
                for name, value in (
                    ("OS_AUTH_URL", self.os_auth_url),
                    ("OS_USERNAME", self.os_username),
                    ("OS_USER_ID", self.os_user_id),
                    ("OS_PASSWORD", self.os_password.get_secret_value()),
                    ("OS_USER_DOMAIN_ID", self.os_user_domain_id),
                    ("OS_PROJECT_ID", self.os_project_id),
                )
                if not value.strip()
            ]
        if blank:
            hints = []
            if "JWT_SECRET" in blank:
                hints.append("Generate a signing key with: openssl rand -hex 32")
            if "SNMP_CREDENTIAL_KEYS" in blank:
                hints.append(
                    'Generate a credential key with: openssl rand -hex 32, then '
                    'set {"k1": "<that>"} and SNMP_CREDENTIAL_ACTIVE_KEY=k1'
                )
            if any(name.startswith("OS_") for name in blank):
                hints.append(
                    "Copy the OS_* values from your OpenStack dashboard's API "
                    "Access tab, or set OPENSTACK_ENABLED=false to run without "
                    "OpenStack."
                )
            hint = (" " + " ".join(hints)) if hints else ""
            raise ValueError(
                f"{', '.join(blank)} must be set and non-blank.{hint}"
            )
        if len(self.jwt_secret.get_secret_value()) < 32:
            raise ValueError(
                "JWT_SECRET must be at least 32 characters; "
                "generate one with: openssl rand -hex 32"
            )
        return self

    @model_validator(mode="after")
    def _credential_key_ring_is_usable(self) -> "Settings":
        """Refuse to start without a usable key ring.

        Without it every v3 machine fails every tick, and a monitoring backend
        that reports itself healthy while collecting nothing is worse than one
        that will not boot. The ring being present is checked above; this is
        about it being *parseable* and naming the active key.
        """
        ring = parse_key_ring(self.snmp_credential_keys.get_secret_value())
        if not ring:
            raise ValueError(
                'SNMP_CREDENTIAL_KEYS must be a non-empty key ring, e.g. {"k1": '
                '"<64 hex chars>"}. Generate a key with: openssl rand -hex 32'
            )
        if self.snmp_credential_active_key not in ring:
            raise ValueError(
                f"SNMP_CREDENTIAL_ACTIVE_KEY={self.snmp_credential_active_key!r} is "
                f"not in SNMP_CREDENTIAL_KEYS ({', '.join(sorted(ring))})"
            )
        return self

    @property
    def credential_key_ring(self) -> dict[str, bytes]:
        return parse_key_ring(self.snmp_credential_keys.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_database_settings() -> DatabaseSettings:
    """For Alembic and the standalone migrator, which need nothing else."""
    return DatabaseSettings()
