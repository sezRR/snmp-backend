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

import json
from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# AES-256, so nothing shorter is a key. Enforced rather than padded or hashed
# into shape: a 16-byte value in this variable is a mistake, not a request for
# AES-128, and silently accepting it would hide the mistake forever.
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
    # The seed for the built-in `default-v2c` credential profile, and nothing
    # else. Since credentials became rows, the sampler has no fallback path to
    # this value: `app.services.bootstrap` copies it into a profile once, on the
    # first boot that finds none, and never reads it again. Removable a release
    # after every deployment has been through that boot.
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

    # ---- SNMP credential encryption -----------------------------------------
    # A key *ring*, not a key: `{"k1": "<64 hex chars>", ...}`, with
    # SNMP_CREDENTIAL_ACTIVE_KEY naming the one new writes use. Every row
    # records the id it was encrypted under, so old keys stay in the ring until
    # `python -m app.db.reencrypt` has moved every row onto the new one. That is
    # what makes rotation a rolling operation rather than a re-entry of every
    # passphrase.
    #
    # Unlike JWT_SECRET these have defaults, because the simulated sampler never
    # decrypts anything and a developer running SNMP_SIMULATE=true should not
    # need to generate a key. The validator below demands them as soon as the
    # deployment polls real agents.
    snmp_credential_keys: SecretStr = SecretStr("")
    snmp_credential_active_key: str = ""

    # ---- Metric retention ----------------------------------------------------
    # Applied as TimescaleDB background jobs by `app.db.policies`. Either at 0
    # disables that policy and leaves the data alone. Compression works on
    # batches of up to a thousand rows, so the ratio it achieves depends on how
    # full a chunk is — a busy day compresses far better than a quiet one.
    metrics_compress_after_hours: float = 24.0
    metrics_retention_days: float = 30.0

    # ---- OpenStack ----------------------------------------------------------
    # The real lookup is read-only: it lists Nova servers across projects and
    # uses Keystone solely to resolve the project/user names already present in
    # the API contract. Nova's address entry under this network supplies the
    # one fixed IPv4/MAC pair the collector needs.
    openstack_simulate: bool = True
    openstack_cache_ttl_seconds: float = 300.0
    openstack_network_name: str = ""
    openstack_api_timeout_seconds: float = Field(default=10.0, gt=0)
    os_auth_url: str = ""
    os_application_credential_id: str = ""
    os_application_credential_secret: SecretStr = SecretStr("")
    os_region_name: str = ""
    os_interface: str = Field(
        default="public", pattern="^(public|internal|admin)$"
    )
    os_cacert: str = ""

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

    @model_validator(mode="after")
    def _real_openstack_configuration_is_complete(self) -> "Settings":
        if self.openstack_simulate:
            return self
        blank = [
            name
            for name, value in (
                ("OS_AUTH_URL", self.os_auth_url),
                ("OS_APPLICATION_CREDENTIAL_ID", self.os_application_credential_id),
                (
                    "OS_APPLICATION_CREDENTIAL_SECRET",
                    self.os_application_credential_secret.get_secret_value(),
                ),
                ("OPENSTACK_NETWORK_NAME", self.openstack_network_name),
            )
            if not value.strip()
        ]
        if blank:
            raise ValueError(
                f"{', '.join(blank)} must be set and non-blank when "
                "OPENSTACK_SIMULATE=false"
            )
        return self

    @model_validator(mode="after")
    def _credential_key_ring_is_usable(self) -> "Settings":
        """Refuse to start without a usable key ring, once SNMP is real.

        Gated on `snmp_simulate` because the simulated sampler never decrypts a
        credential, so demanding a key from a developer running the default
        stack would be ceremony. The moment the deployment polls real agents the
        key becomes load-bearing: without it every v3 machine fails every tick,
        and a monitoring backend that reports itself healthy while collecting
        nothing is worse than one that will not boot.
        """
        if self.snmp_simulate:
            # Still reject a *malformed* ring even here — a typo should surface
            # on the developer's machine, not on the first real deployment.
            parse_key_ring(self.snmp_credential_keys.get_secret_value())
            return self

        ring = parse_key_ring(self.snmp_credential_keys.get_secret_value())
        if not ring:
            raise ValueError(
                "SNMP_CREDENTIAL_KEYS must be set when SNMP_SIMULATE=false. "
                'Generate one with: openssl rand -hex 32, then set {"k1": "<that>"} '
                "and SNMP_CREDENTIAL_ACTIVE_KEY=k1"
            )
        if not self.snmp_credential_active_key.strip():
            raise ValueError(
                "SNMP_CREDENTIAL_ACTIVE_KEY must name one of the ids in "
                f"SNMP_CREDENTIAL_KEYS ({', '.join(sorted(ring))})"
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
