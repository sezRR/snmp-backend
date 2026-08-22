"""Application settings.

Values are read from the process environment first and from a `.env` file
second. See `.env.example` for the full list with defaults.

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
    # Required, and deliberately without defaults. A database name, user or
    # password guessed on the deployment's behalf either reaches nothing or
    # reaches the wrong database with someone else's rows in it, and Compose
    # already refuses to start without all three. `.env.example` carries the
    # values the rest of the documentation assumes.
    pgdatabase: str
    pguser: str
    pgpassword: str
    pgsslmode: str = "prefer"

    # SQLAlchemy's pool_size is the *persistent* pool, not a floor to grow from:
    # anything past it is opened and closed per checkout. 1 would mean a single
    # kept connection and 15 churned ones, so the floor is higher than the
    # psycopg2 pool's was.
    db_pool_min: int = 5
    db_pool_max: int = 16
    db_connect_timeout_seconds: int = 5
    db_statement_timeout_ms: int = 15_000
    # Run `alembic upgrade head` on startup. Turn off to migrate separately with
    # `python -m app.db.migrate`. The old environment name remains accepted for
    # existing installations.
    db_auto_migrate: bool = Field(
        default=True, validation_alias=AliasChoices("DB_AUTO_MIGRATE", "DB_AUTO_INIT")
    )
    # How long the migration step waits out a database that is still doing
    # initdb. 30 x 2s covers a cold database comfortably.
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
    # Gates SNMP calls only, not database connections: a tick issues two or three
    # queries in total regardless of how many machines it samples, so this is
    # sized against the fleet and the interval, not against `db_pool_max`.
    collector_concurrency: int = 32
    # Wall-clock ceiling on one machine's sample, so a slow agent can never hold
    # a concurrency slot for longer than the interval. 0 derives it from the
    # interval, which is the sane default; set it explicitly to override.
    collector_sample_timeout_seconds: float = 0.0

    # ---- SNMP ---------------------------------------------------------------
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
    # Required, like JWT_SECRET. Every stored SNMPv3 passphrase is sealed with
    # one of these keys, so a backend without the ring decrypts nothing and
    # fails every v3 machine on every tick — while reporting itself healthy.
    snmp_credential_keys: SecretStr
    snmp_credential_active_key: str

    # ---- Metric retention ----------------------------------------------------
    # Applied as TimescaleDB background jobs by `app.db.policies`. Any of these
    # at 0 disables that policy and leaves the data alone. Compression works on
    # batches of up to a thousand rows, so the ratio it achieves depends on how
    # full a chunk is — a busy day compresses far better than a quiet one.
    #
    # The raw window is deliberately short: it exists for live troubleshooting,
    # and everything older is served from the two continuous aggregates. Both
    # figures below are tied to each other and to the chunk interval. A chunk is
    # only eligible for compression once its *end* is `compress_after` in the
    # past, so with day-long chunks and a 24 hour window a chunk is not
    # compressed until it is two days old — which, against a three day
    # retention, would leave two thirds of the data uncompressed. Four hour
    # chunks compressed after eight hours put roughly sixty of the seventy-two
    # retained hours in columnar form.
    metrics_compress_after_hours: float = 8.0
    metrics_retention_days: float = 3.0
    # Applied to new chunks only; existing chunks keep the interval they were
    # created with and age out.
    metrics_chunk_interval_hours: float = 4.0

    # ---- Metric rollups -------------------------------------------------------
    # Retention for the `metrics_1m` and `metrics_1h` continuous aggregates.
    # These are what make a long range chart answerable at all once the raw
    # window is three days, so they are the numbers to raise if history goes
    # missing rather than `metrics_retention_days`.
    metrics_rollup_1m_retention_days: float = 90.0
    metrics_rollup_1h_retention_days: float = 730.0
    # How far back a refresh reaches. Must stay *shorter* than
    # `metrics_retention_days`, or a refresh is asked to re-read chunks the
    # retention policy has already dropped and the rollup develops holes.
    metrics_rollup_refresh_lag_days: float = 2.0

    # ---- Metric entity classification -----------------------------------------
    # Comma separated, matched as prefixes, case sensitive.
    #
    # Mounts whose usage is not a real filesystem's usage. hrStorageTable reports
    # tmpfs under the same hrStorageFixedDisk type as a real disk, so type alone
    # cannot tell them apart and the path is the only signal available. These are
    # excluded from `disk_max_used_pct` only — every mount still reaches the UI
    # live. `/tmp` is absent on purpose: it is a real filesystem on plenty of
    # hosts, so excluding it by default would hide a genuinely full disk.
    metrics_pseudo_mount_prefixes: str = (
        "/run,/dev/shm,/sys,/proc,/snap,/var/lib/docker/overlay2,/var/lib/kubelet/pods"
    )
    # Interfaces excluded from the host network totals. A virtual interface
    # cannot move a packet off the box on its own — the traffic it carries
    # crosses a physical NIC as well — so summing both counts it twice. On a
    # Kubernetes node with one veth per pod that inflates the total severalfold.
    # They still appear per-interface in the live payload.
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
    # The lookup is read-only: it lists Nova servers across projects and uses
    # Keystone solely to resolve the project/user names already present in the
    # API contract. Every network a server is attached to is considered, and the
    # first fixed IPv4/MAC pair Nova lists is the one the collector needs.
    # False for a deployment with no OpenStack at all: no Keystone call is made,
    # the fleet is empty, and the `OS_*` credentials below are neither required
    # nor read. Machines must then be registered with an explicit `mac`, which
    # stores them as external — the collector polls the address it was given and
    # never moves it, because nothing else knows better.
    openstack_enabled: bool = True
    openstack_cache_ttl_seconds: float = 300.0
    openstack_api_timeout_seconds: float = Field(default=10.0, gt=0)
    # All required while OPENSTACK_ENABLED is true, and checked below rather
    # than by their types: a blank `OS_PASSWORD=` line has to fail the same way
    # a missing one does. Keystone password authentication — OS_USER_ID
    # identifies the user on its own and is what goes on the wire when set,
    # OS_USERNAME is that same user by name inside OS_USER_DOMAIN_ID, and
    # OS_PROJECT_ID is the scope the session is bound to.
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
    # JWT_SECRET has no default and no fallback. Generating one would be worse
    # than failing: it would differ between processes, so a token minted by one
    # would be rejected by the next, and it would rotate on every restart,
    # logging every user out. Generate one with `openssl rand -hex 32` and put it
    # in `.env`.
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
    # How long a process trusts its cached copy of users.session_epoch before
    # reading it again. This is *not* how long a revoked session survives — a
    # token whose epoch disagrees with the cache is always re-read against the
    # database — it only bounds how long a *second* process goes without
    # noticing an epoch it has never been shown. Trading it up costs
    # correctness nothing and saves a small indexed read per user per window.
    session_epoch_cache_ttl_seconds: float = 10.0

    # ---- Login rate limiting -------------------------------------------------
    # Failed /auth/login attempts are counted per username and per client
    # address; either limit reached blocks further attempts for the rest of the
    # window. Both are needed: the username counter alone would let anyone lock
    # any account out, and the address counter alone would ignore a distributed
    # attack on one account. See app/services/ratelimit.py.
    #
    # The per-user figure is sized for a human who has fat-fingered a password a
    # few times; the per-address one for an office or a NAT behind which several
    # of them are doing it at once.
    login_rate_limit_enabled: bool = True
    login_rate_limit_window_seconds: float = Field(default=300.0, gt=0)
    login_rate_limit_max_per_user: int = Field(default=5, ge=0)
    login_rate_limit_max_per_ip: int = Field(default=20, ge=0)

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
    # Restores a prefix stripped by a reverse proxy in URLs FastAPI generates.
    root_path: str = ""
    # Comma separated browser origins allowed to call this API. Matched exactly
    # — scheme, host and port all count, so http://localhost:8080 does not cover
    # https://ui.example.com or a bare hostname. The default is the compose UI
    # port; a deployment adds its own.
    #
    # `*` is honoured but is a poor idea here: responses carry credentials, so
    # Starlette echoes the caller's origin back instead of a literal `*`, which
    # makes every site on the internet an allowed origin for cookie-bearing
    # requests. Startup logs a warning if it is set.
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
