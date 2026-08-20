"""Every table in the database, as SQLAlchemy sees it.

This module is the schema's single source of truth: Alembic autogenerate diffs
the live database against `Base.metadata`, so a table that is not declared here
does not exist as far as migrations are concerned.

Two conventions worth knowing before editing:

* **`metrics` is a Core `Table`, not a declarative class.** It is a TimescaleDB
  hypertable and deliberately has no primary key, which the ORM requires. It is
  also queried entirely through hand-written SQL in `app.db.metrics`, so a
  mapped class would buy nothing.
* **The pre-existing constraints and indexes are named explicitly**, matching
  what Postgres generated for the databases built by the old `schema.sql`
  (`machines_pkey`, `metrics_mac_fkey`, ...). Letting the naming convention
  rename them would make autogenerate emit a drop/recreate against every
  already-deployed database. New tables use the convention.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    SmallInteger,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import (
    DOUBLE_PRECISION,
    INET,
    MACADDR,
    REAL,
    UUID,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _now() -> datetime:
    """Python-side `onupdate` for the identity tables.

    Deliberately not `func.now()`. A server-side default is a SQL expression
    SQLAlchemy cannot evaluate, so it expires the attribute on flush and reloads
    it on next access — which raises `DetachedInstanceError` the moment a
    repository returns the object to a handler that reads `updated_at` after the
    session has closed. Computing it here keeps the value in hand.

    The fleet tables keep the database's clock, because their SQL sets
    `updated_at = now()` directly. Both clocks are the same host in every
    deployment this ships with.
    """
    return datetime.now(UTC)

# --- Fleet -------------------------------------------------------------------


class SnmpCredential(Base):
    """How to authenticate to an agent. Shared by every machine bound to it.

    Reusable on purpose: a fleet is usually polled with one or two credentials,
    and re-entering a passphrase per host means it is never rotated. The cost is
    blast radius, which the API answers by gating binding on its own scope — see
    `app.api.routers.credentials`.

    **`secret` is ciphertext**, never a passphrase. It holds
    `nonce ‖ AES-256-GCM(json)` over `{"community": …}` for v2c or
    `{"auth": …, "priv": …}` for v3, sealed against `key_id` and
    `secret_version`; `app.security.crypto` is the only module that opens it.
    `fingerprint` exists so a client can distinguish two profiles without the API
    ever handing back what is inside.

    Two "version" concepts live here and are deliberately not both called that:
    `snmp_version` is the protocol, `secret_version` is a counter bumped on every
    change to the secret. The second is what invalidates the sampler's decrypted
    cache and its per-credential engine, so it must change even when nothing
    else about the row does.
    """

    __tablename__ = "snmp_credentials"
    __table_args__ = (
        UniqueConstraint("name", name="uq_snmp_credentials_name"),
        CheckConstraint("snmp_version IN ('2c', '3')", name="ck_snmp_credentials_version"),
        CheckConstraint(
            "security_level IS NULL OR security_level IN "
            "('noAuthNoPriv', 'authNoPriv', 'authPriv')",
            name="ck_snmp_credentials_security_level",
        ),
        CheckConstraint(
            "auth_protocol IS NULL OR auth_protocol IN "
            "('MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512')",
            name="ck_snmp_credentials_auth_protocol",
        ),
        CheckConstraint(
            "priv_protocol IS NULL OR priv_protocol IN "
            "('DES', '3DES', 'AES128', 'AES192', 'AES256')",
            name="ck_snmp_credentials_priv_protocol",
        ),
        # A v2c row carries no USM fields; a v3 row must name its user and level.
        # The API validates this too, but the constraint is what makes a
        # hand-edited row unable to reach the sampler as something half-formed.
        CheckConstraint(
            "(snmp_version = '2c' AND username IS NULL AND security_level IS NULL) "
            "OR (snmp_version = '3' AND username IS NOT NULL "
            "AND security_level IS NOT NULL)",
            name="ck_snmp_credentials_version_shape",
        ),
        # The protocol columns are present exactly when the security level says
        # they must be — the pairing USM itself requires.
        CheckConstraint(
            "(security_level IS NULL AND auth_protocol IS NULL "
            "AND priv_protocol IS NULL) "
            "OR (security_level = 'noAuthNoPriv' AND auth_protocol IS NULL "
            "AND priv_protocol IS NULL) "
            "OR (security_level = 'authNoPriv' AND auth_protocol IS NOT NULL "
            "AND priv_protocol IS NULL) "
            "OR (security_level = 'authPriv' AND auth_protocol IS NOT NULL "
            "AND priv_protocol IS NOT NULL)",
            name="ck_snmp_credentials_level_protocols",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    snmp_version: Mapped[str] = mapped_column(Text, nullable=False)
    # The v3 securityName. Null for v2c, whose identity is the community string
    # and therefore lives inside the ciphertext.
    username: Mapped[str | None] = mapped_column(Text)
    security_level: Mapped[str | None] = mapped_column(Text)
    auth_protocol: Mapped[str | None] = mapped_column(Text)
    priv_protocol: Mapped[str | None] = mapped_column(Text)
    secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    secret_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("1")
    )
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Machine(Base):
    """A polled host. `mac` is the identity; OpenStack owns it for managed hosts."""

    __tablename__ = "machines"
    __table_args__ = (
        PrimaryKeyConstraint("mac", name="machines_pkey"),
        # An index rather than a UNIQUE constraint, because that is what
        # schema.sql created and what deployed databases already have.
        Index("machines_ipv4_key", "ipv4", unique=True),
        Index("ix_machines_credential_id", "credential_id"),
    )

    mac: Mapped[str] = mapped_column(MACADDR)
    ipv4: Mapped[str] = mapped_column(INET, nullable=False)
    label: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    external: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    # Nullable, and an unbound machine is simply not polled — the collector says
    # so per machine in /admin/collector rather than failing quietly. RESTRICT
    # for the same reason `user_roles.role_id` uses it: deleting a credential
    # that is still in use should be a 409 someone has to think about, not a
    # silent mass-unbind that stops the fleet being sampled.
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "snmp_credentials.id",
            ondelete="RESTRICT",
            name="fk_machines_credential_id_snmp_credentials",
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# The hypertable. Its chunk interval, compression settings, the continuous
# aggregates built on top of it and the index below are TimescaleDB features
# that autogenerate cannot see; revisions 0001 and 0004 install them with
# op.execute and nothing here reflects them.
#
# Every metric column is nullable, and that is load-bearing rather than lax. A
# machine whose IF-MIB walk failed has no network reading at all, a machine
# whose agent serves no DISKIO-MIB has no disk I/O, and every rate is unknown on
# the first sample after a restart because a rate needs two counter readings.
# NULL is the honest answer in each case, and aggregates skip it for free.
metrics = Table(
    "metrics",
    Base.metadata,
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("mac", MACADDR, nullable=False),
    # --- cpu ---
    Column("cpu_usage_pct", REAL),
    Column("cpu_cores", SmallInteger),
    # --- ram ---
    Column("ram_total_bytes", BigInteger),
    Column("ram_used_bytes", BigInteger),
    Column("ram_used_pct", REAL),
    Column("ram_available_bytes", BigInteger),
    # --- disk ---
    # The root filesystem, plus the fullest real filesystem. Submounts are not
    # stored: they are mostly tmpfs, they do not roll up into root, and their
    # names churn. They still reach the UI live over SSE.
    Column("disk_root_total_bytes", BigInteger),
    Column("disk_root_used_bytes", BigInteger),
    Column("disk_root_used_pct", REAL),
    Column("disk_max_used_pct", REAL),
    # --- disk i/o, summed over the devices that count toward the host total ---
    Column("dio_read_bps", DOUBLE_PRECISION),
    Column("dio_write_bps", DOUBLE_PRECISION),
    Column("dio_read_iops", REAL),
    Column("dio_write_iops", REAL),
    Column("dio_read_bytes", BigInteger),
    Column("dio_write_bytes", BigInteger),
    Column("dio_reads", BigInteger),
    Column("dio_writes", BigInteger),
    Column("dio_busy_pct", REAL),
    # --- network, summed over physical interfaces only ---
    Column("net_rx_bps", DOUBLE_PRECISION),
    Column("net_tx_bps", DOUBLE_PRECISION),
    Column("net_rx_bytes", BigInteger),
    Column("net_tx_bytes", BigInteger),
    Column("net_rx_util_pct", REAL),
    Column("net_tx_util_pct", REAL),
    # Bits per second, unlike every other *_bps column here, which are bytes per
    # second. That is IF-MIB's unit for ifHighSpeed and renaming it would hide
    # where the number comes from.
    Column("net_speed_bps", BigInteger),
    # Seconds between this sample and the previous one for this machine, which
    # is what every rate above was derived over.
    Column("interval_ms", Integer),
    ForeignKeyConstraint(
        ["mac"], ["machines.mac"], ondelete="CASCADE", name="metrics_mac_fkey"
    ),
    # Not declared in schema.sql and not created by any migration: this is the
    # index create_hypertable() builds for itself on the partitioning column.
    # It is declared here anyway, because a table Alembic can see but an index it
    # cannot means every autogenerate run proposes dropping it.
    Index("metrics_ts_idx", text("ts DESC")),
    Index("metrics_mac_ts_idx", "mac", text("ts DESC")),
)


# --- Identity ----------------------------------------------------------------


class User(Base):
    """An API account.

    Usernames are compared case-insensitively through a functional unique index
    on `lower(username)` rather than a `citext` column: no extension to install,
    and the original casing survives for display.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("users_username_lower_key", text("lower(username)"), unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    username: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    # Bumped by anything that ends this account's sessions. Every access token
    # carries the value it was minted under, and one that no longer matches is
    # refused — which is how a password change reaches the sessions it cannot
    # revoke, access tokens being stateless. See app.services.sessions.
    session_epoch: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_now
    )

    roles: Mapped[list[Role]] = relationship(
        secondary="user_roles", back_populates="users", lazy="selectin"
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def scopes(self) -> frozenset[str]:
        """Everything this user may do: the union of their roles' scopes."""
        return frozenset().union(*(role.scope_set for role in self.roles), frozenset())


class Role(Base):
    """A named bundle of scopes. Created and edited through the API."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("name", name="uq_roles_name"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Set on the built-in admin role. Guards it against deletion and against
    # having its scopes edited away, which is the one change nobody can undo.
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_now
    )

    scopes: Mapped[list[RoleScope]] = relationship(
        back_populates="role", cascade="all, delete-orphan", lazy="selectin"
    )
    users: Mapped[list[User]] = relationship(
        secondary="user_roles", back_populates="roles"
    )

    @property
    def scope_set(self) -> frozenset[str]:
        return frozenset(rs.scope for rs in self.scopes)


class RoleScope(Base):
    """One scope granted to one role.

    A row per scope rather than an array column: roles are user-editable, so the
    grants want to be queryable and individually constrained. The scope strings
    themselves are validated against `app.security.scopes.Scope` on write — the
    set is fixed in code and has no catalogue table.
    """

    __tablename__ = "role_scopes"
    __table_args__ = (Index("ix_role_scopes_scope", "scope"),)

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scope: Mapped[str] = mapped_column(Text, primary_key=True)

    role: Mapped[Role] = relationship(back_populates="scopes")


class UserRole(Base):
    """Grant of a role to a user.

    `role_id` is RESTRICT, not CASCADE: deleting a role that is still assigned
    should be a 409 the caller has to think about, not a silent mass-revocation.
    """

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RefreshToken(Base):
    """A refresh token's server-side record, keyed by its `jti`.

    Access tokens are stateless and short-lived; refresh tokens are not, so they
    need somewhere to be revoked. `replaced_by` chains each rotation to the next,
    which is what makes replay detectable: presenting a token that has already
    been replaced means it leaked, and the whole chain is revoked.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index(
            "ix_refresh_tokens_active",
            "user_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    jti: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("refresh_tokens.jti", ondelete="SET NULL")
    )

    user: Mapped[User] = relationship(back_populates="refresh_tokens")
