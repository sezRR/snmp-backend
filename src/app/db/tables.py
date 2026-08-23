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
        # v2c carries no USM fields; v3 must name its user and level. Enforced
        # here so a hand-edited row cannot reach the sampler half-formed.
        CheckConstraint(
            "(snmp_version = '2c' AND username IS NULL AND security_level IS NULL) "
            "OR (snmp_version = '3' AND username IS NOT NULL "
            "AND security_level IS NOT NULL)",
            name="ck_snmp_credentials_version_shape",
        ),
        # Protocol columns present exactly when the security level requires them.
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
    # v3 securityName; null for v2c, whose identity is inside the ciphertext.
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
        # An index, not a constraint: that is what deployed databases have.
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
    # Nullable: an unbound machine is not polled, and says so in
    # /admin/collector. RESTRICT so deleting a credential in use is a 409, not a
    # silent mass-unbind.
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


# The hypertable. Chunk interval, compression, the aggregates and the index
# below are TimescaleDB features autogenerate cannot see; 0001 and 0004 install
# them with op.execute. Every metric column is nullable on purpose: a failed
# walk has no reading, and a rate needs two counter readings.
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
    # Root, the machine's total capacity, and the fullest single filesystem.
    # Per-mount rows churn and are mostly tmpfs, so they stay live-only.
    #
    # `disk_used_pct` is used/total over every real filesystem, which is what
    # "how full is this machine" means. `disk_max_used_pct` is the fullest one,
    # which is what "is anything about to fill up" means. They answer different
    # questions and a maximum cannot stand in for the ratio: a 100 MB /boot/efi
    # at 10% beside a 100 GB / at 1% is 1% of the machine, not 10%.
    Column("disk_root_total_bytes", BigInteger),
    Column("disk_root_used_bytes", BigInteger),
    Column("disk_root_used_pct", REAL),
    Column("disk_total_bytes", BigInteger),
    Column("disk_used_bytes", BigInteger),
    Column("disk_used_pct", REAL),
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
    # Bits per second, unlike the other *_bps columns: IF-MIB's own unit.
    Column("net_speed_bps", BigInteger),
    # The span every rate above was derived over.
    Column("interval_ms", Integer),
    ForeignKeyConstraint(
        ["mac"], ["machines.mac"], ondelete="CASCADE", name="metrics_mac_fkey"
    ),
    # create_hypertable()'s own index. Declared so autogenerate stops proposing
    # to drop it.
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
    # Bumped by anything ending this account's sessions; a token minted under an
    # older value is refused. See app.services.sessions.
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
    # The built-in admin role: undeletable, and its scopes cannot be edited away.
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
