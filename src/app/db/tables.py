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
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
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


class Machine(Base):
    """A polled host. `mac` is the identity; OpenStack owns it for managed hosts."""

    __tablename__ = "machines"
    __table_args__ = (
        PrimaryKeyConstraint("mac", name="machines_pkey"),
        # An index rather than a UNIQUE constraint, because that is what
        # schema.sql created and what deployed databases already have.
        Index("machines_ipv4_key", "ipv4", unique=True),
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# The hypertable. Its chunk interval, compression settings and the two indexes
# below are TimescaleDB features that autogenerate cannot see; revision 0001
# installs them with op.execute and nothing here reflects them.
metrics = Table(
    "metrics",
    Base.metadata,
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("mac", MACADDR, nullable=False),
    Column("metrics", JSONB, nullable=False),
    ForeignKeyConstraint(
        ["mac"], ["machines.mac"], ondelete="CASCADE", name="metrics_mac_fkey"
    ),
    # Not declared in schema.sql and not created by any migration: this is the
    # index create_hypertable() builds for itself on the partitioning column.
    # It is declared here anyway, because a table Alembic can see but an index it
    # cannot means every autogenerate run proposes dropping it.
    Index("metrics_ts_idx", text("ts DESC")),
    Index("metrics_mac_ts_idx", "mac", text("ts DESC")),
    Index(
        "metrics_gin_idx",
        "metrics",
        postgresql_using="gin",
        postgresql_ops={"metrics": "jsonb_path_ops"},
    ),
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
