"""Auth: users, roles, role scopes, grants and refresh tokens.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-09

Five tables, and the shape of them encodes a few decisions worth restating:

* **No `scopes` table.** The scope set is fixed in code
  (`app.security.scopes.Scope`) and only ever changes with a deployment, so a
  catalogue table would be a second source of truth that could disagree with the
  first. `role_scopes.scope` is validated against the enum on write.
* **`role_scopes` is a row per grant**, not an array column on `roles`. Roles are
  user-editable through the API, so the grants want to be individually
  constrained and queryable ("which roles can purge metrics?").
* **`user_roles.role_id` is RESTRICT**, unlike every other foreign key here.
  Deleting a role that is still assigned should be a 409 the caller has to think
  about, not a silent mass-revocation.
* **`users` has no unique constraint on `username`** — it has a unique index on
  `lower(username)` instead, so `Admin` and `admin` cannot both exist while the
  original casing survives for display. A functional index rather than `citext`,
  which would need an extension.
* **`refresh_tokens.replaced_by`** chains each rotation to its successor. That
  chain is what makes replay detectable: a token presented after it has already
  been replaced has leaked, and the whole chain can be revoked at once.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "is_system", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )

    op.create_table(
        "users",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(
        "users_username_lower_key",
        "users",
        [sa.literal_column("lower(username)")],
        unique=True,
    )

    op.create_table(
        "role_scopes",
        sa.Column("role_id", sa.UUID(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_scopes_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "scope", name=op.f("pk_role_scopes")),
    )
    op.create_index("ix_role_scopes_scope", "role_scopes", ["scope"], unique=False)

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("role_id", sa.UUID(), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_user_roles_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_roles_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name=op.f("pk_user_roles")),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("jti", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by", sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(
            ["replaced_by"],
            ["refresh_tokens.jti"],
            name=op.f("fk_refresh_tokens_replaced_by_refresh_tokens"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("jti", name=op.f("pk_refresh_tokens")),
    )
    # Partial: revoked and expired rows are dead weight for the only lookup that
    # matters, which is "this user's live sessions".
    op.create_index(
        "ix_refresh_tokens_active",
        "refresh_tokens",
        ["user_id"],
        unique=False,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_refresh_tokens_active",
        table_name="refresh_tokens",
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.drop_table("refresh_tokens")
    op.drop_table("user_roles")
    op.drop_index("ix_role_scopes_scope", table_name="role_scopes")
    op.drop_table("role_scopes")
    op.drop_index("users_username_lower_key", table_name="users")
    op.drop_table("users")
    op.drop_table("roles")
