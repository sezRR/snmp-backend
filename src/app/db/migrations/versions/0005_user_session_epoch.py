"""Per-user session epoch, so a password change can end other sessions at once

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-20

Refresh tokens were already revoked by anything that ends a session, but an
access token is stateless and lives for its full TTL — fifteen minutes in which
a session the user just ended can still read and write everything the account
can. This column closes that: every access token carries the epoch it was
minted under, and the auth dependency refuses one that no longer matches.

Defaulting to 0 rather than to a timestamp is what makes this deployable
without an outage: tokens minted before the column existed carry no epoch, are
read as 0, and go on working until they expire.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "session_epoch", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "session_epoch")
