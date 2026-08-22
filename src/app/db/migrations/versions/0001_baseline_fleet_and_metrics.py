"""Baseline: machines and the metrics hypertable."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("machines"):
        # Adopting a schema.sql database: the objects already exist, so only the
        # revision needs recording.
        return

    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")

    op.create_table(
        "machines",
        sa.Column("mac", postgresql.MACADDR(), nullable=False),
        sa.Column("ipv4", postgresql.INET(), nullable=False),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("external", sa.Boolean(), server_default=sa.text("false"), nullable=False),
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
        sa.PrimaryKeyConstraint("mac", name="machines_pkey"),
    )
    op.create_index("machines_ipv4_key", "machines", ["ipv4"], unique=True)

    op.create_table(
        "metrics",
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mac", postgresql.MACADDR(), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["mac"], ["machines.mac"], name="metrics_mac_fkey", ondelete="CASCADE"
        ),
    )

    # Must precede the indexes: create_hypertable rewrites the table.
    op.execute("SELECT create_hypertable('metrics', by_range('ts'))")
    op.execute("SELECT set_chunk_time_interval('metrics', INTERVAL '1 day')")
    op.execute(
        """
        ALTER TABLE metrics SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'mac',
            timescaledb.compress_orderby   = 'ts DESC'
        )
        """
    )

    op.create_index("metrics_mac_ts_idx", "metrics", ["mac", sa.text("ts DESC")])
    op.create_index(
        "metrics_gin_idx",
        "metrics",
        ["metrics"],
        postgresql_using="gin",
        postgresql_ops={"metrics": "jsonb_path_ops"},
    )


def downgrade() -> None:
    op.drop_table("metrics")
    op.drop_table("machines")
