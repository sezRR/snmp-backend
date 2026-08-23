"""Machine-wide disk capacity, alongside the fullest-filesystem percentage"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `disk_max_used_pct` answers "is any filesystem nearly full". It was also
    # being read as "how full is this machine", which it cannot answer: a 100 MB
    # /boot/efi at 10% beside a 100 GB / at 1% is 1% of the machine's storage,
    # not 10%. These three columns carry the capacity-weighted answer.
    #
    # Nullable and not backfilled, because the input no longer exists: a stored
    # row keeps root and the maximum, never the per-mount table the sum needs.
    # Rows written before this revision therefore read as unknown rather than
    # as a number reconstructed from the wrong data.
    op.add_column("metrics", sa.Column("disk_total_bytes", sa.BigInteger()))
    op.add_column("metrics", sa.Column("disk_used_bytes", sa.BigInteger()))
    op.add_column("metrics", sa.Column("disk_used_pct", sa.REAL()))


def downgrade() -> None:
    op.drop_column("metrics", "disk_used_pct")
    op.drop_column("metrics", "disk_used_bytes")
    op.drop_column("metrics", "disk_total_bytes")
