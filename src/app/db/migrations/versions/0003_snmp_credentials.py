"""SNMP credential profiles, and the machine binding that uses them."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "snmp_credentials",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("snmp_version", sa.Text(), nullable=False),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("security_level", sa.Text(), nullable=True),
        sa.Column("auth_protocol", sa.Text(), nullable=True),
        sa.Column("priv_protocol", sa.Text(), nullable=True),
        # nonce ‖ AES-256-GCM ciphertext. Never a passphrase.
        sa.Column("secret", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column(
            "secret_version", sa.Integer(), server_default=sa.text("1"), nullable=False
        ),
        sa.Column("fingerprint", sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_snmp_credentials")),
        sa.UniqueConstraint("name", name="uq_snmp_credentials_name"),
        sa.CheckConstraint(
            "snmp_version IN ('2c', '3')", name="ck_snmp_credentials_version"
        ),
        sa.CheckConstraint(
            "security_level IS NULL OR security_level IN "
            "('noAuthNoPriv', 'authNoPriv', 'authPriv')",
            name="ck_snmp_credentials_security_level",
        ),
        sa.CheckConstraint(
            "auth_protocol IS NULL OR auth_protocol IN "
            "('MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512')",
            name="ck_snmp_credentials_auth_protocol",
        ),
        sa.CheckConstraint(
            "priv_protocol IS NULL OR priv_protocol IN "
            "('DES', '3DES', 'AES128', 'AES192', 'AES256')",
            name="ck_snmp_credentials_priv_protocol",
        ),
        sa.CheckConstraint(
            "(snmp_version = '2c' AND username IS NULL AND security_level IS NULL) "
            "OR (snmp_version = '3' AND username IS NOT NULL "
            "AND security_level IS NOT NULL)",
            name="ck_snmp_credentials_version_shape",
        ),
        sa.CheckConstraint(
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

    op.add_column("machines", sa.Column("credential_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_machines_credential_id_snmp_credentials",
        "machines",
        "snmp_credentials",
        ["credential_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_machines_credential_id", "machines", ["credential_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_machines_credential_id", table_name="machines")
    op.drop_constraint(
        "fk_machines_credential_id_snmp_credentials", "machines", type_="foreignkey"
    )
    op.drop_column("machines", "credential_id")
    op.drop_table("snmp_credentials")
