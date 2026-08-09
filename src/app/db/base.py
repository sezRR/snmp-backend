"""The declarative base and the one `MetaData` Alembic diffs against.

Kept apart from `tables` so that `env.py` and the table definitions can both
import it without a cycle.

The naming convention is not cosmetic. Postgres invents names for unnamed
constraints and indexes, and those names differ between a database built by
`CREATE TABLE` and one built by a migration. Alembic then cannot emit a stable
`drop_constraint`, and autogenerate produces churn on every run. Fixing the
names here makes the diff empty when nothing changed, which is the property the
whole migration workflow rests on.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
