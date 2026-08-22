from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.tables import Role, RoleScope, UserRole
from app.db.users import guard_admins_remain


class SystemRoleError(RuntimeError):
    """The built-in admin role cannot be deleted or have its scopes edited."""


class RoleInUseError(RuntimeError):
    """The role is still granted to somebody."""


def get_by_name(session: Session, name: str) -> Role | None:
    return session.execute(select(Role).where(Role.name == name)).scalar_one_or_none()


def get(session: Session, role_id: uuid.UUID) -> Role | None:
    return session.get(Role, role_id)


def list_all(session: Session) -> list[Role]:
    return list(session.execute(select(Role).order_by(Role.name)).scalars())


def resolve(session: Session, names: list[str]) -> tuple[list[Role], list[str]]:
    """Look up roles by name. Returns (found, missing)."""
    if not names:
        return [], []
    found = list(
        session.execute(select(Role).where(Role.name.in_(names))).scalars()
    )
    known = {role.name for role in found}
    return found, [name for name in names if name not in known]


def create(
    session: Session, name: str, description: str | None, scopes: list[str]
) -> Role:
    role = Role(name=name, description=description, is_system=False)
    role.scopes = [RoleScope(scope=s) for s in sorted(set(scopes))]
    session.add(role)
    session.flush()
    return role


def set_description(session: Session, role: Role, description: str | None) -> None:
    role.description = description


def set_scopes(session: Session, role: Role, scopes: list[str]) -> None:
    """Replace a role's scopes wholesale.

    Refused on a system role: the admin role losing `users:write` is the one
    edit with no way back, and the bootstrap reconciler would silently undo it
    on the next restart anyway.
    """
    if role.is_system:
        raise SystemRoleError(f"the {role.name} role's scopes are fixed")
    role.scopes = [RoleScope(scope=s) for s in sorted(set(scopes))]
    # Editing a role can strip the admin scope from everyone holding it.
    guard_admins_remain(session)


def assignment_count(session: Session, role: Role) -> int:
    return session.execute(
        select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id)
    ).scalar_one()


def delete(session: Session, role: Role) -> None:
    """Refuses on a system role, and on one that is still granted.

    `user_roles.role_id` is ON DELETE RESTRICT, so the database would refuse the
    second case too — but as an IntegrityError at commit, well after the handler
    could say anything useful about it.
    """
    if role.is_system:
        raise SystemRoleError(f"the {role.name} role is built in and cannot be deleted")
    if assignment_count(session, role) > 0:
        raise RoleInUseError(f"the {role.name} role is still assigned to a user")
    session.delete(role)
