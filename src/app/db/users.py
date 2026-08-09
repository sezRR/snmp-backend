"""User repository.

Unlike the fleet and metric repositories, these take a `Session` and are called
through `Database.run_session`. Users, roles and grants are ordinary relational
data with cascades worth having, and nothing here is hot enough to want SQL by
hand.

Each function is one transaction, which is why the *invariants live here rather
than in the routers*. "Do not remove the last admin" cannot be checked before
the mutation without a race — two requests each see two admins and each removes
one. Mutating first and counting after, inside the same transaction, makes the
check exact: whichever transaction commits second sees the other's effect and
rolls itself back.

Objects come back detached but usable: the sessionmaker sets
`expire_on_commit=False`, and `User.roles` / `Role.scopes` are `selectin`, so a
caller can read a user's scopes after the session has closed.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.tables import RefreshToken, Role, RoleScope, User, UserRole
from app.security.scopes import ADMIN_GATE_SCOPE


class LastAdminError(RuntimeError):
    """The change would leave nobody able to administer users."""


def count_admins(session: Session) -> int:
    """Active users holding the scope that can create more of them."""
    stmt = (
        select(func.count(func.distinct(User.id)))
        .join(UserRole, UserRole.user_id == User.id)
        .join(RoleScope, RoleScope.role_id == UserRole.role_id)
        .where(RoleScope.scope == ADMIN_GATE_SCOPE, User.is_active.is_(True))
    )
    return session.execute(stmt).scalar_one()


def guard_admins_remain(session: Session) -> None:
    """Call after a mutation, before returning. Rolls back by raising."""
    session.flush()
    if count_admins(session) == 0:
        raise LastAdminError(
            "that would leave no active user with the "
            f"{ADMIN_GATE_SCOPE} scope, locking everyone out"
        )


# --- Reads -------------------------------------------------------------------


def get(session: Session, user_id: uuid.UUID) -> User | None:
    return session.get(User, user_id)


def get_by_username(session: Session, username: str) -> User | None:
    """Case-insensitive, matching the unique index on `lower(username)`."""
    stmt = select(User).where(func.lower(User.username) == func.lower(username))
    return session.execute(stmt).scalar_one_or_none()


def list_all(session: Session) -> list[User]:
    return list(session.execute(select(User).order_by(User.username)).scalars())


# --- Writes ------------------------------------------------------------------


def create(
    session: Session, username: str, password_hash: str, roles: list[Role]
) -> User:
    user = User(username=username, password_hash=password_hash, is_active=True)
    user.roles = roles
    session.add(user)
    session.flush()
    return user


def set_password(session: Session, user: User, password_hash: str) -> None:
    """Changing a password ends every other session for that user.

    A password change is usually a response to a suspected compromise, and
    leaving the attacker's refresh token alive would make it pointless.
    """
    user.password_hash = password_hash
    revoke_all_tokens(session, user.id)


def set_active(session: Session, user: User, is_active: bool) -> None:
    user.is_active = is_active
    if not is_active:
        revoke_all_tokens(session, user.id)
        guard_admins_remain(session)


def set_roles(session: Session, user: User, roles: list[Role]) -> None:
    user.roles = roles
    guard_admins_remain(session)


def delete(session: Session, user: User) -> None:
    session.delete(user)
    guard_admins_remain(session)


def revoke_all_tokens(session: Session, user_id: uuid.UUID) -> int:
    """Revoke every live refresh token for a user. Returns how many."""
    result = session.execute(
        RefreshToken.__table__.update()
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=func.now())
    )
    return result.rowcount


def purge_expired_tokens(session: Session) -> int:
    """Housekeeping: rows that can no longer authorise anything."""
    result = session.execute(
        sa_delete(RefreshToken).where(RefreshToken.expires_at < func.now())
    )
    return result.rowcount
