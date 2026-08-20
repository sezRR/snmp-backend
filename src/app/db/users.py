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
from sqlalchemy.orm.attributes import set_committed_value

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
    leaving the attacker's credentials alive would make it pointless. Both
    halves of a session go: the refresh token is revoked, and the epoch bump
    refuses the access tokens, which are stateless and cannot be revoked.

    The session that made the change is *not* ended — the caller mints a fresh
    pair afterwards, under the new epoch.

    Keyed on `user.id` rather than by assigning to the instance: callers may
    hold a `User` loaded by an earlier `run_session`, and assigning to a
    detached instance updates nothing. The instance is refreshed too, so a
    caller that goes on to read it sees the new hash and epoch either way.
    """
    store_password_hash(session, user, password_hash)
    end_sessions(session, user)


def store_password_hash(session: Session, user: User, password_hash: str) -> None:
    """Write the hash and nothing else.

    Separate from `set_password` for the one caller that is not a credential
    change: a login whose stored hash predates a cost increase re-stores it
    while it has the plaintext. The password did not change, so ending that
    user's sessions over it would log them out for logging in.
    """
    session.execute(
        User.__table__.update()
        .where(User.id == user.id)
        .values(password_hash=password_hash)
    )
    # Not a plain assignment: on an *attached* user that would mark the
    # instance dirty and flush a second, identical UPDATE.
    set_committed_value(user, "password_hash", password_hash)


def end_sessions(session: Session, user: User) -> int:
    """Invalidate every credential this account is holding. Returns the epoch.

    Refresh tokens are rows and are revoked; access tokens are signed strings
    that nobody can recall, so instead the epoch they were minted under stops
    matching and `app.services.sessions` refuses them on the next request —
    including the request an open SSE stream re-checks itself with.
    """
    epoch = session.execute(
        User.__table__.update()
        .where(User.id == user.id)
        .values(session_epoch=User.__table__.c.session_epoch + 1)
        .returning(User.__table__.c.session_epoch)
    ).scalar_one()
    set_committed_value(user, "session_epoch", epoch)
    revoke_all_tokens(session, user.id)
    return epoch


def set_active(session: Session, user: User, is_active: bool) -> None:
    user.is_active = is_active
    if not is_active:
        # Same reasoning as a password change: the refresh token is revoked and
        # the epoch bump takes the access tokens with it, rather than leaving a
        # disabled account a working session for the token's last few minutes.
        end_sessions(session, user)
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
