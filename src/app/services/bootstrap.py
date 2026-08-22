"""Ensure the admin role, the admin account and the default credential exist.

Runs on every boot, after migrations and before the app serves anything.

This runs after migrations and before the app serves anything, and it raises on
failure so the process exits. That is the intent: an API whose permission
model is enforced everywhere is unusable if nobody holds the scopes, so a
backend that cannot guarantee an administrator must not pretend to be up.

The role is *reconciled*: its scope set is rewritten to exactly `ALL_SCOPES`
every time. That is what lets a scope added to `app.security.scopes` reach the
admin role through an ordinary deployment, with no migration and no data edit,
and it heals a hand-edited database on the next restart.

The user is *not* reconciled. Its password is written once, at creation. Anyone
can change it afterwards through `/auth/me/password`, and rewriting it from the
environment on every boot would silently revert that — while also requiring the
plaintext to stay in `.env`. `ADMIN_PASSWORD_RESET=true` forces one
rotation, for the case where the password is genuinely lost.

The account is always re-activated and always re-granted the role, because an
admin who deactivated themselves or dropped their own role would otherwise have
locked everyone out permanently.
"""

from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from app.config import Settings
from app.db import credentials as credentials_repo
from app.db import machines as machines_repo
from app.db import roles as roles_repo
from app.db import users as users_repo
from app.db.pool import Database
from app.db.tables import Role, RoleScope
from app.security.crypto import CredentialCipher
from app.security.scopes import ADMIN_ROLE_NAME, ALL_SCOPES
from app.services.auth import hash_password_blocking

log = logging.getLogger(__name__)


def ensure_admin_role(session: Session) -> Role:
    role = roles_repo.get_by_name(session, ADMIN_ROLE_NAME)
    if role is None:
        role = Role(
            name=ADMIN_ROLE_NAME,
            description="Full access to every endpoint. Built in; cannot be deleted.",
            is_system=True,
        )
        session.add(role)
        log.info("admin bootstrap: created the %s role", ADMIN_ROLE_NAME)

    role.is_system = True
    current = role.scope_set
    if current != ALL_SCOPES:
        # Assigned wholesale rather than diffed: the target is a constant, so
        # there is nothing a merge would preserve.
        role.scopes = [RoleScope(scope=s) for s in sorted(ALL_SCOPES)]
        if current:
            log.info(
                "admin bootstrap: reconciled the %s role's scopes (%s -> %s)",
                ADMIN_ROLE_NAME,
                len(current),
                len(ALL_SCOPES),
            )
    session.flush()
    return role


def bootstrap_blocking(session: Session, settings: Settings) -> None:
    role = ensure_admin_role(session)
    username = settings.admin_username.strip()
    password = settings.admin_password.get_secret_value()

    user = users_repo.get_by_username(session, username)
    if user is None:
        user = users_repo.create(
            session, username, hash_password_blocking(password), [role]
        )
        log.info(
            "admin bootstrap: created user %r with the %s role (%s scopes)",
            username,
            ADMIN_ROLE_NAME,
            len(ALL_SCOPES),
        )
    else:
        if settings.admin_password_reset:
            users_repo.set_password(session, user, hash_password_blocking(password))
            log.warning(
                "admin bootstrap: ADMIN_PASSWORD_RESET rotated %r's password and "
                "ended its sessions — unset it before the next restart",
                username,
            )
        # Re-granted and re-activated unconditionally. These are the two ways an
        # administrator can lock the whole deployment out of itself, and the
        # environment is the only authority left to undo them.
        if role not in user.roles:
            user.roles = [*user.roles, role]
            log.warning("admin bootstrap: restored the %s role on %r", ADMIN_ROLE_NAME, username)
        if not user.is_active:
            user.is_active = True
            log.warning("admin bootstrap: reactivated %r", username)

    session.flush()


async def bootstrap_admin(db: Database, settings: Settings) -> None:
    """Run the reconciler in one transaction. Raises to abort startup."""
    await db.run_session(bootstrap_blocking, settings)


# --- SNMP credentials --------------------------------------------------------

DEFAULT_V2C_NAME = "default-v2c"


def seed_default_credential_blocking(
    conn: Connection, settings: Settings, cipher: CredentialCipher
) -> None:
    """Carry `SNMP_COMMUNITY` into a credential profile, once.

    Migration 0003 adds the table and leaves it empty, because Alembic runs with
    `DatabaseSettings` and has no key ring to encrypt with. This is where the
    upgrade actually lands: the community string every machine was previously
    polled with becomes a `default-v2c` profile, and every machine that has no
    credential is bound to it, so a fleet that was being polled before the
    upgrade is still being polled after it.

    **The bind only runs in the same pass that creates the profile.** Rebinding
    unbound machines on every boot would undo a deliberate unbind — including
    the unbind that `PATCH /machines/{mac}` tells an operator to perform before
    moving a machine's address, which would then silently rebind under them.
    After the first pass this function does nothing at all.
    """
    existing = credentials_repo.get_by_name(conn, DEFAULT_V2C_NAME)
    if existing is not None:
        return

    credential_id = uuid4()
    payload = {"community": settings.snmp_community}
    secret, key_id = cipher.encrypt(credential_id, 1, payload)
    row = credentials_repo.insert(
        conn,
        credential_id,
        DEFAULT_V2C_NAME,
        "Created from SNMP_COMMUNITY when this deployment gained credentials.",
        "2c",
        None,
        None,
        None,
        None,
        secret,
        key_id,
        cipher.fingerprint(payload),
    )
    if row is None:
        # Another process won the race between the read and this insert.
        return

    bound = machines_repo.bind_unbound(conn, credential_id)
    log.warning(
        "credential bootstrap: created %r from SNMP_COMMUNITY and bound %s "
        "existing machine(s) to it — SNMP_COMMUNITY is no longer read after this",
        DEFAULT_V2C_NAME,
        bound,
    )


async def bootstrap_credentials(
    db: Database, settings: Settings, cipher: CredentialCipher
) -> None:
    """Seed the default credential.

    `Settings` requires a key ring, so the guard below is belt and braces: a
    cipher that cannot seal anything would otherwise fail inside the seeding
    query, on a code path that runs before the API serves its first request.
    """
    if not cipher.usable:
        log.info(
            "credential bootstrap: skipped, no SNMP_CREDENTIAL_KEYS configured"
        )
        return
    await db.run_query(seed_default_credential_blocking, settings, cipher)
