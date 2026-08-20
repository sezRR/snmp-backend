"""The no-editing-upwards guardrail, on both users and roles.

The handlers are called directly, with a fake session standing in for the two
repository reads they make before the guard fires. That is enough: every one of
these paths must refuse before it reaches a write, so a test that gets as far as
needing a real transaction has already failed.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.api.routers import roles as roles_router
from app.api.routers import users as users_router
from app.api.security import Principal
from app.models.auth import (
    PasswordReset,
    RoleScopes,
    RoleUpdate,
    UserRoles,
    UserUpdate,
)
from app.security.scopes import ALL_SCOPES, Scope

import uuid

ADMIN_ID = uuid.uuid4()
PEER_ID = uuid.uuid4()

# users:write and nothing else — the account this guardrail exists for.
OPERATOR = Principal(
    user_id=uuid.uuid4(),
    username="operator",
    scopes=frozenset({str(Scope.USERS_WRITE), str(Scope.ROLES_WRITE)}),
)
ADMIN = Principal(user_id=uuid.uuid4(), username="root", scopes=frozenset(ALL_SCOPES))


NOW = datetime(2026, 8, 17, tzinfo=UTC)


def fake_user(user_id: uuid.UUID, username: str, scopes: frozenset[str]) -> SimpleNamespace:
    return SimpleNamespace(
        id=user_id,
        username=username,
        scopes=scopes,
        is_active=True,
        session_epoch=0,
        roles=[],
        created_at=NOW,
        updated_at=NOW,
    )


def fake_role(name: str, scopes: frozenset[str]) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        description=None,
        scope_set=scopes,
        is_system=name == "admin",
        created_at=NOW,
        updated_at=NOW,
    )


class FakeDb:
    """`run_session` that actually runs the callable, against a stub session."""

    def __init__(self, session: object) -> None:
        self._session = session

    async def run_session(self, fn, *args):
        return fn(self._session, *args)


class FakeEpochs:
    """The session-epoch cache, with nothing behind it.

    These tests are about who may edit whom, not about session invalidation —
    they need the routers' `epochs` argument to exist and record what it was
    told, so that a bump nobody asked for shows up as a failure.
    """

    def __init__(self) -> None:
        self.remembered: list[tuple[object, int]] = []
        self.forgotten: list[object] = []

    def remember(self, user_id, epoch) -> None:
        self.remembered.append((user_id, epoch))

    def forget(self, user_id) -> None:
        self.forgotten.append(user_id)


def user_db(user: SimpleNamespace) -> FakeDb:
    """A session whose `get` returns one user, which is all `_load` needs."""
    return FakeDb(SimpleNamespace(get=lambda _model, _id: user))


def role_db(role: SimpleNamespace) -> FakeDb:
    """A session whose `execute` answers the one query `get_by_name` makes."""
    session = SimpleNamespace(
        execute=lambda _stmt: SimpleNamespace(scalar_one_or_none=lambda: role)
    )
    return FakeDb(session)


class EditingUsersUpwardsTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.admin_account = fake_user(ADMIN_ID, "root", frozenset(ALL_SCOPES))
        self.db = user_db(self.admin_account)
        self.settings = SimpleNamespace(password_min_length=12)
        self.epochs = FakeEpochs()

    async def assert_forbidden(self, awaitable) -> HTTPException:
        with self.assertRaises(HTTPException) as caught:
            await awaitable
        self.assertEqual(caught.exception.status_code, 403)
        return caught.exception

    async def test_operator_cannot_reset_an_admins_password(self) -> None:
        # The escalation: a password reset is a takeover of that account.
        exc = await self.assert_forbidden(
            users_router.reset_user_password(
                ADMIN_ID,
                PasswordReset(new_password="a-long-enough-password"),
                self.db,
                self.settings,
                self.epochs,
                OPERATOR,
            )
        )
        self.assertIn("admin:write", exc.detail)

    async def test_operator_cannot_deactivate_an_admin(self) -> None:
        await self.assert_forbidden(
            users_router.update_user(
                ADMIN_ID, UserUpdate(is_active=False), self.db, self.epochs, OPERATOR
            )
        )

    async def test_operator_cannot_strip_an_admins_roles(self) -> None:
        # Amplification is the other direction; this is taking authority away
        # from someone who has more of it.
        await self.assert_forbidden(
            users_router.set_user_roles(ADMIN_ID, UserRoles(roles=[]), self.db, OPERATOR)
        )

    async def test_operator_cannot_delete_an_admin(self) -> None:
        await self.assert_forbidden(
            users_router.delete_user(ADMIN_ID, self.db, self.epochs, OPERATOR)
        )

    async def test_an_admin_can_still_edit_another_admin(self) -> None:
        with patch.object(
            users_router.users_repo, "set_active", return_value=None
        ) as set_active:
            await users_router.update_user(
                ADMIN_ID, UserUpdate(is_active=False), self.db, self.epochs, ADMIN
            )

        set_active.assert_called_once()

    async def test_a_peer_is_still_editable(self) -> None:
        peer = fake_user(PEER_ID, "operator2", frozenset({str(Scope.USERS_WRITE)}))
        with patch.object(
            users_router.users_repo, "set_active", return_value=None
        ) as set_active:
            await users_router.update_user(
                PEER_ID, UserUpdate(is_active=False), user_db(peer), self.epochs, OPERATOR
            )

        set_active.assert_called_once()


class EditingRolesUpwardsTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.admin_role = fake_role("admin", frozenset(ALL_SCOPES))

    async def assert_forbidden(self, awaitable) -> None:
        with self.assertRaises(HTTPException) as caught:
            await awaitable
        self.assertEqual(caught.exception.status_code, 403)

    async def test_operator_cannot_edit_the_admin_roles_description(self) -> None:
        await self.assert_forbidden(
            roles_router.update_role(
                "admin",
                RoleUpdate(description="mine now"),
                role_db(self.admin_role),
                OPERATOR,
            )
        )

    async def test_operator_cannot_rewrite_a_privileged_roles_scopes(self) -> None:
        # Every scope written is one the caller holds, so the amplification
        # check passes — it is the role's existing authority that forbids this.
        privileged = fake_role("ops", frozenset({str(Scope.ADMIN_WRITE)}))
        await self.assert_forbidden(
            roles_router.set_role_scopes(
                "ops",
                RoleScopes(scopes=[str(Scope.USERS_WRITE)]),
                role_db(privileged),
                OPERATOR,
            )
        )

    async def test_operator_cannot_delete_a_privileged_role(self) -> None:
        privileged = fake_role("ops", frozenset({str(Scope.ADMIN_WRITE)}))
        await self.assert_forbidden(
            roles_router.delete_role("ops", role_db(privileged), OPERATOR)
        )

    async def test_a_role_within_the_callers_scopes_is_editable(self) -> None:
        viewer = fake_role("viewer", frozenset({str(Scope.USERS_WRITE)}))
        with patch.object(
            roles_router.roles_repo, "set_description", return_value=None
        ) as set_description:
            await roles_router.update_role(
                "viewer", RoleUpdate(description="read-only"), role_db(viewer), OPERATOR
            )

        set_description.assert_called_once()

    async def test_an_admin_may_still_edit_the_admin_roles_description(self) -> None:
        with patch.object(
            roles_router.roles_repo, "set_description", return_value=None
        ) as set_description:
            await roles_router.update_role(
                "admin", RoleUpdate(description="the built-in"), role_db(self.admin_role), ADMIN
            )

        set_description.assert_called_once()


class SelfEditTests(IsolatedAsyncioTestCase):
    """The pre-existing guard, which the subset test must not have loosened."""

    async def test_you_still_cannot_delete_yourself(self) -> None:
        db = AsyncMock()
        with self.assertRaises(HTTPException) as caught:
            await users_router.delete_user(
                OPERATOR.user_id, db, FakeEpochs(), OPERATOR
            )

        self.assertEqual(caught.exception.status_code, 409)
        db.run_session.assert_not_awaited()
