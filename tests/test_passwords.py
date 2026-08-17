"""A password change must actually change the password.

Both endpoints, since they arrive at it differently: the self-service one holds
the current plaintext and compares, the administrative one has only the stored
hash and has to verify against it.
"""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.api.routers import users as users_router
from app.api.routers.auth import change_own_password
from app.api.security import Principal
from app.models.auth import PasswordChange, PasswordReset
from app.security.scopes import Scope
from app.services.auth import hash_password_blocking

NOW = datetime(2026, 8, 17, tzinfo=UTC)
CURRENT = "current-password-1"
# One Argon2 hash for the whole module: at the configured cost each is a few
# milliseconds of deliberate work.
CURRENT_HASH = hash_password_blocking(CURRENT)

TARGET_ID = uuid.uuid4()
CALLER = Principal(
    user_id=uuid.uuid4(), username="operator", scopes=frozenset({str(Scope.USERS_WRITE)})
)
SETTINGS = SimpleNamespace(password_min_length=12)


def target_user() -> SimpleNamespace:
    return SimpleNamespace(
        id=TARGET_ID,
        username="viewer1",
        password_hash=CURRENT_HASH,
        scopes=frozenset(),
        is_active=True,
        roles=[],
        created_at=NOW,
        updated_at=NOW,
    )


class FakeDb:
    """`run_session` that runs the callable against a stub session."""

    def __init__(self, user: SimpleNamespace) -> None:
        self._session = SimpleNamespace(get=lambda _model, _id: user)

    async def run_session(self, fn, *args):
        return fn(self._session, *args)


class AdministrativeResetTests(IsolatedAsyncioTestCase):
    async def test_reset_to_the_current_password_is_refused(self) -> None:
        db = FakeDb(target_user())

        with patch.object(users_router.users_repo, "set_password") as set_password:
            with self.assertRaises(HTTPException) as caught:
                await users_router.reset_user_password(
                    TARGET_ID, PasswordReset(new_password=CURRENT), db, SETTINGS, CALLER
                )

        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("different", caught.exception.detail)
        # Refused means refused: no write, so no session revocation either.
        set_password.assert_not_called()

    async def test_a_different_password_still_resets(self) -> None:
        db = FakeDb(target_user())

        with patch.object(users_router.users_repo, "set_password") as set_password:
            await users_router.reset_user_password(
                TARGET_ID,
                PasswordReset(new_password="a-different-password"),
                db,
                SETTINGS,
                CALLER,
            )

        set_password.assert_called_once()

    async def test_an_unreadable_stored_hash_does_not_block_a_reset(self) -> None:
        # A truncated column or a downgraded build. That account needs a new
        # password more than most, so the reset must not be refused.
        user = target_user()
        user.password_hash = "not-a-parseable-argon2-hash"
        db = FakeDb(user)

        with patch.object(users_router.users_repo, "set_password") as set_password:
            await users_router.reset_user_password(
                TARGET_ID, PasswordReset(new_password=CURRENT), db, SETTINGS, CALLER
            )

        set_password.assert_called_once()


class SelfServiceChangeTests(IsolatedAsyncioTestCase):
    async def test_changing_to_the_same_password_is_refused(self) -> None:
        db = AsyncMock()

        with self.assertRaises(HTTPException) as caught:
            await change_own_password(
                db,
                SETTINGS,
                CALLER,
                PasswordChange(current_password=CURRENT, new_password=CURRENT),
            )

        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("different", caught.exception.detail)
        # Cheapest check first: refused before the account is even read.
        db.run_session.assert_not_awaited()

    async def test_too_short_is_still_the_policy_error(self) -> None:
        # Order matters only in that the more specific message should not
        # swallow the policy one.
        db = AsyncMock()

        with self.assertRaises(HTTPException) as caught:
            await change_own_password(
                db,
                SETTINGS,
                CALLER,
                PasswordChange(current_password="short", new_password="short"),
            )

        self.assertIn("at least 12 characters", caught.exception.detail)
