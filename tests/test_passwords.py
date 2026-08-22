import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.api.routers import users as users_router
from app.api.routers.auth import change_own_password
from app.api.security import Principal
from app.db import users as users_repo
from app.db.tables import User
from sqlalchemy.orm.attributes import set_committed_value
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
        session_epoch=0,
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


class FakeEpochs:
    """Records what the router tells the session-epoch cache."""

    def __init__(self) -> None:
        self.remembered: list[tuple[object, int]] = []

    def remember(self, user_id, epoch) -> None:
        self.remembered.append((user_id, epoch))

    def forget(self, user_id) -> None:  # pragma: no cover - not on these paths
        pass


class AdministrativeResetTests(IsolatedAsyncioTestCase):
    async def test_reset_to_the_current_password_is_refused(self) -> None:
        db = FakeDb(target_user())

        with patch.object(users_router.users_repo, "set_password") as set_password:
            with self.assertRaises(HTTPException) as caught:
                await users_router.reset_user_password(
                    TARGET_ID,
                    PasswordReset(new_password=CURRENT),
                    db,
                    SETTINGS,
                    FakeEpochs(),
                    CALLER,
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
                FakeEpochs(),
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
                TARGET_ID,
                PasswordReset(new_password=CURRENT),
                db,
                SETTINGS,
                FakeEpochs(),
                CALLER,
            )

        set_password.assert_called_once()


class SelfServiceChangeTests(IsolatedAsyncioTestCase):
    async def test_changing_to_the_same_password_is_refused(self) -> None:
        db = AsyncMock()

        with self.assertRaises(HTTPException) as caught:
            await change_own_password(
                db,
                SETTINGS,
                FakeEpochs(),
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
                FakeEpochs(),
                CALLER,
                PasswordChange(current_password="short", new_password="short"),
            )

        self.assertIn("at least 12 characters", caught.exception.detail)


class RepositoryWriteTests(TestCase):
    """The write must be SQL, not an assignment to a possibly-detached row.

    The routers load the user in one `run_session` and write in the next, so
    the `User` handed to these is detached from the session doing the write —
    and assigning to a detached instance updates nothing at all. The endpoint
    still returns 200, still revokes the refresh tokens (that part is Core
    SQL), and leaves the old password in force.
    """

    def setUp(self) -> None:
        self.statements: list = []
        self.session = SimpleNamespace(execute=self._execute)
        self.user = User(id=TARGET_ID, username="viewer1", password_hash=CURRENT_HASH)
        set_committed_value(self.user, "session_epoch", 4)

    def _execute(self, stmt):
        self.statements.append(stmt)
        # Enough of a Result for both writers: the epoch bump reads its
        # RETURNING value, the token revocation reads its row count.
        return SimpleNamespace(scalar_one=lambda: 5, rowcount=0)

    def test_the_password_update_is_keyed_on_the_user_id(self) -> None:
        users_repo.store_password_hash(self.session, self.user, "new-hash")

        update = self.statements[0]
        compiled = update.compile()
        self.assertEqual(update.table.name, "users")
        self.assertEqual(compiled.params["password_hash"], "new-hash")
        self.assertIn(TARGET_ID, compiled.params.values())
        # And the caller can still read the new hash off the instance it holds.
        self.assertEqual(self.user.password_hash, "new-hash")

    def test_ending_sessions_bumps_the_epoch_and_revokes_the_tokens(self) -> None:
        # The bump is what reaches the access tokens, which are stateless and
        # cannot be revoked; the caller mints its replacement pair under the
        # returned value, which is why it has to come back.
        epoch = users_repo.end_sessions(self.session, self.user)

        self.assertEqual(epoch, 5)
        self.assertEqual(self.user.session_epoch, 5)
        tables = [stmt.table.name for stmt in self.statements]
        self.assertEqual(tables, ["users", "refresh_tokens"])

    def test_a_password_change_does_both(self) -> None:
        users_repo.set_password(self.session, self.user, "new-hash")

        self.assertEqual(self.user.password_hash, "new-hash")
        self.assertEqual(self.user.session_epoch, 5)

    def test_a_hash_upgrade_ends_nothing(self) -> None:
        # A login that re-stores a hash whose cost parameters changed is not a
        # credential change, and must not sign the user out for logging in.
        users_repo.store_password_hash(self.session, self.user, "rehashed")

        self.assertEqual(self.user.session_epoch, 4)
        self.assertEqual([stmt.table.name for stmt in self.statements], ["users"])
