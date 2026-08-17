from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock

from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app.api.routers.auth import login
from app.services.ratelimit import LoginRateLimiter


class FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def build_limiter(clock: FakeClock, **overrides: object) -> LoginRateLimiter:
    kwargs: dict[str, object] = {
        "max_per_user": 3,
        "max_per_ip": 5,
        "window_seconds": 60.0,
        "clock": clock,
    }
    kwargs.update(overrides)
    return LoginRateLimiter(**kwargs)  # type: ignore[arg-type]


class LoginRateLimiterTests(TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.limiter = build_limiter(self.clock)

    def test_attempts_below_the_limit_are_allowed(self) -> None:
        for _ in range(2):
            self.limiter.record_failure("alice", "10.0.0.1")

        self.assertIsNone(self.limiter.retry_after("alice", "10.0.0.1"))

    def test_user_limit_blocks_for_the_rest_of_the_window(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")

        self.assertEqual(self.limiter.retry_after("alice", "10.0.0.1"), 60.0)

    def test_block_expires_once_the_oldest_failure_ages_out(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")
        self.clock.advance(59.0)

        self.assertEqual(self.limiter.retry_after("alice", "10.0.0.1"), 1.0)

        self.clock.advance(1.0)
        self.assertIsNone(self.limiter.retry_after("alice", "10.0.0.1"))

    def test_user_block_follows_the_username_to_another_address(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")

        # The point of the username counter: a botnet does not get a fresh
        # budget per host.
        self.assertIsNotNone(self.limiter.retry_after("alice", "10.0.0.9"))

    def test_username_casing_does_not_buy_a_fresh_budget(self) -> None:
        for name in ("alice", "Alice", "ALICE"):
            self.limiter.record_failure(name, "10.0.0.1")

        self.assertIsNotNone(self.limiter.retry_after("aLiCe", "10.0.0.1"))

    def test_address_limit_survives_a_spray_across_usernames(self) -> None:
        for name in ("a", "b", "c", "d", "e"):
            self.limiter.record_failure(name, "10.0.0.1")

        # No username is near its own limit, but the address is at five.
        self.assertIsNone(self.limiter.retry_after("f", "10.0.0.2"))
        self.assertIsNotNone(self.limiter.retry_after("f", "10.0.0.1"))

    def test_one_address_cannot_lock_out_the_whole_service(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")

        self.assertIsNone(self.limiter.retry_after("bob", "10.0.0.2"))

    def test_success_clears_the_username_but_not_the_address(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")
        for _ in range(2):
            self.limiter.record_failure("bob", "10.0.0.1")

        self.limiter.record_success("alice")

        self.assertIsNone(self.limiter.retry_after("alice", "10.0.0.2"))
        # Five failures from that address, which is its limit, so the address
        # stays blocked even for the account that just succeeded.
        self.assertIsNotNone(self.limiter.retry_after("alice", "10.0.0.1"))

    def test_a_missing_client_address_still_counts_the_username(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", None)

        self.assertIsNotNone(self.limiter.retry_after("alice", None))

    def test_disabled_limiter_never_blocks(self) -> None:
        limiter = build_limiter(self.clock, enabled=False)
        for _ in range(50):
            limiter.record_failure("alice", "10.0.0.1")

        self.assertIsNone(limiter.retry_after("alice", "10.0.0.1"))

    def test_keys_are_forgotten_once_their_failures_age_out(self) -> None:
        self.limiter.record_failure("alice", "10.0.0.1")
        self.clock.advance(61.0)
        # The sweep runs on write, at most once per window.
        self.limiter.record_failure("bob", "10.0.0.2")

        self.assertEqual(
            sorted(self.limiter._failures), ["ip:10.0.0.2", "user:bob"]
        )


class LoginThrottlingTests(IsolatedAsyncioTestCase):
    """The handler's half: 429 before any work, and counting on rejection."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.limiter = build_limiter(self.clock)
        self.db = SimpleNamespace(run_session=AsyncMock())
        self.settings = SimpleNamespace()
        self.form = OAuth2PasswordRequestForm(username="alice", password="hunter2")

    async def test_throttled_login_is_429_and_touches_nothing(self) -> None:
        for _ in range(3):
            self.limiter.record_failure("alice", "10.0.0.1")

        with self.assertRaises(HTTPException) as caught:
            await login(self.db, self.settings, self.limiter, "10.0.0.1", self.form)

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.headers["Retry-After"], "60")
        # No database round trip and, more to the point, no Argon2 verification.
        self.db.run_session.assert_not_awaited()

    async def test_unknown_user_is_401_and_counted(self) -> None:
        self.db.run_session.return_value = None

        with self.assertRaises(HTTPException) as caught:
            await login(self.db, self.settings, self.limiter, "10.0.0.1", self.form)

        self.assertEqual(caught.exception.status_code, 401)
        # Counted even though the account does not exist — a limit that only
        # applied to real usernames would enumerate them.
        self.assertEqual(len(self.limiter._failures["user:alice"]), 1)
