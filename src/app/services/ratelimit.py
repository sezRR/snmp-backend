"""Failed-login throttling.

No database and no HTTP here, like `app.services.auth`: this counts events
against keys and says how long the caller must wait. `app.api.routers.auth`
turns that into a 429.

**Two keys per attempt, because one is not enough.** A per-username counter is
what stops a password being guessed, but on its own it lets anyone lock any
account out by failing five logins against it. A per-IP counter is what stops a
spray across many usernames from one host, but on its own it does nothing about
a botnet grinding a single account. Both are checked, and the longer wait wins.

**Only failures count.** A successful login clears the username's counter and
leaves the address's alone — otherwise anyone holding one valid account could
reset their own budget between guesses at another.

**In-process, on `app.state`**, like `StreamTickets`. With one process that is
the whole picture; with several, each carries its own counters and the effective
limit multiplies by the process count. That is a weaker bound, not a broken one,
and the alternative is a shared store this installation does not have.
Moving to one means replacing the dict below and nothing else.

The counters are what protect the Argon2 verification, which is deliberately
expensive: `retry_after` is consulted before a password is hashed, so a rejected
attempt costs a dictionary lookup rather than 19 MiB and a few milliseconds of
CPU. That is as much a denial-of-service bound as a credential-stuffing one.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable, Iterator

log = logging.getLogger(__name__)


class LoginRateLimiter:
    """Sliding-window failure counters, keyed by username and client address.

    A key is blocked once it holds `max_*` failures inside `window_seconds`, and
    stays blocked until the oldest of them ages out — so the wait after the last
    failure that trips the limit is the full window, and shrinks from there.
    """

    def __init__(
        self,
        *,
        max_per_user: int,
        max_per_ip: int,
        window_seconds: float,
        enabled: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_per_user = max_per_user
        self._max_per_ip = max_per_ip
        self._window = window_seconds
        self._enabled = enabled
        self._clock = clock
        # key -> timestamps of recent failures. Each deque is capped at its own
        # limit, so a key costs a bounded number of floats no matter how long it
        # is hammered; `_sweep` is what drops the keys themselves.
        self._failures: dict[str, deque[float]] = {}
        self._last_sweep = clock()

    def retry_after(self, username: str, ip: str | None) -> float | None:
        """Seconds the caller must wait, or None if the attempt may proceed."""
        if not self._enabled:
            return None
        now = self._clock()
        waits = [
            wait
            for key, limit in self._keys(username, ip)
            if (wait := self._wait(key, limit, now)) is not None
        ]
        return max(waits) if waits else None

    def record_failure(self, username: str, ip: str | None) -> None:
        """Count one rejected attempt against both of its keys."""
        if not self._enabled:
            return
        now = self._clock()
        self._sweep(now)
        for key, limit in self._keys(username, ip):
            attempts = self._failures.get(key)
            if attempts is None:
                attempts = self._failures[key] = deque(maxlen=limit)
            attempts.append(now)

    def record_success(self, username: str) -> None:
        """Forget this username's failures. The address keeps its own count."""
        if not self._enabled:
            return
        self._failures.pop(self._user_key(username), None)

    # --- internals -----------------------------------------------------------

    def _keys(self, username: str, ip: str | None) -> Iterator[tuple[str, int]]:
        """The (key, limit) pairs an attempt is counted against.

        Prefixed so a username can never collide with an address, and the
        username is casefolded because the bucket has no reason to be stricter
        than the lookup — varying the case must not buy a fresh budget.
        """
        if self._max_per_user > 0:
            yield self._user_key(username), self._max_per_user
        # `ip` is None when the ASGI scope carries no client, which is the case
        # for in-process test transports. Nothing to key on, so nothing to
        # count; the username half still applies.
        if ip is not None and self._max_per_ip > 0:
            yield f"ip:{ip}", self._max_per_ip

    @staticmethod
    def _user_key(username: str) -> str:
        return f"user:{username.strip().casefold()}"

    def _wait(self, key: str, limit: int, now: float) -> float | None:
        attempts = self._failures.get(key)
        if attempts is None:
            return None
        self._expire(attempts, now)
        if len(attempts) < limit:
            return None
        return attempts[0] + self._window - now

    def _expire(self, attempts: deque[float], now: float) -> None:
        cutoff = now - self._window
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()

    def _sweep(self, now: float) -> None:
        """Drop keys whose failures have all aged out.

        Once per window rather than per attempt: the work is proportional to the
        number of live keys, and that number is already bounded by the per-IP
        limit — an address is blocked long before it can name many usernames.
        """
        if now - self._last_sweep < self._window:
            return
        self._last_sweep = now
        for key, attempts in list(self._failures.items()):
            self._expire(attempts, now)
            if not attempts:
                del self._failures[key]
