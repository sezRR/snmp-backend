"""Ending a session has to reach the credentials that are already out there.

Revoking the refresh token was never the hard half: it is a row. The access
token is a signed string in somebody's localStorage, and the stream it opened is
a socket that was authenticated once, minutes ago. These cover both.
"""

import asyncio
import json
import uuid
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase

from app.api.routers.stream import _events
from app.services.bus import MetricBus
from app.services.sessions import SessionEpochs

USER = uuid.uuid4()


class FakeDb:
    """`run_query` over a dict of user id to epoch, counting the reads."""

    def __init__(self, epochs: dict[uuid.UUID, int]) -> None:
        self.epochs = epochs
        self.reads = 0

    async def run_query(self, fn, *args):
        self.reads += 1
        (user_id,) = args
        return self.epochs.get(user_id)


class SessionEpochTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.db = FakeDb({USER: 5})
        self.epochs = SessionEpochs(self.db, ttl_seconds=60.0)

    async def test_a_matching_epoch_is_answered_from_cache(self) -> None:
        # The first request pays for the read; the rest of the session does not.
        self.assertTrue(await self.epochs.matches(USER, 5))
        self.assertTrue(await self.epochs.matches(USER, 5))
        self.assertEqual(self.db.reads, 1)

    async def test_a_token_from_before_the_bump_is_refused(self) -> None:
        self.assertFalse(await self.epochs.matches(USER, 4))

    async def test_a_fresh_token_beats_a_stale_cache(self) -> None:
        # The case that would log out the tab that just changed the password:
        # another process still has 5 cached and is shown a token minted under
        # 6. A cache is not allowed to answer a disagreement.
        self.epochs.remember(USER, 5)
        self.db.epochs[USER] = 6

        self.assertTrue(await self.epochs.matches(USER, 6))
        # ...and the re-read leaves the cache correct, so the old token that
        # was matching a moment ago is now refused.
        self.assertFalse(await self.epochs.matches(USER, 5))

    async def test_remembering_a_bump_refuses_the_previous_epoch_at_once(self) -> None:
        self.assertTrue(await self.epochs.matches(USER, 5))
        self.db.epochs[USER] = 6
        self.epochs.remember(USER, 6)

        self.assertFalse(await self.epochs.matches(USER, 5))

    async def test_a_deleted_account_is_refused_whatever_it_carries(self) -> None:
        self.assertFalse(await SessionEpochs(FakeDb({}), 60.0).matches(USER, 0))

    async def test_a_cached_epoch_expires(self) -> None:
        epochs = SessionEpochs(self.db, ttl_seconds=0.0)
        self.assertTrue(await epochs.matches(USER, 5))
        self.assertTrue(await epochs.matches(USER, 5))
        self.assertEqual(self.db.reads, 2)

    async def test_forgetting_sends_the_next_question_to_the_database(self) -> None:
        await self.epochs.matches(USER, 5)
        self.epochs.forget(USER)
        await self.epochs.matches(USER, 5)
        self.assertEqual(self.db.reads, 2)


async def _drain(events, count, timeout=2.0):
    """The first `count` events, or fail rather than hang."""
    collected = []

    async def pull():
        async for event in events:
            collected.append(event)
            if len(collected) == count:
                return

    await asyncio.wait_for(pull(), timeout)
    return collected


class StreamRevocationTests(IsolatedAsyncioTestCase):
    """A stream authenticates once and then runs for hours; it has to re-ask."""

    def setUp(self) -> None:
        self.bus = MetricBus()
        self.request = SimpleNamespace(is_disconnected=self._connected)

    async def _connected(self) -> bool:
        return False

    async def test_a_revoked_session_ends_the_stream(self) -> None:
        answers = [True, False]

        async def still_live() -> bool:
            return answers.pop(0) if answers else False

        events = _events(self.bus, None, self.request, still_live, 0.01)
        connected, revoked = await _drain(events, 2)

        self.assertEqual(connected["event"], "connected")
        self.assertEqual(revoked["event"], "session-revoked")
        self.assertEqual(json.loads(revoked["data"]), {"reason": "session ended"})
        # And nothing is left subscribed to the bus.
        await events.aclose()
        self.assertEqual(self.bus.subscriber_count, 0)

    async def test_an_idle_stream_keeps_its_subscription_across_rechecks(self) -> None:
        # The recheck timer fires far more often than a sample arrives on a
        # quiet fleet. If waiting for one were cancellable, every tick would
        # unwind the subscription and the sample below would never land.
        async def still_live() -> bool:
            return True

        events = _events(self.bus, None, self.request, still_live, 0.01)
        await _drain(events, 1)

        async def publish_after_several_rechecks():
            await asyncio.sleep(0.1)
            self.bus.publish(_sample())

        publisher = asyncio.create_task(publish_after_several_rechecks())
        (metric,) = await _drain(events, 1)
        await publisher

        self.assertEqual(metric["event"], "metric")
        self.assertEqual(self.bus.subscriber_count, 1)
        await events.aclose()
        self.assertEqual(self.bus.subscriber_count, 0)


def _sample():
    from datetime import UTC, datetime

    from app.models.metric import MetricSample

    return MetricSample(
        ts=datetime.now(UTC), mac="fa:16:3e:00:00:01", metrics={"cpu": {"usage_percent": 1.0}}
    )
