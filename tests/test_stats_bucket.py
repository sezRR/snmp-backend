"""Bucket presets and the width an omitted `?bucket=` resolves to.

`/metrics/stats` answers windows from an hour to two years out of three sources.
A fixed default width cannot serve that: five minutes is twelve points over an
hour and eight thousand over a month, one of which is unreadable and the other
of which the row cap rejects. `StatsBucket.at_least` is what fits the width to
the window instead — and the same call floors it at what a rollup can resolve.
"""

from unittest import TestCase

from app.api.routers.metrics import MAX_BUCKETS, TARGET_POINTS
from app.db import rollups
from app.models.metric import StatsBucket

HOUR = 3_600.0
DAY = 24 * HOUR

# The ladder an omitted bucket must produce, as (window seconds, preset).
LADDER = (
    (HOUR, StatsBucket.S30),
    (6 * HOUR, StatsBucket.M1),
    (DAY, StatsBucket.M5),
    (7 * DAY, StatsBucket.H1),
    (30 * DAY, StatsBucket.H6),
    (90 * DAY, StatsBucket.H6),
    (730 * DAY, StatsBucket.D7),
)


class AtLeastTest(TestCase):
    def test_presets_are_declared_narrowest_first(self):
        """`at_least` returns the first match, so the order is load-bearing."""
        widths = [bucket.seconds for bucket in StatsBucket]
        self.assertEqual(widths, sorted(widths))

    def test_returns_the_narrowest_preset_that_is_wide_enough(self):
        self.assertEqual(StatsBucket.at_least(0), StatsBucket.S30)
        self.assertEqual(StatsBucket.at_least(30), StatsBucket.S30)
        self.assertEqual(StatsBucket.at_least(31), StatsBucket.M1)
        self.assertEqual(StatsBucket.at_least(3_600), StatsBucket.H1)

    def test_asking_for_more_than_the_widest_preset_gives_the_widest(self):
        self.assertEqual(StatsBucket.at_least(1e9), StatsBucket.D7)

    def test_fitted_bucket_matches_the_documented_ladder(self):
        for span, expected in LADDER:
            with self.subTest(span=span):
                self.assertEqual(StatsBucket.at_least(span / TARGET_POINTS), expected)

    def test_fitted_bucket_never_trips_the_row_cap(self):
        """The reason the fit exists: no window can 422 on its own default."""
        for span, _ in LADDER:
            with self.subTest(span=span):
                fitted = StatsBucket.at_least(span / TARGET_POINTS)
                self.assertLessEqual(span / fitted.seconds, MAX_BUCKETS)

    def test_every_source_floor_is_a_preset(self):
        """The floor is named back to the caller, so it has to be askable.

        A source whose minimum bucket rounded up to some wider preset would mean
        `X-Metrics-Bucket` reporting a width that does not match what the query
        actually grouped by.
        """
        for source, seconds in rollups.SOURCE_MIN_BUCKET_SECONDS.items():
            with self.subTest(source=source):
                floor = StatsBucket.at_least(seconds)
                if source == "metrics":
                    # Raw resolves to the second; the narrowest preset is 30s.
                    self.assertEqual(floor, StatsBucket.S30)
                else:
                    self.assertEqual(floor.seconds, seconds)

    def test_interval_is_what_postgres_gets(self):
        self.assertEqual(StatsBucket.M15.interval, "15 minutes")
        self.assertEqual(StatsBucket.D1.interval, "1 day")
