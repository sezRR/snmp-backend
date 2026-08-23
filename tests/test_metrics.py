from datetime import UTC, datetime
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException

from app.api.routers.metrics import purge_machine_metrics
from app.db import machines as machines_repo
from app.db import metrics as metrics_repo


class _Result:
    def __init__(self, *, rowcount: int = 0, rows: list[dict] | None = None) -> None:
        self.rowcount = rowcount
        self._rows = rows or []

    def mappings(self) -> list[dict]:
        return self._rows


class _Connection:
    def __init__(
        self, *, rowcounts: list[int] | None = None, rows: list[dict] | None = None
    ) -> None:
        self.rowcounts = iter(rowcounts or [])
        self.rows = rows
        self.calls: list[tuple[str, dict | None]] = []

    def execute(self, statement, params=None) -> _Result:
        self.calls.append((str(statement), params))
        if self.rows is not None:
            rows, self.rows = self.rows, None
            return _Result(rows=rows)
        return _Result(rowcount=next(self.rowcounts, 0))


class MetricPurgeTests(TestCase):
    def test_machine_purge_deletes_raw_and_both_rollups(self) -> None:
        before = datetime(2026, 8, 1, tzinfo=UTC)
        conn = _Connection(rowcounts=[0, 7, 3, 1])

        deleted = metrics_repo.purge_machine(conn, "fa:fa:fa:fa:fa:fa", before)

        self.assertEqual(deleted, {"metrics": 7, "metrics_1m": 3, "metrics_1h": 1})
        sql = [query for query, _ in conn.calls]
        self.assertIn(
            "SET LOCAL timescaledb.max_tuples_decompressed_per_dml_transaction = 0",
            sql[0],
        )
        self.assertIn("DELETE FROM metrics\n", sql[1])
        self.assertIn("DELETE FROM metrics_1m\n", sql[2])
        self.assertIn("DELETE FROM metrics_1h\n", sql[3])
        self.assertTrue(
            all(
                params == {"mac": "fa:fa:fa:fa:fa:fa", "before": before}
                for _, params in conn.calls[1:]
            )
        )

    def test_all_history_purge_clears_raw_and_both_rollups(self) -> None:
        conn = _Connection()

        method, rows = metrics_repo.purge_all(conn, None)

        self.assertEqual((method, rows), ("truncate", None))
        sql = [query for query, _ in conn.calls]
        self.assertEqual(len(sql), 1)
        self.assertIn("TRUNCATE TABLE metrics, metrics_1m, metrics_1h", sql[0])

    def test_ranged_all_history_purge_drops_chunks_from_every_source(self) -> None:
        before = datetime(2026, 8, 1, tzinfo=UTC)
        conn = _Connection()

        method, rows = metrics_repo.purge_all(conn, before)

        self.assertEqual((method, rows), ("drop_chunks", None))
        sql = [query for query, _ in conn.calls]
        self.assertIn("drop_chunks('metrics'", sql[0])
        self.assertIn("drop_chunks('metrics_1m'", sql[1])
        self.assertIn("drop_chunks('metrics_1h'", sql[2])
        self.assertTrue(all(params == {"before": before} for _, params in conn.calls))


class MetricCountTests(TestCase):
    def test_counts_include_each_source_and_cagg_only_machines(self) -> None:
        oldest = datetime(2026, 7, 1, tzinfo=UTC)
        latest = datetime(2026, 8, 1, tzinfo=UTC)
        conn = _Connection(
            rows=[
                {
                    "source": "metrics",
                    "mac": "fa:fa:fa:fa:fa:01",
                    "rows": 7,
                    "samples": 7,
                    "oldest": oldest,
                    "latest": latest,
                },
                {
                    "source": "metrics_1m",
                    "mac": "fa:fa:fa:fa:fa:01",
                    "rows": 3,
                    "samples": 21,
                    "oldest": oldest,
                    "latest": latest,
                },
                {
                    "source": "metrics_1h",
                    "mac": "fa:fa:fa:fa:fa:02",
                    "rows": 2,
                    "samples": 100,
                    "oldest": oldest,
                    "latest": latest,
                },
            ]
        )

        counts = metrics_repo.counts_by_machine(conn)

        self.assertEqual(
            counts,
            [
                {
                    "mac": "fa:fa:fa:fa:fa:01",
                    "samples": 7,
                    "latest": latest,
                    "metrics": {
                        "rows": 7,
                        "samples": 7,
                        "oldest": oldest,
                        "latest": latest,
                    },
                    "metrics_1m": {
                        "rows": 3,
                        "samples": 21,
                        "oldest": oldest,
                        "latest": latest,
                    },
                    "metrics_1h": {
                        "rows": 0,
                        "samples": 0,
                        "oldest": None,
                        "latest": None,
                    },
                },
                {
                    "mac": "fa:fa:fa:fa:fa:02",
                    "samples": 0,
                    "latest": None,
                    "metrics": {
                        "rows": 0,
                        "samples": 0,
                        "oldest": None,
                        "latest": None,
                    },
                    "metrics_1m": {
                        "rows": 0,
                        "samples": 0,
                        "oldest": None,
                        "latest": None,
                    },
                    "metrics_1h": {
                        "rows": 2,
                        "samples": 100,
                        "oldest": oldest,
                        "latest": latest,
                    },
                },
            ],
        )


class MachineDeleteTests(TestCase):
    @patch.object(metrics_repo, "purge_machine_rollups")
    @patch.object(metrics_repo, "allow_bulk_decompression")
    def test_deregister_purges_rollups_after_raw_metrics_cascade(
        self, allow_bulk_decompression: Mock, purge_machine_rollups: Mock
    ) -> None:
        conn = _Connection(rowcounts=[1])
        mac = "fa:fa:fa:fa:fa:fa"

        deleted = machines_repo.delete(conn, mac)

        self.assertTrue(deleted)
        allow_bulk_decompression.assert_called_once_with(conn)
        purge_machine_rollups.assert_called_once_with(conn, mac, None)

    @patch.object(metrics_repo, "purge_machine_rollups")
    @patch.object(metrics_repo, "allow_bulk_decompression")
    def test_unknown_machine_does_not_purge_rollups(
        self, allow_bulk_decompression: Mock, purge_machine_rollups: Mock
    ) -> None:
        conn = _Connection(rowcounts=[0])

        deleted = machines_repo.delete(conn, "fa:fa:fa:fa:fa:fa")

        self.assertFalse(deleted)
        allow_bulk_decompression.assert_called_once_with(conn)
        purge_machine_rollups.assert_not_called()


class MachinePurgeEndpointTests(IsolatedAsyncioTestCase):
    async def test_stale_rollup_history_can_be_purged_after_deregistration(
        self,
    ) -> None:
        db = Mock()
        db.run_query = AsyncMock(
            side_effect=[
                None,
                {"metrics": 0, "metrics_1m": 10, "metrics_1h": 2},
            ]
        )

        result = await purge_machine_metrics("fa:fa:fa:fa:fa:fa", db, None)

        self.assertEqual(result.rows_deleted, 12)
        self.assertEqual(
            result.rows_deleted_by_source,
            {"metrics": 0, "metrics_1m": 10, "metrics_1h": 2},
        )

    async def test_unknown_machine_without_history_is_still_not_found(self) -> None:
        db = Mock()
        db.run_query = AsyncMock(
            side_effect=[
                None,
                {"metrics": 0, "metrics_1m": 0, "metrics_1h": 0},
            ]
        )

        with self.assertRaises(HTTPException) as raised:
            await purge_machine_metrics("fa:fa:fa:fa:fa:fa", db, None)

        self.assertEqual(raised.exception.status_code, 404)
