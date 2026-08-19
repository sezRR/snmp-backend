"""Wide-row metrics: scalar columns, no jsonb, plus the 1m and 1h rollups

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-19

The jsonb payload averaged 4.8 KB on a Kubernetes node and 73% of it was three
arrays nothing queried: every loop device, every tmpfs mount, and one veth per
pod. At a five second interval that is 83 MB per machine per day before indexes,
and the GIN index over the blob cost another 0.8x the heap while serving no
query in the codebase - `jsonb_path_ops` only answers `@>`, `@?` and `@@`, which
nothing ever issued.

This revision replaces the blob with one column per metric, backfills the
history it can, and adds the two continuous aggregates that make the shortened
raw retention survivable. Aggregates were not possible over the old shape at
all: the disk figure needed `jsonb_array_elements`, and a continuous aggregate
rejects set-returning functions.

Two backfilled columns deliberately disagree with the jsonb they are computed
from, because the old scalars were wrong:

* `net_*` is re-summed over physical interfaces only. `network.rx_bps` counted
  every up, non-loopback interface, so one packet crossing a veth, a bridge and
  the uplink counted three times.
* `disk_max_used_pct` skips pseudo filesystems, where the old query took the max
  over every mount and read a full tmpfs as a full disk.

The aggregate definitions below are literal rather than generated from
`app.db.rollups`. A migration is a snapshot: if it read that module, editing the
spec would change what this revision replays as, and a database rebuilt from
scratch would diverge from one migrated forward.
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# Matching `Settings.metrics_virtual_iface_prefixes` and
# `metrics_pseudo_mount_prefixes` as they stood when this revision was written.
# Frozen here on purpose: the backfill has to stay reproducible after the
# settings defaults move on.
VIRTUAL_IFACE_PREFIXES = (
    "veth|cni|flannel|docker|br-|virbr|kube-ipvs|tunl|gre|sit|ip6tnl|"
    "tailscale|wg|weave|cali|nomad"
)
PSEUDO_MOUNT_PREFIXES = (
    "/run|/dev/shm|/sys|/proc|/snap|/var/lib/docker/overlay2|/var/lib/kubelet/pods"
)


def upgrade() -> None:
    # 1. The columns. All nullable, and that is load-bearing: a failed IF-MIB
    #    walk means no network reading at all, and every rate is unknown until
    #    there are two counter readings behind it.
    op.execute(
        """
        ALTER TABLE metrics
            ADD COLUMN cpu_usage_pct REAL,
            ADD COLUMN cpu_cores SMALLINT,
            ADD COLUMN ram_total_bytes BIGINT,
            ADD COLUMN ram_used_bytes BIGINT,
            ADD COLUMN ram_used_pct REAL,
            ADD COLUMN ram_available_bytes BIGINT,
            ADD COLUMN disk_root_total_bytes BIGINT,
            ADD COLUMN disk_root_used_bytes BIGINT,
            ADD COLUMN disk_root_used_pct REAL,
            ADD COLUMN disk_max_used_pct REAL,
            ADD COLUMN dio_read_bps DOUBLE PRECISION,
            ADD COLUMN dio_write_bps DOUBLE PRECISION,
            ADD COLUMN dio_read_iops REAL,
            ADD COLUMN dio_write_iops REAL,
            ADD COLUMN dio_read_bytes BIGINT,
            ADD COLUMN dio_write_bytes BIGINT,
            ADD COLUMN dio_reads BIGINT,
            ADD COLUMN dio_writes BIGINT,
            ADD COLUMN dio_busy_pct REAL,
            ADD COLUMN net_rx_bps DOUBLE PRECISION,
            ADD COLUMN net_tx_bps DOUBLE PRECISION,
            ADD COLUMN net_rx_bytes BIGINT,
            ADD COLUMN net_tx_bytes BIGINT,
            ADD COLUMN net_rx_util_pct REAL,
            ADD COLUMN net_tx_util_pct REAL,
            ADD COLUMN net_speed_bps BIGINT,
            ADD COLUMN interval_ms INTEGER
        """
    )

    # 2. Compressed chunks have to come apart before a full-table UPDATE. The
    #    compression policy puts them back on its next run.
    op.execute(
        """
        SELECT decompress_chunk(chunk, true)
        FROM show_chunks('metrics') AS chunk
        """
    )

    # 3. Backfill. Three of these columns are reductions over the arrays
    #    rather than copies of a scalar, so they arrive as subqueries.
    #
    #    They cannot be laterals in a FROM clause: Postgres does not let the
    #    FROM list of an UPDATE reference the row being updated, which is
    #    exactly what unnesting that row's own jsonb needs. Multi-column SET
    #    assignment does allow the correlation, and keeps one unnest per group
    #    rather than one per column.
    op.execute(
        f"""
        UPDATE metrics AS m SET
            cpu_usage_pct         = CAST(m.metrics->'cpu'->>'usage_percent' AS real),
            cpu_cores             = CAST(m.metrics->'cpu'->>'cores' AS smallint),
            ram_total_bytes       = CAST(m.metrics->'ram'->>'total_bytes' AS bigint),
            ram_used_bytes        = CAST(m.metrics->'ram'->>'used_bytes' AS bigint),
            ram_used_pct          = CAST(m.metrics->'ram'->>'used_percent' AS real),
            ram_available_bytes   = CAST(m.metrics->'ram'->>'available_bytes' AS bigint),
            dio_read_bps          = CAST(m.metrics->'disk_io'->>'read_bps' AS double precision),
            dio_write_bps         = CAST(m.metrics->'disk_io'->>'write_bps' AS double precision),
            dio_read_iops         = CAST(m.metrics->'disk_io'->>'read_iops' AS real),
            dio_write_iops        = CAST(m.metrics->'disk_io'->>'write_iops' AS real),
            dio_read_bytes        = CAST(m.metrics->'disk_io'->>'read_bytes' AS bigint),
            dio_write_bytes       = CAST(m.metrics->'disk_io'->>'write_bytes' AS bigint),
            dio_reads             = CAST(m.metrics->'disk_io'->>'reads' AS bigint),
            dio_writes            = CAST(m.metrics->'disk_io'->>'writes' AS bigint),
            interval_ms           = round(
                coalesce(
                    CAST(m.metrics->'disk_io'->>'interval_seconds' AS double precision),
                    CAST(m.metrics->'network'->>'interval_seconds' AS double precision)
                ) * 1000
            ),

            -- The root filesystem, the only mount worth keeping: the rest are
            -- overwhelmingly tmpfs, and tmpfs usage does not roll up into
            -- root's. A machine with no '/' row yields no subquery row at all,
            -- which sets all three to NULL - the honest answer.
            (disk_root_total_bytes, disk_root_used_bytes, disk_root_used_pct) = (
                SELECT
                    CAST(d->>'total_bytes' AS bigint),
                    CAST(d->>'used_bytes' AS bigint),
                    CAST(d->>'used_percent' AS real)
                FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(m.metrics->'disk') = 'array'
                         THEN m.metrics->'disk' ELSE CAST('[]' AS jsonb) END
                ) AS d
                WHERE d->>'mount' = '/'
                LIMIT 1
            ),

            -- The fullest real filesystem. The old query took this over every
            -- mount, so a full `/run/credentials/...` read as a full disk.
            disk_max_used_pct = (
                SELECT max(CAST(d->>'used_percent' AS real))
                FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(m.metrics->'disk') = 'array'
                         THEN m.metrics->'disk' ELSE CAST('[]' AS jsonb) END
                ) AS d
                WHERE d->>'mount' !~ '^({PSEUDO_MOUNT_PREFIXES})'
            ),

            dio_busy_pct = (
                SELECT max(CAST(d->>'busy_percent_1min' AS real))
                FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(m.metrics->'disk_io'->'devices') = 'array'
                         THEN m.metrics->'disk_io'->'devices'
                         ELSE CAST('[]' AS jsonb) END
                ) AS d
                WHERE CAST(d->>'counted' AS boolean)
            ),

            -- Physical interfaces only. A virtual interface never moves a
            -- packet off the machine by itself, so summing both counted the
            -- same traffic twice - severalfold on a Kubernetes node with one
            -- veth per pod. sum() ignores NULLs, so an interface that produced
            -- no rate this tick drops out of the rate totals by itself while
            -- still contributing its byte counters.
            (
                net_rx_bps, net_tx_bps, net_rx_bytes, net_tx_bytes,
                net_rx_util_pct, net_tx_util_pct, net_speed_bps
            ) = (
                SELECT
                    CAST(round(CAST(sum(CAST(i->>'rx_bps' AS double precision))
                                    AS numeric), 2) AS double precision),
                    CAST(round(CAST(sum(CAST(i->>'tx_bps' AS double precision))
                                    AS numeric), 2) AS double precision),
                    sum(CAST(i->>'rx_bytes' AS bigint)),
                    sum(CAST(i->>'tx_bytes' AS bigint)),
                    max(CAST(i->>'rx_util_percent' AS real)),
                    max(CAST(i->>'tx_util_percent' AS real)),
                    max(CAST(i->>'speed_bps' AS bigint))
                FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(m.metrics->'network'->'interfaces') = 'array'
                         THEN m.metrics->'network'->'interfaces'
                         ELSE CAST('[]' AS jsonb) END
                ) AS i
                WHERE i->>'name' !~ '^({VIRTUAL_IFACE_PREFIXES})'
            )
        """
    )

    # 4. The GIN index answered `@>`, `@?` and `@@`. Nothing ever asked one.
    #
    #    DROP COLUMN does not rewrite the existing tuples - it marks the column
    #    dropped and leaves its bytes in the heap - so the space this frees does
    #    not appear until each chunk is either compressed (which rewrites it) or
    #    dropped by the retention policy. Both happen within days. Run
    #    `VACUUM FULL metrics` to see it immediately, at the cost of an
    #    exclusive lock; that is a decision for whoever is deploying, so it is
    #    not done here.
    op.execute("DROP INDEX IF EXISTS metrics_gin_idx")
    op.execute("ALTER TABLE metrics DROP COLUMN metrics")

    # 5. Four hour chunks, down from a day. A chunk is only eligible for
    #    compression once its *end* is `compress_after` in the past, so day-long
    #    chunks against a three day retention would leave most of the window
    #    uncompressed. Existing chunks keep their interval and age out.
    op.execute("SELECT set_chunk_time_interval('metrics', INTERVAL '4 hours')")

    # 6. The rollups, WITH NO DATA: creating them populated would hold one
    #    transaction open across the whole history.
    #
    #    `materialized_only` is stated rather than left to the default, which
    #    has changed between TimescaleDB versions. It is what we want here: a
    #    rollup is only ever read for ranges past the raw window, so unioning it
    #    with the raw table on every query would be work spent on rows the query
    #    cannot reach anyway.
    op.execute(
        """
        CREATE MATERIALIZED VIEW metrics_1m
        WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
        SELECT
            time_bucket(INTERVAL '1 minute', ts) AS bucket,
            mac,
            count(*) AS samples,
            sum(cpu_usage_pct) AS cpu_usage_pct_sum,
            count(cpu_usage_pct) AS cpu_usage_pct_n,
            max(cpu_usage_pct) AS cpu_usage_pct_max,
            sum(ram_used_pct) AS ram_used_pct_sum,
            count(ram_used_pct) AS ram_used_pct_n,
            max(ram_used_pct) AS ram_used_pct_max,
            sum(ram_used_bytes) AS ram_used_bytes_sum,
            count(ram_used_bytes) AS ram_used_bytes_n,
            max(ram_used_bytes) AS ram_used_bytes_max,
            sum(disk_root_used_pct) AS disk_root_used_pct_sum,
            count(disk_root_used_pct) AS disk_root_used_pct_n,
            max(disk_root_used_pct) AS disk_root_used_pct_max,
            sum(disk_max_used_pct) AS disk_max_used_pct_sum,
            count(disk_max_used_pct) AS disk_max_used_pct_n,
            max(disk_max_used_pct) AS disk_max_used_pct_max,
            sum(net_rx_bps) AS net_rx_bps_sum,
            count(net_rx_bps) AS net_rx_bps_n,
            max(net_rx_bps) AS net_rx_bps_max,
            sum(net_tx_bps) AS net_tx_bps_sum,
            count(net_tx_bps) AS net_tx_bps_n,
            max(net_tx_bps) AS net_tx_bps_max,
            sum(dio_read_bps) AS dio_read_bps_sum,
            count(dio_read_bps) AS dio_read_bps_n,
            max(dio_read_bps) AS dio_read_bps_max,
            sum(dio_write_bps) AS dio_write_bps_sum,
            count(dio_write_bps) AS dio_write_bps_n,
            max(dio_write_bps) AS dio_write_bps_max,
            sum(dio_read_iops) AS dio_read_iops_sum,
            count(dio_read_iops) AS dio_read_iops_n,
            max(dio_read_iops) AS dio_read_iops_max,
            sum(dio_write_iops) AS dio_write_iops_sum,
            count(dio_write_iops) AS dio_write_iops_n,
            max(dio_write_iops) AS dio_write_iops_max,
            sum(dio_busy_pct) AS dio_busy_pct_sum,
            count(dio_busy_pct) AS dio_busy_pct_n,
            max(dio_busy_pct) AS dio_busy_pct_max,
            max(net_rx_bytes) AS net_rx_bytes_max,
            max(net_tx_bytes) AS net_tx_bytes_max,
            max(dio_read_bytes) AS dio_read_bytes_max,
            max(dio_write_bytes) AS dio_write_bytes_max,
            max(cpu_cores) AS cpu_cores_max,
            max(ram_total_bytes) AS ram_total_bytes_max,
            max(disk_root_total_bytes) AS disk_root_total_bytes_max,
            max(net_speed_bps) AS net_speed_bps_max
        FROM metrics
        GROUP BY bucket, mac
        WITH NO DATA
        """
    )
    op.execute(
        """
        CREATE MATERIALIZED VIEW metrics_1h
        WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
        SELECT
            time_bucket(INTERVAL '1 hour', ts) AS bucket,
            mac,
            count(*) AS samples,
            sum(cpu_usage_pct) AS cpu_usage_pct_sum,
            count(cpu_usage_pct) AS cpu_usage_pct_n,
            max(cpu_usage_pct) AS cpu_usage_pct_max,
            sum(ram_used_pct) AS ram_used_pct_sum,
            count(ram_used_pct) AS ram_used_pct_n,
            max(ram_used_pct) AS ram_used_pct_max,
            sum(ram_used_bytes) AS ram_used_bytes_sum,
            count(ram_used_bytes) AS ram_used_bytes_n,
            max(ram_used_bytes) AS ram_used_bytes_max,
            sum(disk_root_used_pct) AS disk_root_used_pct_sum,
            count(disk_root_used_pct) AS disk_root_used_pct_n,
            max(disk_root_used_pct) AS disk_root_used_pct_max,
            sum(disk_max_used_pct) AS disk_max_used_pct_sum,
            count(disk_max_used_pct) AS disk_max_used_pct_n,
            max(disk_max_used_pct) AS disk_max_used_pct_max,
            sum(net_rx_bps) AS net_rx_bps_sum,
            count(net_rx_bps) AS net_rx_bps_n,
            max(net_rx_bps) AS net_rx_bps_max,
            sum(net_tx_bps) AS net_tx_bps_sum,
            count(net_tx_bps) AS net_tx_bps_n,
            max(net_tx_bps) AS net_tx_bps_max,
            sum(dio_read_bps) AS dio_read_bps_sum,
            count(dio_read_bps) AS dio_read_bps_n,
            max(dio_read_bps) AS dio_read_bps_max,
            sum(dio_write_bps) AS dio_write_bps_sum,
            count(dio_write_bps) AS dio_write_bps_n,
            max(dio_write_bps) AS dio_write_bps_max,
            sum(dio_read_iops) AS dio_read_iops_sum,
            count(dio_read_iops) AS dio_read_iops_n,
            max(dio_read_iops) AS dio_read_iops_max,
            sum(dio_write_iops) AS dio_write_iops_sum,
            count(dio_write_iops) AS dio_write_iops_n,
            max(dio_write_iops) AS dio_write_iops_max,
            sum(dio_busy_pct) AS dio_busy_pct_sum,
            count(dio_busy_pct) AS dio_busy_pct_n,
            max(dio_busy_pct) AS dio_busy_pct_max,
            max(net_rx_bytes) AS net_rx_bytes_max,
            max(net_tx_bytes) AS net_tx_bytes_max,
            max(dio_read_bytes) AS dio_read_bytes_max,
            max(dio_write_bytes) AS dio_write_bytes_max,
            max(cpu_cores) AS cpu_cores_max,
            max(ram_total_bytes) AS ram_total_bytes_max,
            max(disk_root_total_bytes) AS disk_root_total_bytes_max,
            max(net_speed_bps) AS net_speed_bps_max
        FROM metrics
        GROUP BY bucket, mac
        WITH NO DATA
        """
    )

    for view in ("metrics_1m", "metrics_1h"):
        op.execute(f"ALTER MATERIALIZED VIEW {view} SET (timescaledb.compress = true)")

    # Populated before the shortened retention can drop the raw rows out from
    # under them. Without this, a chart asking for more than three days comes
    # back empty rather than coarse. `refresh_continuous_aggregate` cannot run
    # inside a transaction block, hence the COMMIT.
    op.execute("COMMIT")
    for view in ("metrics_1m", "metrics_1h"):
        op.execute(f"CALL refresh_continuous_aggregate('{view}', NULL, NULL)")


def downgrade() -> None:
    """Reversible as schema, not as data.

    The jsonb column comes back empty. Its per-mount, per-device and
    per-interface arrays were never stored as columns, so there is nothing to
    reconstruct them from, and inventing a one-mount payload would be a worse
    outcome than an honest empty object.
    """
    for view in ("metrics_1h", "metrics_1m"):
        op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {view}")

    op.execute("SELECT set_chunk_time_interval('metrics', INTERVAL '1 day')")
    op.execute(
        """
        SELECT decompress_chunk(chunk, true)
        FROM show_chunks('metrics') AS chunk
        """
    )
    op.execute("ALTER TABLE metrics ADD COLUMN metrics JSONB")
    op.execute("UPDATE metrics SET metrics = CAST('{}' AS jsonb)")
    op.execute("ALTER TABLE metrics ALTER COLUMN metrics SET NOT NULL")
    op.execute(
        "CREATE INDEX metrics_gin_idx ON metrics USING gin (metrics jsonb_path_ops)"
    )
    op.execute(
        """
        ALTER TABLE metrics
            DROP COLUMN cpu_usage_pct,
            DROP COLUMN cpu_cores,
            DROP COLUMN ram_total_bytes,
            DROP COLUMN ram_used_bytes,
            DROP COLUMN ram_used_pct,
            DROP COLUMN ram_available_bytes,
            DROP COLUMN disk_root_total_bytes,
            DROP COLUMN disk_root_used_bytes,
            DROP COLUMN disk_root_used_pct,
            DROP COLUMN disk_max_used_pct,
            DROP COLUMN dio_read_bps,
            DROP COLUMN dio_write_bps,
            DROP COLUMN dio_read_iops,
            DROP COLUMN dio_write_iops,
            DROP COLUMN dio_read_bytes,
            DROP COLUMN dio_write_bytes,
            DROP COLUMN dio_reads,
            DROP COLUMN dio_writes,
            DROP COLUMN dio_busy_pct,
            DROP COLUMN net_rx_bps,
            DROP COLUMN net_tx_bps,
            DROP COLUMN net_rx_bytes,
            DROP COLUMN net_tx_bytes,
            DROP COLUMN net_rx_util_pct,
            DROP COLUMN net_tx_util_pct,
            DROP COLUMN net_speed_bps,
            DROP COLUMN interval_ms
        """
    )
