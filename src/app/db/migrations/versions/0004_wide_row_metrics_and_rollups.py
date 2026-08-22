"""Wide-row metrics: scalar columns, no jsonb, plus the 1m and 1h rollups"""
from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# Frozen copies of the settings defaults as they stood here, so the backfill
# stays reproducible after those defaults move on.
VIRTUAL_IFACE_PREFIXES = (
    "veth|cni|flannel|docker|br-|virbr|kube-ipvs|tunl|gre|sit|ip6tnl|"
    "tailscale|wg|weave|cali|nomad"
)
PSEUDO_MOUNT_PREFIXES = (
    "/run|/dev/shm|/sys|/proc|/snap|/var/lib/docker/overlay2|/var/lib/kubelet/pods"
)


def upgrade() -> None:
    # 1. The columns, all nullable: a failed walk has no reading, and a rate
    #    needs two counter readings.
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

    # 2. Compressed chunks must come apart before a full-table UPDATE; the
    #    policy recompresses them on its next run.
    op.execute(
        """
        SELECT decompress_chunk(chunk, true)
        FROM show_chunks('metrics') AS chunk
        """
    )

    # 3. Backfill. Three columns are reductions over the arrays, so they are
    #    subqueries — an UPDATE's FROM list cannot reference the row being
    #    updated, but multi-column SET can.
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

    # 4. The GIN index answered queries nothing ever asked. DROP COLUMN leaves
    #    the bytes in the heap until a chunk is compressed or dropped, so the
    #    space returns within days; `VACUUM FULL` is the deployer's call.
    op.execute("DROP INDEX IF EXISTS metrics_gin_idx")
    op.execute("ALTER TABLE metrics DROP COLUMN metrics")

    # 5. Four hour chunks: a chunk compresses only once its end is
    #    `compress_after` old. Existing chunks age out at their own interval.
    op.execute("SELECT set_chunk_time_interval('metrics', INTERVAL '4 hours')")

    # 6. The rollups, WITH NO DATA — populating them here would hold one
    #    transaction open across all history. `materialized_only` is stated
    #    because its default changed between TimescaleDB versions.
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

    # Populated before the shortened retention drops the raw rows.
    # `refresh_continuous_aggregate` cannot run in a transaction, hence COMMIT.
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
