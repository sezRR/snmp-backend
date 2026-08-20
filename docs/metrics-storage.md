# Metric storage: design, policies and stress-test findings

How telemetry gets from an SNMP walk into TimescaleDB, what happens to it there,
and what a 37-machine / 90-day load actually measured. Written 2026-08-20 against
TimescaleDB 2.22.1-pg17.

Companion to the "Why the metrics table is wide" section of the README, which
carries the short version. This document is the working detail.

---

## 1. Shape

`metrics` is a hypertable of **29 columns: `ts`, `mac`, and 27 scalars** — one per
metric. It previously held `ts`, `mac` and a single `metrics jsonb` blob.

```
ts                     timestamptz  NOT NULL
mac                    macaddr      NOT NULL  REFERENCES machines(mac) ON DELETE CASCADE

cpu_usage_pct          real         cpu_cores              smallint
ram_total_bytes        bigint       ram_used_bytes         bigint
ram_used_pct           real         ram_available_bytes    bigint
disk_root_total_bytes  bigint       disk_root_used_bytes   bigint
disk_root_used_pct     real         disk_max_used_pct      real
dio_read_bps           float8       dio_write_bps          float8
dio_read_iops          real         dio_write_iops         real
dio_read_bytes         bigint       dio_write_bytes        bigint
dio_reads              bigint       dio_writes             bigint
dio_busy_pct           real
net_rx_bps             float8       net_tx_bps             float8
net_rx_bytes           bigint       net_tx_bytes           bigint
net_rx_util_pct        real         net_tx_util_pct        real
net_speed_bps          bigint       interval_ms            integer
```

Indexes: `metrics_ts_idx (ts DESC)`, `metrics_mac_ts_idx (mac, ts DESC)`. The old
`metrics_gin_idx` (`jsonb_path_ops`) was dropped — it answered only `@>`, `@?`
and `@@`, which no query in this repo or the frontend ever issued, while costing
0.8x the heap.

**Every metric column is nullable, and that is load-bearing.** A failed IF-MIB
walk means no network reading at all; the `disk_io` section is absent entirely
when DISKIO is disabled or fails; and every `*_bps` / `*_iops` is unknown on the
first sample after a restart because a rate needs two counter reads behind it.
NULL means "this sample has nothing to say", and it propagates correctly all the
way through the rollups (see §6).

**Unit trap:** every `*_bps` column is **bytes**/s except `net_speed_bps`, which
is **bits**/s — it is a link speed, not a throughput.

### Why the per-entity arrays are gone

The jsonb payload averaged 4817 B on the real Kubernetes node, and **73% of that
was three arrays nothing queried**:

| section | bytes | content |
|---|---|---|
| `disk_io` | 1649 | 9 devices, 8 of them `loop*` carrying zeros with `counted: false` |
| `network` | 1267 | 12 interfaces, 9 of them ephemeral `veth*` / `cni0` / `flannel.1` |
| `disk` | 603 | 11 mounts, 10 of them tmpfs under `/run` |
| `ram` | 118 | |
| `cpu` | 35 | |

Their members are unstable by nature — one veth per pod, renamed on every restart
— which is what rules out a column per entity and makes storing them a poor trade
against keeping them live.

They are still **collected and streamed**. `/metrics/latest` and the SSE stream
carry every mount, device and interface; only storage is scalar. That is not an
optimisation — the frontend's `DiskCard` renders a table of every mount, so
without the live path it would degrade to a single root row.

---

## 2. How data is generated

### 2.1 The real path

```
pysnmp GETBULK walks                       src/app/services/snmp/pysnmp_backend.py
  -> nested payload {cpu, ram, disk[], disk_io{devices[]}, network{interfaces[]}}
  -> flatten(payload, pseudo_mount_prefixes=, virtual_iface_prefixes=)
                                           src/app/services/snmp/flatten.py:120
  -> one dict per machine, every COLUMNS key present, None where absent
  -> metrics_repo.insert_many              src/app/db/metrics.py:43
  -> collector.last_samples[mac] = sample  src/app/services/collector.py:279
  -> bus.publish(sample)  (full arrays)    src/app/services/collector.py:280
```

The collector ticks every `COLLECTOR_INTERVAL_SECONDS` (default 5) and writes one
row per machine per tick. `insert_many` goes through the SQLAlchemy Core table so
psycopg2's `executemany_mode="values_plus_batch"` folds the whole batch into one
`execute_values` round trip.

`flatten` is **pure and total** — every key in `COLUMNS` is present in the result,
`None` where the source section is missing. It is the single place that knows the
payload-to-column mapping, and `nest()` (`flatten.py:257`) is its exact inverse,
used to rebuild the nested wire shape from a stored row. `flatten(nest(row)) ==
row` is asserted in `tests/test_flatten.py`.

Two columns are **reductions, not copies**, and deliberately disagree with the
scalars the old payload carried:

- `net_rx_bps` / `net_tx_bps` / `net_rx_bytes` / `net_tx_bytes` are summed over
  **physical interfaces only** (`is_physical_interface`, `flatten.py:77`). The old
  `network.rx_bps` summed every up, non-loopback interface, so one packet crossing
  a veth, a bridge and the uplink counted three times. Measured on the k8s node:
  46,202 B/s reported against 23,635 B/s actually crossing `eth0`.
- `disk_max_used_pct` is the max over **non-pseudo mounts** (`is_pseudo_mount`,
  `flatten.py:67`). The old query took the max over every mount, so a full
  `/run/credentials/...` read as a full disk.

Both prefix lists are settings (`METRICS_VIRTUAL_IFACE_PREFIXES`,
`METRICS_PSEUDO_MOUNT_PREFIXES`), because `/tmp` is a real filesystem on some
hosts and the right answer is site-specific. Migration 0004 freezes its own copies
so the backfill stays reproducible after the defaults move on.

### 2.2 The stress-test path

Ninety days at 5 s for 37 machines is **57.5M raw rows** — about 18 GB before
compression. Raw retention is three days, so all but the last three days exist
only to be aggregated and then dropped. The loader therefore works in **30 batches
of 3 days**, each of which:

1. `INSERT` its slice, generated in SQL from `generate_series` crossed with
   `machines`, with per-machine phase offsets so no two machines are identical;
2. `CALL refresh_continuous_aggregate` on both rollups over exactly that slice;
3. `SELECT drop_chunks('metrics', older_than => <batch end>)` for every batch
   older than the retention window.

Peak disk stays at one batch (~600 MB) instead of 18 GB. Total wall clock ~23 min:
~37 s insert, ~8.5 s for both refreshes, ~1 s to drop per batch.

The generated values drift continuously — sine components at several periods plus
`random()` noise, a disk-fill ramp across the whole 90 days, and monotonic
cumulative counters derived from a global sample index so they stay monotonic
across batch boundaries. **This matters for the storage numbers**: replaying a
fixed payload compresses far better than real telemetry does, and an earlier
measurement that did so overstated the compression ratio (4.3x against the 3.75x
real drift gives).

Gaps are injected deliberately — 1 sample in 997 has the whole `disk_io` section
NULL, 1 in 1993 has `network` NULL — to exercise the nullable path end to end.

The 30 synthetic machines are inserted **disabled**, so the collector does not
start polling 30 simulated agents and writing live rows on top of the historic
set. Flip `enabled` to poll them.

Scripts live in the session scratchpad, not in the repo; `scripts/seed_dev.py`
remains the supported way to seed a dev database.

---

## 3. Hypertable and chunking

| relation | chunk interval | why |
|---|---|---|
| `metrics` | **4 hours** | `METRICS_CHUNK_INTERVAL_HOURS` |
| `metrics_1m` | **1 day** | `ROLLUP_1M_CHUNK_INTERVAL`, `policies.py:49` |
| `metrics_1h` | **30 days** | `ROLLUP_1H_CHUNK_INTERVAL`, `policies.py:50` |

Raw chunks are 4 hours, down from a day, because **a chunk is only eligible for
compression once its *end* is `compress_after` in the past**. Day-long chunks
against a three-day retention would leave most of the window uncompressed. At 4 h
chunks with `compress_after = 8h` a chunk compresses at ~12 h of age, so ~60 of
the 72 retained hours are compressed.

Measured cost of the smaller chunk: **3.4%** (87.4 B/row against 84.5 B/row on
identical rows). Cheap for what it buys.

The rollup intervals are **not** defaults. TimescaleDB sizes a continuous
aggregate's chunks at ten times its source's, so both rollups inherited 40 hours
from the raw table's 4. That is roughly right for the minute rollup and badly
wrong for the hourly one: 40 hours of hourly buckets is 40 rows per machine per
chunk, so a 730-day retention would accumulate **~440 chunks** whose per-chunk
overhead dwarfs what they hold, and a full-window query would plan across every
one. Sized by content instead — a day of minute buckets is 1440 rows/machine, a
month of hourly buckets is 720 — `metrics_1h` holds 90 days in **6 chunks**.

All three intervals are re-asserted on every boot by
`_apply_chunk_intervals` (`policies.py:162`). `set_chunk_time_interval` only
affects chunks created from that point on; existing chunks keep theirs and age
out, which is what makes it safe to re-run.

---

## 4. Compression

Columnar compression, identical settings on all three relations:

```
compress_segmentby = 'mac'
compress_orderby   = 'ts DESC'      -- metrics
compress_orderby   = 'bucket ASC'   -- both rollups (TimescaleDB's default)
```

| policy | window | source |
|---|---|---|
| `metrics` | 8 hours | `METRICS_COMPRESS_AFTER_HOURS` |
| `metrics_1m` | 7 days | `ROLLUP_1M_COMPRESS_AFTER`, `policies.py:36` |
| `metrics_1h` | 30 days | `ROLLUP_1H_COMPRESS_AFTER`, `policies.py:37` |

The rollup windows are module constants rather than settings: unlike the raw
window they are not a storage/detail tradeoff anyone tunes, just far enough back
that nothing is still writing to the chunk.

### Measured

| | uncompressed | compressed | ratio |
|---|---|---|---|
| `metrics` row | 317 B | **83 B** | 3.75x |
| `metrics_1m` row | 466 B | **146-163 B** | ~2.9x |
| old jsonb + GIN row | 1930 B | ~284 B | 6.8x |

Compression earns *less* on the wide row than on the blob, and that is expected:
generic LZ over repetitive text has more to remove than delta-delta over already
narrow scalars. It is also the wrong number to optimise — the row is 6x narrower
before either of them runs.

Per-row compressed cost held at **83.2-83.4 B across every compressed chunk at 37
machines**, against 84.5 B measured at 7. Compression is flat in fleet size.

### Trap: backfilling into a compressed chunk

Inserting into an already-compressed chunk parks the new rows in that chunk's
**uncompressed area**, and calling `compress_chunk` on it again does not reliably
fold them in. One backfilled chunk reported `is_compressed = t` while sitting at
**334 B/row — 4x its clean size** — until it was fully decompressed and
recompressed, at which point it dropped to 83.4 B/row.

Any bulk write against historical `metrics` must `decompress_chunk` the affected
chunks first. Migration 0004 does exactly this before its backfill.

---

## 5. Retention

| relation | window | setting |
|---|---|---|
| `metrics` | **3 days** | `METRICS_RETENTION_DAYS` |
| `metrics_1m` | **90 days** | `METRICS_ROLLUP_1M_RETENTION_DAYS` |
| `metrics_1h` | **730 days** | `METRICS_ROLLUP_1H_RETENTION_DAYS` |

The raw window is short on purpose: it exists for live troubleshooting, and
anything older is served from the rollups. Raise the **rollup** retentions, not
`METRICS_RETENTION_DAYS`, if history goes missing.

`METRICS_ROLLUP_REFRESH_LAG_DAYS` (default 2) is the refresh `start_offset`. It
**must stay shorter than raw retention**, or a refresh is asked to re-read chunks
retention has already dropped and the rollup develops holes exactly where the raw
data used to be. `_refresh_lag_days` (`policies.py:62`) clamps it to 75% of
retention and logs a warning rather than letting that happen silently.

All policies live in `src/app/db/policies.py`, not in Alembic, and are **dropped
and re-added on every boot**. A migration would pin whichever window happened to
be configured the day it was written, and `add_*_policy(..., if_not_exists =>
TRUE)` would then keep that first window and quietly ignore the changed setting.
Failures are logged, not raised — the app is functional without them, but an
unnoticed missing retention policy is how a disk fills up.

---

## 6. Continuous aggregates

Two, both **built directly on raw `metrics`**:

| view | bucket | end_offset | schedule | mat. table | chunks (90 d) |
|---|---|---|---|---|---|
| `metrics_1m` | 1 minute | 1 minute | 1 minute | `_materialized_hypertable_3` | 90 |
| `metrics_1h` | 1 hour | 1 hour | 10 minutes | `_materialized_hypertable_4` | 6 |

Both are `finalized`, `compression_enabled`, and **`materialized_only = true`**.
That last is stated explicitly in the migration rather than left to the default,
which changed in TimescaleDB 2.13. It is what we want: a rollup is only ever read
for ranges past the raw window, so unioning it with the raw table on every query
would be work spent on rows the query cannot reach anyway. The cost is that the
in-flight bucket is not visible — `metrics_1m` runs ~2-3 min behind, `metrics_1h`
up to ~70 min behind.

### Sums and counts, not averages

Each of 12 gauges contributes **three** columns — `<col>_sum`, `<col>_n`,
`<col>_max` — and 8 counters/constants contribute `<col>_max` only. 47 columns per
view. Spec in `src/app/db/rollups.py`.

Re-bucketing an average is only correct when every bucket carried the same number
of samples, and they do not: a failed poll writes no row at all, and any single
column can be NULL on its own. Keeping numerator and denominator apart makes
`sum(x_sum) / nullif(sum(x_n), 0)` exact at any bucket width.

Verified at 37 machines over 24 h: raw, `metrics_1m` and `metrics_1h` all report
**643,400 samples**, `cpu_avg` 33.132250 / 33.132409 / 33.132226 (float32
accumulation order), identical `cpu_max`. NULL denominators propagate exactly —
`sum(dio_read_bps_n)` equals `count(dio_read_bps)` over raw to the row.

Continuous aggregates were **impossible over the old jsonb shape**: the disk
figure needed `jsonb_array_elements`, and a continuous aggregate rejects
set-returning functions. Scalar columns delete that problem outright.

The aggregate definitions in migration 0004 are **literal SQL, not generated from
`rollups.py`**. A migration is a snapshot: if it read that module, editing the
spec would silently change what an old revision replays as, and a database rebuilt
from scratch would diverge from one migrated forward.

### Hierarchical continuous aggregates: none exist, and one probably should

Confirmed against the catalog — both views have `parent_mat_hypertable_id IS
NULL` and `raw_hypertable_id = 1` (`metrics`). `metrics_1h` re-reads raw rows
rather than folding up `metrics_1m`.

Measured cost of that choice, same 1-hour rollup work over the same window:

| source | ms |
|---|---|
| raw `metrics` (today) | 750 |
| `metrics_1m` (hierarchical) | **215** |

**3.5x cheaper**, and *exact* — because the rollup stores sums and counts, folding
1-minute buckets into 1-hour ones is `sum(sum)`, `sum(n)`, `max(max)`, not an
average of averages. Over 2585 bucket/machine pairs, **2583 agreed to the bit**.

The 2 that differed were both the **current hour**, on the only two live-polled
machines, short by 29 samples — precisely `metrics_1m`'s ~2.5 min refresh lag.
That is the one real cost of stacking: a hierarchical view inherits its parent's
staleness.

Here that cost is already absorbed. `metrics_1h` has `end_offset = 1 hour`, so by
the time it materialises an hour bucket, `metrics_1m` finished that bucket ~57
minutes earlier. **Hierarchical would be strictly better: same numbers, 3.5x less
refresh work, no freshness loss.**

Not changed, because it is a schema change (drop and recreate `metrics_1h`) and
was not in scope. **It is much cheaper to do now than later**: `metrics_1h` can
currently be rebuilt in full from `metrics_1m`, since both start on the same date.
Once `metrics_1h` holds history older than `metrics_1m`'s 90-day window, that
history has no other copy and rebuilding would destroy it.

---

## 7. Read path

`GET /metrics/stats` takes an explicit window — `?from=` and `?to=`, both
required, ISO 8601, naive read as UTC — and answers it from whichever source
still holds it. What decides the source is how far back `from` reaches, not how
long the window is: an hour-long window six months ago comes from a rollup,
because the raw rows for it are long gone (`rollups.hours_back`,
`rollups.pick_source`):

| `from` reaches back | source | min bucket |
|---|---|---|
| <= `METRICS_RETENTION_DAYS * 24` (72) | `metrics` | 1 second |
| <= `METRICS_ROLLUP_1M_RETENTION_DAYS * 24` (2160) | `metrics_1m` | 1 minute |
| otherwise | `metrics_1h` | 1 hour |

`?mac=` is required and repeatable, up to `MAX_MACS` (10). Rows are buckets
times machines and the cap below counts buckets alone, so the endpoint makes the
caller name its machines rather than defaulting to the whole fleet.

`?bucket=` is a preset, not a free-form interval: `30s`, `1m`, `5m`, `15m`,
`1h`, `6h`, `1d`, `7d` (`models.metric.StatsBucket`). It used to be any string,
cast to `interval` in SQL — so `?bucket=asgg` reached Postgres and came back a
500 out of the driver rather than a 422 out of validation.

### The bucket a request actually gets

`?bucket=` is optional, and there is no fixed default: a single width cannot
serve a range that runs from an hour to two years — five minutes is twelve
points over an hour and eight thousand over a month. Omitted, it is **fitted**
to the window, aiming for `TARGET_POINTS` (360) points — a chart's worth of
detail at a payload a browser can hold several of
(`StatsBucket.at_least(span / TARGET_POINTS)`):

| window | fitted bucket | points |
|---|---|---|
| 1h | `30s` | 120 |
| 6h | `1m` | 360 |
| 24h | `5m` | 288 |
| 7d | `1h` | 168 |
| 30d | `6h` | 120 |
| 90d | `6h` | 360 |
| 2y | `7d` | 104 |

The ladder is lumpy — 30 days and 90 days both land on `6h` — because the
presets are the ones a human would pick off a dropdown, not a continuous scale.
A window between two presets rounds *up*, so the count lands under the target
rather than over it.

Fitted or asked for, the width is then **floored** at what the source can
resolve — the same `at_least` call, against `SOURCE_MIN_BUCKET_SECONDS`. The
floor resolves to a preset rather than to the source's own interval string,
which is what makes the result nameable: `1h` is a bucket a caller can ask for
again, `1 hour` was only ever a substitution inside the query.

Both steps change the width away from what was requested, so the answer says
what it used:

```
X-Metrics-Bucket: 15m
X-Metrics-Source: metrics_1m
```

Both are listed in `expose_headers` on the CORS middleware (`main.py`) — a
browser cannot read a response header it was not handed.

Two rejections happen before the query runs, both 422: `to` at or before
`from`, and a window covering more than `MAX_BUCKETS` (5000) buckets. The bucket
count is measured on the effective width, so an explicit `?bucket=30s` over two
years is judged as the 17538 hourly buckets it would actually return. A fitted
bucket cannot trip that cap, since `TARGET_POINTS` is well under it.

`stats_projection` emits `avg(col)` / `max(col)` for raw and
`sum(col_sum)/nullif(sum(col_n),0)` / `max(col_max)` for a rollup, under the same
output names either way — `MetricStatsRow` is the wire contract of
`/metrics/stats` and predates the wide row, so its field names are kept exactly.

The requested bucket is **floored** at what the source can resolve, in SQL:

```sql
time_bucket(
    greatest(CAST(CAST(:bucket AS text) AS interval),
             CAST(CAST(:min_bucket AS text) AS interval)),
    m.<time_column>
)
```

Asking a one-hour rollup for five-minute buckets does not fail, it returns one
populated bucket in twelve — which a chart draws as an outage rather than as a
resolution limit.

Casts are spelled `CAST(x AS type)` throughout rather than `x::type`, because
SQLAlchemy's `text()` reads a bare `:` as the start of a bind parameter and would
swallow the type name.

### `/metrics/latest` is live-first

Served from `collector.last_samples`, falling back to a DB-reconstructed row via
`nest()` for any machine the collector has not sampled since this process
started. The live cache is what keeps the per-mount / per-device / per-interface
arrays in the response; the DB fallback reconstructs to root-only, which is a gap
of at most one interval after a restart, not a bug.

`last_samples` is pruned in exactly the two places `statuses` is — the stale-mac
sweep and `deregister_machine` — or a deleted machine would keep showing a
sample.

### Materialized views

The only materialized views in the schema are the two continuous aggregates. There
are no plain `MATERIALIZED VIEW`s and nothing is refreshed by hand outside the
migration's one-shot backfill.

---

## 8. Bugs found and fixed during the stress test

### 8.1 Rollup queries ignored the requested bucket width

`GROUP BY bucket` — Postgres resolves an ambiguous `GROUP BY` name to the **input**
column, not the output alias. Raw `metrics` has no column called `bucket`, so it
worked; `metrics_1m` and `metrics_1h` do, so the query grouped by the rollup's own
bucket and silently returned the source's resolution.

The frontend's **7d chart** was the victim:

| | before | after |
|---|---|---|
| rows | 20,167 | **343** |
| payload | 14.8 MB | **252 KB** |
| latency | 243 ms | **27 ms** |

`ORDER BY` resolves the *other* way, to the output column, so spelling either as a
name makes the two disagree. Fixed by using ordinals in both —
`src/app/db/metrics.py:129`.

### 8.2 `/metrics/latest` full-scanned the retention window

`mac` is projected as text, so an unqualified `ORDER BY mac, ts DESC` sorted on
`(mac)::text`, matching no index. Sequential scan plus external merge sorts on
disk to return one row per machine.

At 37 machines and 3 days of raw: **1190 ms and 91 MB of on-disk sort** for 37
rows. Qualifying the table alias makes it a SkipScan per chunk: **1.84 ms**.
646x, and it degrades linearly with retention. `src/app/db/metrics.py:143`.

### 8.3 Rollups inherited a 40-hour chunk interval

Covered in §3. `metrics_1h` was heading for ~440 chunks at its 730-day retention;
it now holds 90 days in 6.

---

## 9. Stress-test results

37 machines (7 real/seeded + 30 synthetic), 90 days of history, raw aged down to
its 3-day window by the retention policy without intervention.

### Resident size

| relation | rows | resident | per machine |
|---|---|---|---|
| `metrics` (3 d) | 1,951,749 | 278 MB | **7.7 MB** |
| `metrics_1m` (90 d) | 4,794,103 | 745 MB | **20 MB** |
| `metrics_1h` (90 d) | 78,810 | 23 MB | 630 kB |
| **database total** | | **1066 MB** | |

At the full 730-day hourly retention that is roughly **31 MB per machine**, against
~147 MB for the previous 30-day jsonb window — **4.6x less, while gaining 90 days
of minute data and two years of hourly data where there was none.**

The 90-day minute rollup is the largest single consumer (20 of the 31 MB). Halving
`METRICS_ROLLUP_1M_RETENTION_DAYS` halves it.

At 500 machines: ~16 GB, against ~74 GB.

### Query latency, exactly as the frontend issues it

`machines/$mac.tsx` always passes `mac`, so every stats call is single-machine.

| frontend range | source | ms |
|---|---|---|
| 15m / 30 s | `metrics` | 5.0 |
| 1h / 1 min | `metrics` | 5.8 |
| 6h / 5 min | `metrics` | 32.4 |
| 24h / 15 min | `metrics` | 39.6 |
| 7d / 1 hour | `metrics_1m` | 100.7 |

Fleet-wide (no `mac`, not issued by any current caller) is the heavy path — 24 h
raw 490 ms, 30 d rollup 1.4 s — but those return 7-20 MB, so payload dominates
rather than the scan.

### Latent scaling limit

`pick_source` routes on **range only, never bucket width**. A 5-minute bucket over
24 h reads raw when `metrics_1m` holds the same answer 17x cheaper (72 ms against
4.2 ms). Fleet-wide 24 h raw was 490 ms at 37 machines and scales linearly —
roughly 6.6 s at 500.

Not changed: fixing it costs freshness, because `materialized_only = true` means
`metrics_1m` trails ~2-3 min. No current caller hits it.

---

## 10. `stats_agg` evaluation

Asked whether TimescaleDB Toolkit's `stats_agg` would improve the rollups.
**Measured answer: no, on both axes.**

**It is not in this image.** `timescale/timescaledb:2.22.1-pg17` ships only
`timescaledb`. Toolkit lives in `timescale/timescaledb-ha` — **835 MB -> 2.54 GB**,
and it drags TimescaleDB 2.22.1 -> 2.29.2 with it.

Both designs built side by side over 1,278,720 raw rows (37 machines x 2 days at
5 s), same buckets, same 12 gauges, same 8 max-only columns:

| 1-minute rollup | uncompressed | compressed | ratio |
|---|---|---|---|
| `sum`/`count`/`max` (current) | 464.9 B/row | **157.2 B/row** | 2.96x |
| `stats_agg` + `max` | 893.1 B/row | **493.5 B/row** | 1.81x |

**3.1x more storage compressed**, for two compounding reasons:

- one `StatsSummary1D` is **48 bytes** against 12 for `sum` + `count` — it carries
  higher moments nothing asked for;
- it compresses *worse* (1.81x against 2.96x), because a fixed-size binary state
  is opaque to the columnar encoders and falls back to generic LZ, while
  `sum`/`count`/`max` are native floats and ints that get delta and gorilla
  encoding.

Query cost, re-bucketing 2 days to 1 hour across 9 public metrics:

| | ms |
|---|---|
| `sum(x_sum)/nullif(sum(x_n),0)` | **18** |
| `average(rollup(x_stats))` | **114** |

**6.3x slower** — a Rust custom aggregate deserialising 48 bytes per input row
against two builtin `sum()`s over native columns.

Results are otherwise identical (max delta 1.8e-05 on CPU, float32 epsilon;
3.3e-11 on `net_rx_bps`) and NULL handling matches exactly: 1,277,425 non-null raw
values, `sum(x_n)` = 1,277,425, `sum(num_vals(x_stats))` = 1,277,425.

It does not even collapse the triple: `StatsSummary1D` holds no extremes, so `max`
stays a separate column. It replaces two columns with one that is 4x wider.

### What would justify the Toolkit dependency

- **`percentile_agg` / `uddsketch`** — p95/p99 per bucket. `sum`/`count`/`max`
  cannot answer that at any bucket width; it is the one thing genuinely impossible
  today. Worth deciding **now** rather than later, for the same reason as §6: once
  retention drops raw, the rollups are the only copy of history, and adding a
  column means dropping and re-materialising them.
- **`counter_agg`** — reset-safe counter deltas. Lower value than it looks:
  `_rate()` (`pysnmp_backend.py:242`) already corrects wraps and nulls implausible
  deltas at sample time, so the rate columns are sound. It would only matter if
  something started deriving traffic from `net_rx_bytes_max` deltas, where an
  snmpd restart currently yields a negative.

---

## 11. Open items

| item | status |
|---|---|
| Make `metrics_1h` hierarchical on `metrics_1m` | recommended, measured 3.5x cheaper, **not done**; cheaper now than later |
| Route `pick_source` on bucket width as well as range | measured 17x win, costs ~2-3 min freshness, **not done** |
| Decide on `percentile_agg` before the rollups hold unique history | **open** |
| Frontend run against the migrated API (`pnpm dev`) | **not done** — API shape verified, Zod schemas confirmed permissive, but the 7d range is unclicked |
| `net_speed_bps` is NULL on the k8s node | expected — its `eth0` reports no speed over SNMP; the old code picked up `cni0`'s 10 Gbps. The link-speed caption and utilisation bars are empty for that host |

### Verification status

66 unit tests pass. `ruff` reports 29 errors, identical to the pre-change baseline
(all pre-existing import-sort nits), none new. All 8 TimescaleDB background jobs
scheduled with 0 failures. Migration round-trips clean on an empty database
(up -> down -> up), and `alembic check` reports no drift.
