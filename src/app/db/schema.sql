-- Schema owned by the application (src/app/db/init.py applies it).
--
-- Deliberately NOT loaded through /docker-entrypoint-initdb.d: that only runs
-- against an empty data directory, so it cannot be evolved. This file is
-- re-applied on every startup and must stay idempotent.

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Machines the client asked us to observe.
--
-- Only identity and polling address live here. Everything else about a machine
-- — tenant, user, flavor, specs — comes from OpenStack at read time, so there
-- is no second copy of it to drift. `label` is the client's own annotation, not
-- an OpenStack fact, which is why it is stored.
CREATE TABLE IF NOT EXISTS machines (
    mac        macaddr     PRIMARY KEY,
    ipv4       inet        NOT NULL,
    label      text,
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- One machine per address: the collector polls by IPv4.
CREATE UNIQUE INDEX IF NOT EXISTS machines_ipv4_key ON machines (ipv4);

-- Samples. `metrics` is jsonb rather than typed columns so the collector can
-- gain or lose metrics without a migration.
--
-- The FK is what makes "delete the MAC, delete its history" a single statement.
-- A hypertable may reference a regular table; the cascade does touch every
-- chunk, which is fine at this scale. Time-ranged purges use drop_chunks().
CREATE TABLE IF NOT EXISTS metrics (
    ts      timestamptz NOT NULL,
    mac     macaddr     NOT NULL REFERENCES machines (mac) ON DELETE CASCADE,
    metrics jsonb       NOT NULL
);

SELECT create_hypertable('metrics', by_range('ts'), if_not_exists => TRUE);

-- One chunk per day rather than the seven-day default. At a five second
-- interval a fleet in the hundreds writes millions of rows a day, so weekly
-- chunks would be both unwieldy to compress and coarse to drop: `purge_all`
-- and the retention policy are chunk-granular, and a chunk straddling the
-- cutoff is kept whole.
SELECT set_chunk_time_interval('metrics', INTERVAL '1 day');

-- Columnar compression. Segmenting by mac keeps one machine's history
-- contiguous, which is how every query reads it; ordering by ts descending
-- matches both the index below and the "most recent first" access pattern.
-- Declaring this is separate from scheduling it — `app.db.init` adds the
-- policy, because when to compress is a setting.
ALTER TABLE metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'mac',
    timescaledb.compress_orderby   = 'ts DESC'
);

CREATE INDEX IF NOT EXISTS metrics_mac_ts_idx ON metrics (mac, ts DESC);

-- Supports containment/existence queries into the jsonb payload, e.g. finding
-- samples that carry a metric key that was only added recently.
CREATE INDEX IF NOT EXISTS metrics_gin_idx ON metrics USING gin (metrics jsonb_path_ops);
