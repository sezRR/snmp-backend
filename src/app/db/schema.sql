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

CREATE INDEX IF NOT EXISTS metrics_mac_ts_idx ON metrics (mac, ts DESC);

-- Supports containment/existence queries into the jsonb payload, e.g. finding
-- samples that carry a metric key that was only added recently.
CREATE INDEX IF NOT EXISTS metrics_gin_idx ON metrics USING gin (metrics jsonb_path_ops);
