-- 20260623120000_host_services.sql: durable storage for OS service-manager
-- inventory introduced by the CDMS / HostService iteration.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_services — one row per (asset_id, manager, name) observed managed
--                   service. `manager` discriminates the source-of-record
--                   so a single host can carry both systemd + docker rows
--                   without collisions; `state` and `start_mode` are
--                   normalised CHECK enums so audit rules can match them
--                   without parsing per-manager strings.
--
-- config_hash gives drift detection a per-row signal: any change to the
-- underlying unit file / plist / SCM registry key produces a fresh hash,
-- and the row is upserted with last_seen_at advanced. The DBOS bridge
-- replays unsynced rows to ClickHouse via the same `synced_at` watermark
-- pattern used by loaded_drivers.

CREATE TABLE IF NOT EXISTS host_services (
    id            TEXT PRIMARY KEY NOT NULL,
    asset_id      TEXT NOT NULL,
    manager       TEXT NOT NULL
                  CHECK (manager IN (
                      'systemd', 'launchd', 'windows-scm',
                      'openrc', 'sysv', 'sysvinit', 'rcd',
                      'unknown'
                  )),
    name          TEXT NOT NULL,
    display_name  TEXT,
    description   TEXT,
    state         TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (state IN (
                      'running', 'stopped', 'failed',
                      'activating', 'deactivating',
                      'masked', 'not-found', 'unknown'
                  )),
    start_mode    TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (start_mode IN (
                      'auto', 'manual', 'disabled',
                      'boot', 'system', 'static',
                      'masked', 'on-demand', 'unknown'
                  )),
    run_as        TEXT,
    binary_path   TEXT,
    config_path   TEXT,
    config_hash   TEXT,
    pid           INTEGER,
    exit_code     INTEGER,
    last_seen_at  TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    synced_at     INTEGER,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_services_unique
    ON host_services(asset_id, manager, name);

CREATE INDEX IF NOT EXISTS idx_host_services_unsynced
    ON host_services(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_host_services_state
    ON host_services(asset_id, state);
