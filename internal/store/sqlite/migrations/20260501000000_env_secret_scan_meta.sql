-- 20260501000000_env_secret_scan_meta.sql: tracks which scan runs have had
-- their environment secret findings (RFC-0123) synced to ClickHouse.
-- Additive-only: one new bookkeeping table that referencs scan_runs(id).
-- No existing tables are modified. Container and process env secret
-- findings continue to live in config_findings — this table only records
-- the per-scan-run sync watermark consumed by the kite_collector Python
-- bridge workspace.

CREATE TABLE IF NOT EXISTS env_secret_scan_meta (
    scan_run_id   TEXT PRIMARY KEY NOT NULL REFERENCES scan_runs(id),
    synced_at     INTEGER,
    finding_count INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_env_secret_sync_pending
    ON env_secret_scan_meta(synced_at)
    WHERE synced_at IS NULL;
