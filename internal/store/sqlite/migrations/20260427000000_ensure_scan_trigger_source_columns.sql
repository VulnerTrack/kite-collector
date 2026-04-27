-- 20260427000000_ensure_scan_trigger_source_columns.sql
-- @tolerate: duplicate column name
--
-- Recovery migration: re-applies the ALTERs from 20260425 in case that
-- migration was recorded as applied without actually running. Each ALTER
-- is independently safe -- SQLite's ALTER TABLE ADD COLUMN either succeeds
-- (column missing) or errors with "duplicate column name: <col>" (column
-- present) -- never half-applies.
--
-- The migration runner swallows "duplicate column name" errors as success
-- for any migration whose header contains the "@tolerate: duplicate column
-- name" directive (see Migrate() in migrate.go). This preserves operator
-- data on healthy DBs (no table rebuild, no DEFAULT reset) while still
-- recovering broken-operator DBs whose 20260425 was a no-op.
--
-- The CREATE INDEX IF NOT EXISTS is safe regardless of which case applies.

ALTER TABLE scan_runs ADD COLUMN trigger_source      TEXT NOT NULL DEFAULT 'cli';
ALTER TABLE scan_runs ADD COLUMN triggered_by        TEXT;
ALTER TABLE scan_runs ADD COLUMN cancel_requested_at TEXT;

CREATE INDEX IF NOT EXISTS idx_scan_runs_trigger_source
    ON scan_runs(trigger_source, started_at);
