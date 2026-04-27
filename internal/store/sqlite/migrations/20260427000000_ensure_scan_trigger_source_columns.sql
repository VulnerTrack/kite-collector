-- 20260427000000_ensure_scan_trigger_source_columns.sql: recovery migration
-- for live operator deploys whose schema_migrations recorded
-- 20260425000000_scan_trigger_source as applied without the ADD COLUMN
-- statements actually running. Symptom: dashboard "render scan-status"
-- fails with "no such column: trigger_source (1)".
--
-- SQLite's ALTER TABLE ADD COLUMN has no IF NOT EXISTS form, so we cannot
-- simply re-execute the original migration. Instead we use the portable
-- table-rebuild pattern (same approach as
-- 20260424000000_drop_identity_platform_endpoint.sql), which converges to
-- the canonical schema regardless of whether 20260425 ever applied:
--
--   * Bug case (live operator): scan_runs lacks trigger_source/triggered_by/
--     cancel_requested_at. The INSERT...SELECT below copies the pre-20260425
--     columns (the original 20260403 column list). The three new columns
--     adopt their DEFAULTs on the rebuilt table — exactly what the original
--     ADD COLUMN statements would have produced for pre-existing rows.
--   * Healthy case (20260425 applied): the same INSERT...SELECT copies the
--     pre-20260425 columns. The three new columns adopt their DEFAULTs:
--     trigger_source becomes 'cli' (matching the historical implicit
--     behaviour and the original migration's DEFAULT — only previously
--     non-default rows of trigger_source='api'|'scheduled' are reset),
--     triggered_by becomes NULL, cancel_requested_at becomes NULL. Both
--     of the latter are operationally transient (a cancel request lives
--     at most for one in-flight scan), so this is acceptable.
--   * Fresh install: all migrations apply in order; this rebuild copies
--     zero or more rows from a scan_runs that already has every canonical
--     column, with the same default-reset semantics described above.
--
-- The migration runner wraps each file in a single transaction (see
-- sqlite.Migrate), so the CREATE/INSERT/DROP/RENAME sequence is atomic.

CREATE TABLE scan_runs_new (
    id                  TEXT PRIMARY KEY,
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    status              TEXT NOT NULL DEFAULT 'running',
    total_assets        INTEGER DEFAULT 0,
    new_assets          INTEGER DEFAULT 0,
    updated_assets      INTEGER DEFAULT 0,
    stale_assets        INTEGER DEFAULT 0,
    coverage_percent    REAL DEFAULT 0.0,
    error_count         INTEGER DEFAULT 0,
    scope_config        TEXT,
    discovery_sources   TEXT,
    trigger_source      TEXT NOT NULL DEFAULT 'cli',
    triggered_by        TEXT,
    cancel_requested_at TEXT
);

INSERT INTO scan_runs_new (
    id,
    started_at,
    completed_at,
    status,
    total_assets,
    new_assets,
    updated_assets,
    stale_assets,
    coverage_percent,
    error_count,
    scope_config,
    discovery_sources
)
SELECT
    id,
    started_at,
    completed_at,
    status,
    total_assets,
    new_assets,
    updated_assets,
    stale_assets,
    coverage_percent,
    error_count,
    scope_config,
    discovery_sources
FROM scan_runs;

DROP TABLE scan_runs;

ALTER TABLE scan_runs_new RENAME TO scan_runs;

CREATE INDEX IF NOT EXISTS idx_scan_runs_trigger_source
    ON scan_runs(trigger_source, started_at);
