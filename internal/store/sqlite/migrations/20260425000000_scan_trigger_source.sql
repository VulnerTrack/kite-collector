-- 20260425000000_scan_trigger_source.sql: RFC-0104 phase 2
-- Adds provenance and cancellation-request columns to scan_runs so the
-- scan coordinator can distinguish CLI, API, and scheduled triggers and
-- record operator cancel requests ahead of the engine's terminal update.

ALTER TABLE scan_runs ADD COLUMN trigger_source      TEXT NOT NULL DEFAULT 'cli';
ALTER TABLE scan_runs ADD COLUMN triggered_by        TEXT;
ALTER TABLE scan_runs ADD COLUMN cancel_requested_at TEXT;

CREATE INDEX IF NOT EXISTS idx_scan_runs_trigger_source
    ON scan_runs(trigger_source, started_at);
