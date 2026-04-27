-- 20260426000000_events_check_asset_analyzed.sql: extend events.event_type
-- CHECK constraint to include 'AssetAnalyzed' (introduced by db503fa for
-- non-material rescan ticks).
--
-- SQLite cannot ALTER an existing CHECK constraint, so this migration uses
-- the standard table-rebuild pattern: create events_new with the new CHECK
-- list, copy rows, drop old, rename. Indexes on the original table are
-- recreated below since DROP TABLE removes them.
--
-- The migration runner wraps each file in a single transaction (see
-- sqlite.Migrate), so the CREATE/INSERT/DROP/RENAME sequence is atomic.

CREATE TABLE events_new (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL CHECK(event_type IN ('AssetDiscovered','AssetUpdated','AssetAnalyzed','UnauthorizedAssetDetected','UnmanagedAssetDetected','AssetNotSeen','AssetRemoved')),
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    severity    TEXT NOT NULL DEFAULT 'low',
    details     TEXT,
    timestamp   TEXT NOT NULL
);

INSERT INTO events_new (id, event_type, asset_id, scan_run_id, severity, details, timestamp)
SELECT id, event_type, asset_id, scan_run_id, severity, details, timestamp
FROM events;

DROP TABLE events;

ALTER TABLE events_new RENAME TO events;

CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_id);
