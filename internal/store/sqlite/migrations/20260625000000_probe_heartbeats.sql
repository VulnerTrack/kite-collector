-- 20260625000000_probe_heartbeats.sql: synthetic per-source liveness
-- records + tamper / canary-drift incident types.
--
-- Adds one new table (probe_heartbeats) and widens the runtime_incidents
-- incident_type CHECK constraint to admit 'tamper_detected' and
-- 'canary_drift'. SQLite cannot ALTER a CHECK in place, so the table is
-- rebuilt — preserving every row and index.

CREATE TABLE IF NOT EXISTS probe_heartbeats (
    id              TEXT PRIMARY KEY,
    scan_run_id     TEXT NOT NULL,
    source          TEXT NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('ok', 'error', 'timeout', 'circuit_open')),
    items_emitted   INTEGER NOT NULL DEFAULT 0
                    CHECK (items_emitted >= 0),
    duration_ms     INTEGER NOT NULL DEFAULT 0
                    CHECK (duration_ms >= 0),
    binary_hash     TEXT NOT NULL,
    signature       BLOB NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

-- One row per (scan, source). Two heartbeats from the same source in the
-- same scan is a bug; this index makes it fail fast.
CREATE UNIQUE INDEX IF NOT EXISTS idx_probe_heartbeats_unique
    ON probe_heartbeats(scan_run_id, source);

-- Reconciler pulls every heartbeat for one scan, then per-source last-seen.
CREATE INDEX IF NOT EXISTS idx_probe_heartbeats_scan
    ON probe_heartbeats(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_probe_heartbeats_source_created
    ON probe_heartbeats(source, created_at DESC);

-- Widen runtime_incidents.incident_type CHECK to admit tamper_detected and
-- canary_drift. SQLite cannot ALTER a CHECK; rebuild the table. Foreign keys
-- are temporarily disabled around the swap so the rename does not cascade.
PRAGMA foreign_keys = OFF;

CREATE TABLE runtime_incidents_new (
    id              TEXT PRIMARY KEY,
    incident_type   TEXT NOT NULL
                    CHECK (incident_type IN (
                        'panic_recovered', 'timeout_exceeded',
                        'circuit_breaker_tripped', 'response_truncated',
                        'body_limit_exceeded',
                        'tamper_detected', 'canary_drift'
                    )),
    component       TEXT NOT NULL,
    error_message   TEXT NOT NULL,
    stack_trace     TEXT,
    scan_run_id     TEXT,
    severity        TEXT NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    recovered       INTEGER NOT NULL DEFAULT 1,
    error_code      TEXT,
    created_at      TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

INSERT INTO runtime_incidents_new
    (id, incident_type, component, error_message, stack_trace,
     scan_run_id, severity, recovered, error_code, created_at)
SELECT
    id, incident_type, component, error_message, stack_trace,
    scan_run_id, severity, recovered, error_code, created_at
FROM runtime_incidents;

DROP TABLE runtime_incidents;
ALTER TABLE runtime_incidents_new RENAME TO runtime_incidents;

CREATE INDEX IF NOT EXISTS idx_incidents_scan ON runtime_incidents(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON runtime_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_component ON runtime_incidents(component);

PRAGMA foreign_keys = ON;
