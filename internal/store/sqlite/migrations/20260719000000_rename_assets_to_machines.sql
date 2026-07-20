-- 20260719000000_rename_assets_to_machines.sql
-- Full-break rename of the domain concept `asset` -> `machine`.
--
-- The asset_id FK column exists on 95 child tables. Renaming each with a
-- separate ALTER TABLE ... RENAME COLUMN forces SQLite to reparse the entire
-- ~156-table schema once per statement (O(n^2), ~11s). Instead we rewrite all
-- of them plus their indexes in a single sqlite_master edit under
-- writable_schema, then RESET to reload once. This is a standard SQLite bulk
-- schema-change technique and only touches the exact token `asset_id` (never
-- asset_class / is_asset_seizure / chassis_asset_tag / asset_no / etc., which
-- are different concepts and do not contain that substring).
PRAGMA writable_schema=ON;
UPDATE sqlite_master
   SET sql = replace(sql, 'asset_id', 'machine_id')
 WHERE sql LIKE '%asset_id%';
PRAGMA writable_schema=RESET;

-- Core table: rename asset_type/asset_tag columns (updates CHECK + UNIQUE),
-- then the table itself (updates child FK `REFERENCES assets(id)`).
ALTER TABLE assets RENAME COLUMN asset_type TO machine_type;
ALTER TABLE assets RENAME COLUMN asset_tag TO machine_tag;
ALTER TABLE assets RENAME TO machines;

-- Rename the assets-table indexes.
DROP INDEX idx_assets_authorized;
CREATE INDEX idx_machines_authorized ON machines(is_authorized);
DROP INDEX idx_assets_compliance_state;
CREATE INDEX idx_machines_compliance_state ON machines(compliance_state);
DROP INDEX idx_assets_discovery_source;
CREATE INDEX idx_machines_discovery_source ON machines(discovery_source);
DROP INDEX idx_assets_hostname;
CREATE INDEX idx_machines_hostname ON machines(hostname);
DROP INDEX idx_assets_last_seen;
CREATE INDEX idx_machines_last_seen ON machines(last_seen_at);
DROP INDEX idx_assets_natural_key;
CREATE INDEX idx_machines_natural_key ON machines(natural_key);
DROP INDEX idx_assets_ownership_type;
CREATE INDEX idx_machines_ownership_type ON machines(ownership_type);
DROP INDEX idx_assets_site;
CREATE INDEX idx_machines_site ON machines(site);
DROP INDEX idx_assets_tenant;
CREATE INDEX idx_machines_tenant ON machines(tenant);

-- scan_runs counter columns.
ALTER TABLE scan_runs RENAME COLUMN total_assets TO total_machines;
ALTER TABLE scan_runs RENAME COLUMN new_assets TO new_machines;
ALTER TABLE scan_runs RENAME COLUMN updated_assets TO updated_machines;
ALTER TABLE scan_runs RENAME COLUMN stale_assets TO stale_machines;
ALTER TABLE scan_runs RENAME COLUMN analyzed_assets TO analyzed_machines;

-- config_findings: column already machine_id (writable_schema); rename its index.
DROP INDEX idx_findings_asset;
CREATE INDEX idx_findings_machine ON config_findings(machine_id);

-- Rebuild `events`: its column is already machine_id; this fixes the
-- event_type CHECK (Asset* -> Machine*) which ALTER cannot change.
CREATE TABLE events_new (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL CHECK(event_type IN ('MachineDiscovered','MachineUpdated','MachineAnalyzed','UnauthorizedMachineDetected','UnmanagedMachineDetected','MachineNotSeen','MachineRemoved')),
    machine_id  TEXT NOT NULL REFERENCES machines(id),
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    severity    TEXT NOT NULL DEFAULT 'low',
    details     TEXT,
    timestamp   TEXT NOT NULL
);
INSERT INTO events_new (id, event_type, machine_id, scan_run_id, severity, details, timestamp)
SELECT id,
       CASE event_type
           WHEN 'AssetDiscovered'            THEN 'MachineDiscovered'
           WHEN 'AssetUpdated'               THEN 'MachineUpdated'
           WHEN 'AssetAnalyzed'              THEN 'MachineAnalyzed'
           WHEN 'UnauthorizedAssetDetected'  THEN 'UnauthorizedMachineDetected'
           WHEN 'UnmanagedAssetDetected'     THEN 'UnmanagedMachineDetected'
           WHEN 'AssetNotSeen'               THEN 'MachineNotSeen'
           WHEN 'AssetRemoved'               THEN 'MachineRemoved'
           ELSE event_type
       END,
       machine_id, scan_run_id, severity, details, timestamp
FROM events;
DROP TABLE events;
ALTER TABLE events_new RENAME TO events;
CREATE INDEX idx_events_machine ON events(machine_id);