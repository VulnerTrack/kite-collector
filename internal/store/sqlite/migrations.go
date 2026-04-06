package sqlite

// schema contains the DDL executed by Migrate to bootstrap the database.
// It is kept as a string constant because the migration file lives outside
// this package tree (migrations/sqlite/001_initial.sql) and go:embed does not
// support relative paths that escape the package directory.
const schema = `
-- kite-collector asset discovery schema

CREATE TABLE IF NOT EXISTS assets (
    id               TEXT PRIMARY KEY,
    asset_type       TEXT NOT NULL CHECK(asset_type IN ('server','workstation','network_device','cloud_instance','container','virtual_machine','iot_device','appliance')),
    hostname         TEXT NOT NULL,
    os_family        TEXT,
    os_version       TEXT,
    kernel_version   TEXT,
    architecture     TEXT,
    is_authorized    TEXT NOT NULL DEFAULT 'unknown' CHECK(is_authorized IN ('unknown','authorized','unauthorized')),
    is_managed       TEXT NOT NULL DEFAULT 'unknown' CHECK(is_managed IN ('unknown','managed','unmanaged')),
    environment      TEXT,
    owner            TEXT,
    criticality      TEXT,
    discovery_source TEXT NOT NULL,
    first_seen_at    TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    tags             TEXT,
    natural_key      TEXT,
    UNIQUE(hostname, asset_type)
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    id             TEXT PRIMARY KEY,
    asset_id       TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    interface_name TEXT,
    ip_address     TEXT NOT NULL,
    mac_address    TEXT,
    subnet         TEXT,
    is_primary     INTEGER NOT NULL DEFAULT 0,
    is_public      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS installed_software (
    id              TEXT PRIMARY KEY,
    asset_id        TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_name   TEXT NOT NULL,
    vendor          TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL,
    cpe23           TEXT,
    package_manager TEXT,
    architecture    TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                TEXT PRIMARY KEY,
    started_at        TEXT NOT NULL,
    completed_at      TEXT,
    status            TEXT NOT NULL DEFAULT 'running',
    total_assets      INTEGER DEFAULT 0,
    new_assets        INTEGER DEFAULT 0,
    updated_assets    INTEGER DEFAULT 0,
    stale_assets      INTEGER DEFAULT 0,
    coverage_percent  REAL DEFAULT 0.0,
    error_count       INTEGER DEFAULT 0,
    scope_config      TEXT,
    discovery_sources TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL CHECK(event_type IN ('AssetDiscovered','AssetUpdated','UnauthorizedAssetDetected','UnmanagedAssetDetected','AssetNotSeen','AssetRemoved')),
    asset_id    TEXT NOT NULL REFERENCES assets(id),
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    severity    TEXT NOT NULL DEFAULT 'low',
    details     TEXT,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_findings (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    auditor     TEXT NOT NULL,
    check_id    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    cwe_id      TEXT NOT NULL,
    cwe_name    TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    expected    TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cis_control TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posture_assessments (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    capec_id    TEXT NOT NULL,
    capec_name  TEXT NOT NULL,
    finding_ids TEXT NOT NULL DEFAULT '[]',
    likelihood  TEXT NOT NULL DEFAULT 'low',
    mitigation  TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_assets_authorized ON assets(is_authorized);
CREATE INDEX IF NOT EXISTS idx_assets_natural_key ON assets(natural_key);
CREATE INDEX IF NOT EXISTS idx_interfaces_ip ON network_interfaces(ip_address);
CREATE INDEX IF NOT EXISTS idx_interfaces_mac ON network_interfaces(mac_address);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_id);
CREATE INDEX IF NOT EXISTS idx_software_cpe ON installed_software(cpe23);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON config_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON config_findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON config_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON config_findings(check_id);
CREATE INDEX IF NOT EXISTS idx_posture_asset ON posture_assessments(asset_id);
CREATE INDEX IF NOT EXISTS idx_posture_capec ON posture_assessments(capec_id);
`
