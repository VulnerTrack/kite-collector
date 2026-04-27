package postgres

// schema contains the DDL executed by Migrate to bootstrap the PostgreSQL
// database. It is kept as a string constant (mirroring the SQLite store
// approach) because the canonical migration file lives outside this package
// tree (migrations/postgres/001_initial.sql) and go:embed does not support
// relative paths that escape the package directory.
const schema = `
-- kite-collector asset discovery schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS assets (
    id               UUID PRIMARY KEY,
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
    first_seen_at    TIMESTAMPTZ NOT NULL,
    last_seen_at     TIMESTAMPTZ NOT NULL,
    tags             JSONB,
    natural_key      TEXT,
    UNIQUE(hostname, asset_type)
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    id             UUID PRIMARY KEY,
    asset_id       UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    interface_name TEXT,
    ip_address     TEXT NOT NULL,
    mac_address    TEXT,
    subnet         TEXT,
    is_primary     BOOLEAN NOT NULL DEFAULT FALSE,
    is_public      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS installed_software (
    id              UUID PRIMARY KEY,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_name   TEXT NOT NULL,
    vendor          TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL,
    cpe23           TEXT,
    package_manager TEXT,
    architecture    TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                UUID PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL,
    completed_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'running',
    total_assets      INTEGER DEFAULT 0,
    new_assets        INTEGER DEFAULT 0,
    updated_assets    INTEGER DEFAULT 0,
    stale_assets      INTEGER DEFAULT 0,
    coverage_percent  DOUBLE PRECISION DEFAULT 0.0,
    error_count       INTEGER DEFAULT 0,
    scope_config      JSONB,
    discovery_sources JSONB
);

-- RFC-0104 phase 2: trigger provenance + operator cancel request marker.
-- Additive, idempotent ALTERs so redeploys over existing databases are safe.
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS trigger_source      TEXT NOT NULL DEFAULT 'cli';
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS triggered_by        TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS events (
    id          UUID PRIMARY KEY,
    event_type  TEXT NOT NULL CHECK(event_type IN ('AssetDiscovered','AssetUpdated','AssetAnalyzed','UnauthorizedAssetDetected','UnmanagedAssetDetected','AssetNotSeen','AssetRemoved')),
    asset_id    UUID NOT NULL REFERENCES assets(id),
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
    severity    TEXT NOT NULL DEFAULT 'low',
    details     JSONB,
    timestamp   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS config_findings (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
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
    timestamp   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS posture_assessments (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
    capec_id    TEXT NOT NULL,
    capec_name  TEXT NOT NULL,
    finding_ids JSONB NOT NULL DEFAULT '[]',
    likelihood  TEXT NOT NULL DEFAULT 'low',
    mitigation  TEXT NOT NULL DEFAULT '',
    timestamp   TIMESTAMPTZ NOT NULL
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
CREATE INDEX IF NOT EXISTS idx_scan_runs_trigger_source ON scan_runs(trigger_source, started_at);

-- Extend events.event_type CHECK to include 'AssetAnalyzed' on databases
-- created before the inline CHECK above was widened. Drops the auto-named
-- constraint (events_event_type_check) and re-adds it with the new value
-- list. Idempotent: a freshly created table already has the wider list, so
-- the DROP/ADD pair simply replaces a constraint with an equivalent one.
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_event_type_check;
ALTER TABLE events ADD CONSTRAINT events_event_type_check
    CHECK (event_type IN ('AssetDiscovered','AssetUpdated','AssetAnalyzed','UnauthorizedAssetDetected','UnmanagedAssetDetected','AssetNotSeen','AssetRemoved'));
`
