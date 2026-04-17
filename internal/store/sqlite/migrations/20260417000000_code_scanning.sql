-- 006_code_scanning.sql: support code asset types and MTTR tracking.
--
-- Changes:
--   1. Rebuild assets table with an expanded asset_type CHECK that includes
--      'repository' and 'software_project', which already exist as valid
--      model.AssetType constants but were missing from the SQL constraint.
--   2. Add first_seen_at to config_findings so time-to-fix can be computed
--      across scan runs.

PRAGMA foreign_keys = OFF;

-- Rebuild assets with the updated constraint. All existing columns from
-- migrations 001–005 are preserved in the same order.
CREATE TABLE assets_new (
    id                 TEXT PRIMARY KEY,
    asset_type         TEXT NOT NULL CHECK(asset_type IN (
                           'server','workstation','network_device','cloud_instance',
                           'container','virtual_machine','iot_device','appliance',
                           'software_project','repository'
                       )),
    hostname           TEXT NOT NULL,
    os_family          TEXT,
    os_version         TEXT,
    kernel_version     TEXT,
    architecture       TEXT,
    is_authorized      TEXT NOT NULL DEFAULT 'unknown'
                           CHECK(is_authorized IN ('unknown','authorized','unauthorized')),
    is_managed         TEXT NOT NULL DEFAULT 'unknown'
                           CHECK(is_managed IN ('unknown','managed','unmanaged')),
    environment        TEXT,
    owner              TEXT,
    criticality        TEXT,
    discovery_source   TEXT NOT NULL,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    tags               TEXT,
    natural_key        TEXT,
    mdm_enrollment_id  TEXT,
    cmdb_sys_id        TEXT,
    site               TEXT,
    tenant             TEXT,
    asset_tag          TEXT,
    operational_status TEXT,
    UNIQUE(hostname, asset_type)
);

INSERT INTO assets_new (
    id, asset_type, hostname, os_family, os_version, kernel_version,
    architecture, is_authorized, is_managed, environment, owner, criticality,
    discovery_source, first_seen_at, last_seen_at, tags, natural_key,
    mdm_enrollment_id, cmdb_sys_id, site, tenant, asset_tag, operational_status
)
SELECT
    id, asset_type, hostname, os_family, os_version, kernel_version,
    architecture, is_authorized, is_managed, environment, owner, criticality,
    discovery_source, first_seen_at, last_seen_at, tags, natural_key,
    mdm_enrollment_id, cmdb_sys_id, site, tenant, asset_tag, operational_status
FROM assets;

DROP TABLE assets;
ALTER TABLE assets_new RENAME TO assets;

-- Restore all indexes that existed before the rebuild.
CREATE INDEX IF NOT EXISTS idx_assets_hostname         ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen        ON assets(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_assets_authorized       ON assets(is_authorized);
CREATE INDEX IF NOT EXISTS idx_assets_natural_key      ON assets(natural_key);
CREATE INDEX IF NOT EXISTS idx_assets_discovery_source ON assets(discovery_source);
CREATE INDEX IF NOT EXISTS idx_assets_site             ON assets(site);
CREATE INDEX IF NOT EXISTS idx_assets_tenant           ON assets(tenant);

PRAGMA foreign_keys = ON;

-- Add first_seen_at to config_findings for MTTR (mean time to remediate)
-- tracking. Backfill existing rows from their recorded timestamp.
ALTER TABLE config_findings ADD COLUMN first_seen_at TEXT;
UPDATE config_findings SET first_seen_at = timestamp WHERE first_seen_at IS NULL;
