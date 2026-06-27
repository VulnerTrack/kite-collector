-- 005_mdm_cmdb_columns.sql: add MDM and CMDB metadata columns to the assets table.
-- These columns store enrichment data from MDM platforms (Intune, Jamf, SCCM)
-- and CMDB systems (NetBox, ServiceNow). All columns are nullable and additive;
-- existing queries are unaffected.

ALTER TABLE assets ADD COLUMN mdm_enrollment_id TEXT;
ALTER TABLE assets ADD COLUMN cmdb_sys_id TEXT;
ALTER TABLE assets ADD COLUMN site TEXT;
ALTER TABLE assets ADD COLUMN tenant TEXT;
ALTER TABLE assets ADD COLUMN asset_tag TEXT;
ALTER TABLE assets ADD COLUMN operational_status TEXT;

CREATE INDEX IF NOT EXISTS idx_assets_discovery_source ON assets(discovery_source);
CREATE INDEX IF NOT EXISTS idx_assets_site ON assets(site);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant);
