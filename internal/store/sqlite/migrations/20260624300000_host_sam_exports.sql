-- host_sam_exports inventories Software-Asset-Management
-- export files cached on workstations across Windows,
-- Linux, and macOS.
--
-- Enterprise SAM tools dump per-asset CSV/XML/JSON of every
-- installed software with display name, publisher, version,
-- install date, and (when available) vendor URL:
--
--   Microsoft SCCM / MEM      sccm_software_inventory_*.csv
--   Microsoft Intune          intune_software_*.json
--   Lansweeper                lansweeper_software_*.csv|.xml
--   Snow License Manager      snow_inventory_*.xml
--   Flexera FlexNet Manager   flexera_inventory_*.csv
--   ManageEngine Desktop      desktopcentral_software_*.csv
--                             Central
--   HCL BigFix                bigfix_software_*.csv
--   Microsoft winget          winget-export.json
--   Chocolatey list           choco-list-*.csv
--   GLPI inventory (open)     glpi_software_*.csv
--   OCS Inventory (open)      ocs_software_*.csv
--
-- This collector complements iter 121 winsoftwarelicences
-- (single licence-artifact files) with the *aggregate
-- per-asset inventory* layer that ISO/IEC 19770-1 and
-- ITIL SAM require enterprises to maintain.
--
-- Why this is sensitive:
--   * Per-row contains DisplayName + Publisher that maps
--     directly to vendor licence audits.
--   * Asset hostname embedded in row metadata + workforce
--     payroll-tier inference (which laptops have Adobe CC,
--     QuickBooks, IDEs etc).
--   * Some exports embed product keys / activation IDs —
--     never persisted verbatim (only SHA-256 hash of file).
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                 Software Asset Management
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   Ley 25.326 (AR) / GDPR     Asset-PII linkage
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1592   Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_pii_software         — at least one row matches the
--                              curated PII/financial/PHI
--                              catalogue (shared with
--                              iter 121 winsoftwarelicences).
--   has_unlicensed_software  — row carries unlicensed /
--                              activation-pending marker.
--   is_stale_inventory       — inventory timestamp older
--                              than 90 days from clock.
--   is_credential_exposure_risk — readable file + hostname
--                              + (PII software OR unlicensed
--                              software).
--
-- Asset hostname stored ONLY as SHA-256 hash (never raw).

CREATE TABLE IF NOT EXISTS host_sam_exports (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    tool_kind                   TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (tool_kind IN (
            'sccm','intune','lansweeper','snow-lm',
            'flexera','desktop-central','bigfix',
            'winget-export','chocolatey-list',
            'glpi','ocs-inventory','generic-csv',
            'other','unknown'
        )),
    asset_hostname_hash         TEXT    NOT NULL DEFAULT '',
    inventory_timestamp         TEXT    NOT NULL DEFAULT '',
    software_count              INTEGER NOT NULL DEFAULT 0,
    pii_software_count          INTEGER NOT NULL DEFAULT 0,
    unlicensed_count            INTEGER NOT NULL DEFAULT 0,
    publishers_distinct_count   INTEGER NOT NULL DEFAULT 0,
    inventory_age_days          INTEGER NOT NULL DEFAULT 0,
    has_pii_software            INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_software IN (0,1)),
    has_unlicensed_software     INTEGER NOT NULL DEFAULT 0 CHECK (has_unlicensed_software IN (0,1)),
    is_stale_inventory          INTEGER NOT NULL DEFAULT 0 CHECK (is_stale_inventory IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_sam_pii
    ON host_sam_exports(tool_kind) WHERE has_pii_software = 1;

CREATE INDEX IF NOT EXISTS idx_sam_unlicensed
    ON host_sam_exports(tool_kind) WHERE has_unlicensed_software = 1;

CREATE INDEX IF NOT EXISTS idx_sam_stale
    ON host_sam_exports(tool_kind, inventory_timestamp) WHERE is_stale_inventory = 1;

CREATE INDEX IF NOT EXISTS idx_sam_exposure
    ON host_sam_exports(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_sam_drift
    ON host_sam_exports(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_sam_tool
    ON host_sam_exports(tool_kind, inventory_timestamp);

CREATE INDEX IF NOT EXISTS idx_sam_asset
    ON host_sam_exports(asset_hostname_hash);
