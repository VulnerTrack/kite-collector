-- host_chocolatey_inventory inventories Chocolatey package
-- manager artifacts cached on Windows workstations.
--
-- Chocolatey is the dominant Windows package manager in
-- enterprise deployments (PSADT, MDT, Configuration Manager
-- replacement). Each installed package leaves:
--
--   C:\ProgramData\chocolatey\lib\<pkg>\<pkg>.nuspec
--   C:\ProgramData\chocolatey\.chocolatey\<pkg>.<ver>\
--   C:\ProgramData\chocolatey\logs\chocolatey.log
--   C:\ProgramData\chocolatey\config\chocolatey.config
--   C:\ProgramData\chocolatey\extensions\<ext>.nuspec
--
-- nuspec XML carries exactly the ISO 27001 A.5.32 +
-- ITIL SAM inventory fields:
--
--   <id>             package identifier (title slug)
--   <title>          display name
--   <authors>        publisher / manufacturer
--   <copyright>      copyright owner
--   <projectUrl>     vendor URL
--   <licenseUrl>     licence URL
--   <description>    purpose
--   <tags>           classification tags
--   <version>        version
--   <releaseNotes>   change-log + release date
--
-- **The Windows-package-manager metadata layer.** Distinct from:
--   - iter 121 winsoftwarelicences   per-licence-file
--   - iter 122 winsamexports         SAM-tool aggregate
--   - iter 123 winregistryuninstall  host-native Uninstall
--   - iter 124 winsbom               SBOM artifacts
--
-- Per package the audit captures:
--   * canonical product fields populated from nuspec elements
--   * install date proxy from file mtime
--   * DP/DS classification via the curated PII/PHI/PCI
--     catalogue shared with iters 121-124
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32  Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9   Inventory of assets
--   ISO/IEC 19770-1             Software Asset Management
--   ITIL 4 SAM                  Software Asset Management
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195.002 Compromise Software Supply Chain
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_license_url            — nuspec ships licenseUrl —
--                                facilitates audit-trail.
--   is_pii_handling            — package matches PII /
--                                financial / PHI / PCI
--                                catalogue.
--   has_recent_install         — file mtime within 30d.
--   is_credential_exposure_risk — readable file +
--                                PII-handling product
--                                metadata exposed in shared
--                                workstation cache.

CREATE TABLE IF NOT EXISTS host_chocolatey_inventory (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_size                   INTEGER NOT NULL DEFAULT 0,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    artifact_kind               TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (artifact_kind IN (
            'choco-nuspec','choco-log','choco-config',
            'choco-extension-nuspec','choco-pin',
            'other','unknown'
        )),
    package_id                  TEXT    NOT NULL DEFAULT '',
    title                       TEXT    NOT NULL DEFAULT '',
    publisher                   TEXT    NOT NULL DEFAULT '',
    version                     TEXT    NOT NULL DEFAULT '',
    project_url                 TEXT    NOT NULL DEFAULT '',
    license_url                 TEXT    NOT NULL DEFAULT '',
    description                 TEXT    NOT NULL DEFAULT '',
    tags                        TEXT    NOT NULL DEFAULT '',
    install_date_yyyymmdd       TEXT    NOT NULL DEFAULT '',
    dp_ds_class                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (dp_ds_class IN (
            'handles-pii','handles-financial','handles-phi',
            'handles-pci','system-utility','dev-tool',
            'media-tool','oss-no-pii','other','unknown'
        )),
    has_license_url             INTEGER NOT NULL DEFAULT 0 CHECK (has_license_url IN (0,1)),
    has_project_url             INTEGER NOT NULL DEFAULT 0 CHECK (has_project_url IN (0,1)),
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    is_pii_handling             INTEGER NOT NULL DEFAULT 0 CHECK (is_pii_handling IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_choco_pii
    ON host_chocolatey_inventory(package_id, publisher) WHERE is_pii_handling = 1;

CREATE INDEX IF NOT EXISTS idx_choco_recent
    ON host_chocolatey_inventory(install_date_yyyymmdd, package_id) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_choco_license
    ON host_chocolatey_inventory(package_id) WHERE has_license_url = 1;

CREATE INDEX IF NOT EXISTS idx_choco_exposure
    ON host_chocolatey_inventory(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_choco_drift
    ON host_chocolatey_inventory(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_choco_package
    ON host_chocolatey_inventory(package_id, version);

CREATE INDEX IF NOT EXISTS idx_choco_dp_ds
    ON host_chocolatey_inventory(dp_ds_class, package_id);
