-- host_winget_exports inventories Microsoft winget (Windows
-- Package Manager) export + state files cached on Windows
-- workstations.
--
-- winget is Microsoft's first-party Windows Package Manager
-- shipped with Windows 10/11. `winget export -o file.json`
-- produces a canonical JSON listing every installed
-- package with PackageIdentifier (e.g. `Microsoft.Office`,
-- `Google.Chrome`, `Intuit.QuickBooks`, `Adobe.Acrobat`) and
-- version. The PackageIdentifier convention
-- `<Publisher>.<Product>` gives the inventory `title` +
-- `manufacturer` for free.
--
-- Files cached on workstations:
--
--   winget-export.json              winget export output
--   winget-export-<date>.json
--   pinned.json                     winget pin list
--   sources.json                    winget source registry
--   <pkg>.installLog                per-package install log
--   <pkg>.uninstallLog              per-package uninstall log
--
-- Located under:
--   %LOCALAPPDATA%\Packages\
--       Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\
--           LocalState\
--   %LOCALAPPDATA%\Microsoft\WinGet\
--   C:\ProgramData\Microsoft\WinGet\
--
-- **The Microsoft-native package-manager layer.** Distinct
-- from:
--   - iter 121 winsoftwarelicences  per-licence-file
--   - iter 122 winsamexports        third-party SAM tools
--   - iter 123 winregistryuninstall host-native Uninstall
--   - iter 124 winsbom              SBOM artifacts
--   - iter 125 winchocolatey        Chocolatey nuspec
--
-- Per file the audit captures:
--   * source name + URL (winget / msstore / custom corporate)
--   * winget version + creation timestamp
--   * package count + Microsoft vs third-party split
--   * PII-package subset (catalogue shared with iters 121-125)
--   * MS Store source presence (license-attribution risk)
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.32 Intellectual property rights
--   ISO/IEC 27001:2022 A.5.9  Inventory of assets
--   ISO/IEC 19770-1            Software Asset Management
--   ITIL 4 SAM                Software Asset Management
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1195   Supply Chain Compromise
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_msstore_source        — Microsoft Store source in
--                                sources list — consumer
--                                licence channel risk.
--   has_third_party_source    — custom non-default source
--                                configured (potential
--                                supply-chain attack vector).
--   has_pii_packages          — > 0 packages match catalogue.
--   is_credential_exposure_risk — readable file + packages
--                                + PII OR third-party source.

CREATE TABLE IF NOT EXISTS host_winget_exports (
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
            'winget-export-json','winget-pin-list',
            'winget-source-list','winget-install-log',
            'winget-uninstall-log','other','unknown'
        )),
    winget_version              TEXT    NOT NULL DEFAULT '',
    source_name                 TEXT    NOT NULL DEFAULT '',
    source_argument             TEXT    NOT NULL DEFAULT '',
    creation_timestamp          TEXT    NOT NULL DEFAULT '',
    package_count               INTEGER NOT NULL DEFAULT 0,
    microsoft_package_count     INTEGER NOT NULL DEFAULT 0,
    third_party_package_count   INTEGER NOT NULL DEFAULT 0,
    pii_package_count           INTEGER NOT NULL DEFAULT 0,
    has_msstore_source          INTEGER NOT NULL DEFAULT 0 CHECK (has_msstore_source IN (0,1)),
    has_third_party_source      INTEGER NOT NULL DEFAULT 0 CHECK (has_third_party_source IN (0,1)),
    has_pii_packages            INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_packages IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_winget_pii
    ON host_winget_exports(source_name, package_count) WHERE has_pii_packages = 1;

CREATE INDEX IF NOT EXISTS idx_winget_msstore
    ON host_winget_exports(creation_timestamp) WHERE has_msstore_source = 1;

CREATE INDEX IF NOT EXISTS idx_winget_thirdparty
    ON host_winget_exports(source_name, source_argument) WHERE has_third_party_source = 1;

CREATE INDEX IF NOT EXISTS idx_winget_exposure
    ON host_winget_exports(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_winget_drift
    ON host_winget_exports(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_winget_kind
    ON host_winget_exports(artifact_kind, creation_timestamp);
