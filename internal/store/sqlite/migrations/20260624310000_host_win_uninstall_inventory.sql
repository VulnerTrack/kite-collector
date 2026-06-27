-- host_win_uninstall_inventory inventories Windows
-- software-inventory dumps cached on workstations.
--
-- The canonical Windows source of truth for installed
-- software lives in the Uninstall registry keys:
--
--   HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
--   HKLM\Software\Wow6432Node\Microsoft\Windows\
--           CurrentVersion\Uninstall
--   HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall
--
-- Admins routinely export this via PowerShell or reg.exe and
-- the dumps land on disk:
--
--   uninstall_export_HKLM_*.reg
--   uninstall_export_HKCU_*.reg
--   addremoveprograms_*.csv
--   appx_packages_*.json|csv
--   Get-Package_*.json
--   Get-WmiObject_Win32_Product_*.csv
--   dism_features_*.csv
--   programs_and_features_*.csv
--   installed_programs_*.csv
--
-- **The host-native software inventory layer.** Distinct from:
--   - iter 121 winsoftwarelicences — per-licence-file
--   - iter 122 winsamexports       — third-party SAM tools
--
-- Each row captures one inventory dump. Per dump:
--   - software-entry count
--   - Microsoft vs third-party publisher split
--   - PII-software subset (shared catalogue with iters 121/122)
--   - recent-install detection (any entry within 30d)
--   - suspicious / unsigned publisher count
--
-- Regulatory base:
--   ISO/IEC 27001:2022 A.5.9    Inventory of assets
--   ISO/IEC 27001:2022 A.5.32   Intellectual property rights
--   ISO/IEC 19770-1             Software Asset Management
--   ITIL 4 SAM                  Software Asset Management
--   NIST SP 800-53 CM-8         System Component Inventory
--
-- MITRE / CWE:
--   T1518   Software Discovery
--   T1592   Gather Victim Org Information
--   CWE-200, CWE-359, CWE-732
--
-- Headline finding shapes:
--   has_recent_install            — entry installed within
--                                    last 30 days from clock.
--   has_unsigned_publisher        — > 0 entries with no
--                                    publisher field.
--   has_pii_software              — > 0 entries match PII /
--                                    financial / PHI catalogue.
--   is_credential_exposure_risk   — readable file +
--                                    (PII OR unsigned-publisher
--                                    + entry_count > 0).
--
-- Files store software metadata only (DisplayName, Publisher,
-- DisplayVersion, InstallDate, InstallLocation, URLInfoAbout)
-- which are public product names — not PII.

CREATE TABLE IF NOT EXISTS host_win_uninstall_inventory (
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
            'reg-uninstall-hklm','reg-uninstall-hkcu',
            'addremove-csv','appx-packages-json',
            'appx-packages-csv','ps-get-package',
            'wmi-win32-product','dism-features-csv',
            'programs-features-csv','installed-programs-csv',
            'other','unknown'
        )),
    entry_count                 INTEGER NOT NULL DEFAULT 0,
    microsoft_publisher_count   INTEGER NOT NULL DEFAULT 0,
    third_party_publisher_count INTEGER NOT NULL DEFAULT 0,
    unsigned_publisher_count    INTEGER NOT NULL DEFAULT 0,
    pii_software_count          INTEGER NOT NULL DEFAULT 0,
    recent_install_count        INTEGER NOT NULL DEFAULT 0,
    max_install_date_yyyymmdd   TEXT    NOT NULL DEFAULT '',
    min_install_date_yyyymmdd   TEXT    NOT NULL DEFAULT '',
    inventory_timestamp         TEXT    NOT NULL DEFAULT '',
    has_recent_install          INTEGER NOT NULL DEFAULT 0 CHECK (has_recent_install IN (0,1)),
    has_unsigned_publisher      INTEGER NOT NULL DEFAULT 0 CHECK (has_unsigned_publisher IN (0,1)),
    has_pii_software            INTEGER NOT NULL DEFAULT 0 CHECK (has_pii_software IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_uninst_recent
    ON host_win_uninstall_inventory(artifact_kind) WHERE has_recent_install = 1;

CREATE INDEX IF NOT EXISTS idx_uninst_unsigned
    ON host_win_uninstall_inventory(artifact_kind, unsigned_publisher_count)
    WHERE has_unsigned_publisher = 1;

CREATE INDEX IF NOT EXISTS idx_uninst_pii
    ON host_win_uninstall_inventory(artifact_kind, pii_software_count)
    WHERE has_pii_software = 1;

CREATE INDEX IF NOT EXISTS idx_uninst_exposure
    ON host_win_uninstall_inventory(file_path) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_uninst_drift
    ON host_win_uninstall_inventory(file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_uninst_kind
    ON host_win_uninstall_inventory(artifact_kind, inventory_timestamp);
