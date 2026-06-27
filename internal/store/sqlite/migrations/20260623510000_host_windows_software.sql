-- 20260623510000_host_windows_software.sql: per-host Windows
-- installed-software inventory introduced by CDMS iter 40.
--
-- Two related tables in one migration:
--
--   host_windows_programs — one row per HKLM / HKCU Uninstall key
--                           entry. Captures MSI + native installer
--                           apps the existing winget/chocolatey
--                           collectors don't surface.
--
--   host_windows_patches  — one row per Get-HotFix KB. Captures
--                           every Windows Update / WSUS / manual
--                           KB applied to the host.
--
-- Audit value:
--   - MITRE T1518 (Software Discovery — defender side) — the audit
--     pipeline correlates each (display_name, display_version) against
--     CPE strings and the CVE feed to spot vulnerable apps.
--   - `is_per_user=1` flags installs that landed in HKCU\...\Uninstall
--     (no admin required). Common attacker delivery vehicle for
--     persistence-without-elevation.
--   - `is_system_component=1` filters Windows-shipped components out
--     of CMDB displays without losing them from forensic queries.
--   - host_windows_patches drives patch-gap audits via KB → CVE
--     mapping; the audit pipeline alerts when a known-exploited
--     vulnerability's fix-KB is missing from the host.

CREATE TABLE IF NOT EXISTS host_windows_programs (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    source                   TEXT NOT NULL
                             CHECK (source IN (
                                 'registry-hklm',
                                 'registry-hklm-wow64',
                                 'registry-hkcu',
                                 'unknown'
                             )),
    registry_key             TEXT NOT NULL,         -- full path
    product_id               TEXT NOT NULL,         -- the leaf name (often a GUID)
    display_name             TEXT,
    display_version          TEXT,
    publisher                TEXT,
    install_date             TEXT,                  -- RFC3339; from YYYYMMDD
    install_source           TEXT,
    install_location         TEXT,
    uninstall_string         TEXT,
    estimated_size_bytes     INTEGER NOT NULL DEFAULT 0,
    is_system_component      INTEGER NOT NULL DEFAULT 0
                             CHECK (is_system_component IN (0, 1)),
    is_per_user              INTEGER NOT NULL DEFAULT 0
                             CHECK (is_per_user IN (0, 1)),
    user_sid                 TEXT,                  -- when source=registry-hkcu
    parent_key_name          TEXT,                  -- for KB/update entries with a parent app
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_programs_unique
    ON host_windows_programs(asset_id, registry_key, user_sid);

CREATE INDEX IF NOT EXISTS idx_host_windows_programs_unsynced
    ON host_windows_programs(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me per-user installs" (HKCU = no-admin attack vector).
CREATE INDEX IF NOT EXISTS idx_host_windows_programs_per_user
    ON host_windows_programs(asset_id, display_name)
    WHERE is_per_user = 1;

-- Fast path: app-by-publisher review.
CREATE INDEX IF NOT EXISTS idx_host_windows_programs_publisher
    ON host_windows_programs(asset_id, publisher);

-- Fast path: CVE join (display_name + version).
CREATE INDEX IF NOT EXISTS idx_host_windows_programs_cpe_join
    ON host_windows_programs(display_name, display_version);

CREATE TABLE IF NOT EXISTS host_windows_patches (
    id              TEXT PRIMARY KEY NOT NULL,
    asset_id        TEXT NOT NULL,
    source          TEXT NOT NULL
                    CHECK (source IN (
                        'powershell-get-hotfix',
                        'wmi-quickfixengineering',
                        'unknown'
                    )),
    hotfix_id       TEXT NOT NULL,                -- "KB5031356"
    description     TEXT,                          -- "Security Update"
    install_date    TEXT,                          -- RFC3339
    installed_by    TEXT,
    caption         TEXT,                          -- support URL
    service_pack_in_effect TEXT,
    last_seen_at    TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    synced_at       INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_patches_unique
    ON host_windows_patches(asset_id, hotfix_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_patches_unsynced
    ON host_windows_patches(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "is KB X installed on host Y?"
CREATE INDEX IF NOT EXISTS idx_host_windows_patches_lookup
    ON host_windows_patches(asset_id, hotfix_id);
