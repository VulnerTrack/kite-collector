-- 20260623810000_host_msix_packages.sql: durable storage for per-host
-- MSIX / UWP / AppX package inventory introduced by CDMS iter 74.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_msix_packages — one row per `AppxManifest.xml` discovered
--                        under C:\Program Files\WindowsApps\<PackageFullName>\
--                        (machine-wide) or %LOCALAPPDATA%\Packages\
--                        <PackageFamily>\ (per-user staged). Each
--                        manifest describes a Microsoft Store /
--                        sideloaded / pre-installed UWP package and
--                        carries its capability declarations — the
--                        Windows-runtime equivalent of an Android
--                        Permissions block.
--
-- Audit value (MITRE T1518 — Software Discovery, defender side, plus
-- T1620 — Reflective Code Loading via runFullTrust, T1059 — Command
-- and Scripting Interpreter for full-trust shells):
--   - `has_run_full_trust=1` — the package declared the restricted
--     `runFullTrust` capability. It runs OUTSIDE the AppContainer
--     sandbox with the user's full token. Legitimate desktop
--     bridge apps (Outlook, Notepad++) do this; sideloaded apps
--     that ship the same capability are the headline finding.
--   - `has_broad_file_system_access=1` — `broadFileSystemAccess`
--     restricted capability. The package can read every file
--     the user can. Microsoft enforces this via Microsoft Store
--     review but it's trivially set on sideloaded MSIX.
--   - `is_sideloaded=1` — Publisher subject doesn't include the
--     Microsoft / Windows publisher CN. Sideloaded packages
--     skip the Store vetting pipeline (T1195 supply chain).
--   - Drift events — file_hash change on AppxManifest.xml = the
--     package was upgraded or replaced. Always alert-worthy.

CREATE TABLE IF NOT EXISTS host_msix_packages (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,         -- AppxManifest.xml
    file_hash                       TEXT NOT NULL,
    package_dir                     TEXT NOT NULL,         -- parent dir
    package_full_name               TEXT,                  -- "Microsoft.WindowsCalculator_11.2306.1.0_x64__8wekyb3d8bbwe"
    identity_name                   TEXT NOT NULL,         -- "Microsoft.WindowsCalculator"
    identity_version                TEXT NOT NULL,         -- "11.2306.1.0"
    identity_publisher              TEXT,                  -- full X.500
    identity_publisher_cn           TEXT,                  -- common name extracted
    identity_architecture           TEXT,                  -- "x64" / "x86" / "neutral"
    display_name                    TEXT,
    publisher_display_name          TEXT,
    application_count               INTEGER NOT NULL DEFAULT 0,
    primary_executable              TEXT,                  -- first <Application Executable=…>
    capabilities_json               TEXT NOT NULL DEFAULT '[]',
    capability_count                INTEGER NOT NULL DEFAULT 0,
    install_scope                   TEXT NOT NULL
                                    CHECK (install_scope IN (
                                        'machine-wide', 'per-user', 'unknown'
                                    )),
    has_run_full_trust              INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_run_full_trust IN (0, 1)),
    has_broad_file_system_access    INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_broad_file_system_access IN (0, 1)),
    has_allow_elevation             INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_allow_elevation IN (0, 1)),
    has_restricted_capability       INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_restricted_capability IN (0, 1)),
    is_microsoft_publisher          INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_microsoft_publisher IN (0, 1)),
    is_sideloaded                   INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_sideloaded IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_msix_packages_unique
    ON host_msix_packages(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_msix_packages_unsynced
    ON host_msix_packages(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me MSIX packages running full-trust" (sandbox
-- bypass — the headline finding).
CREATE INDEX IF NOT EXISTS idx_host_msix_packages_full_trust
    ON host_msix_packages(asset_id, identity_name)
    WHERE has_run_full_trust = 1;

-- Fast path: "show me sideloaded packages" (T1195.002 supply chain).
CREATE INDEX IF NOT EXISTS idx_host_msix_packages_sideload
    ON host_msix_packages(asset_id, identity_name, identity_publisher)
    WHERE is_sideloaded = 1;

-- Fast path: broadFileSystemAccess — package reads any user file.
CREATE INDEX IF NOT EXISTS idx_host_msix_packages_broad_fs
    ON host_msix_packages(asset_id, identity_name)
    WHERE has_broad_file_system_access = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_msix_packages_drift
    ON host_msix_packages(asset_id, file_path, file_hash);
