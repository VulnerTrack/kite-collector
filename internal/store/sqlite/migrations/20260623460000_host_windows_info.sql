-- 20260623460000_host_windows_info.sql: durable storage for per-host
-- Windows OS / identity baseline introduced by CDMS iter 35.
--
-- This is the first table of the MID Server-aligned Windows track:
-- one row per asset capturing the "what is this host?" baseline.
-- Subsequent Windows iterations (hardware/serial, CPU/memory, NICs,
-- storage, etc.) join against this row via asset_id.
--
-- Sources (PowerShell shim, no Go COM/WMI deps):
--   - Get-CimInstance Win32_ComputerSystem  (Name, Domain, Workgroup,
--                                            Manufacturer, Model,
--                                            UserName, TotalPhysicalMemory,
--                                            PartOfDomain)
--   - Get-CimInstance Win32_OperatingSystem (Caption, Version,
--                                            OSArchitecture,
--                                            InstallDate, LastBootUpTime)
--   - HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion (CurrentBuild,
--                                            UBR, DisplayVersion,
--                                            ProductName, EditionID)
--
-- Audit value:
--   - MITRE T1082 (System Information Discovery — defender side):
--     comprehensive asset inventory for CMDB. Cross-correlates with
--     host_users, host_listeners, host_services to map domain trust.
--   - Drift events — `os_build` or `os_ubr` change between scans =
--     Windows Update applied. Pair with KB list (future iter) for
--     patch-gap audit.
--   - `is_domain_joined=1` AND `domain` not matching the corporate
--     domain set = rogue host suspicion.
--   - `last_boot_up_time` < 30 days but `os_ubr` unchanged = uptime
--     is normal but patches aren't landing.

CREATE TABLE IF NOT EXISTS host_windows_info (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    source                   TEXT NOT NULL
                             CHECK (source IN (
                                 'powershell-cim', 'powershell-wmi',
                                 'unknown'
                             )),
    hostname                 TEXT NOT NULL DEFAULT '',
    domain                   TEXT,
    workgroup                TEXT,
    is_domain_joined         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_domain_joined IN (0, 1)),
    logged_on_user           TEXT,
    manufacturer             TEXT,
    model                    TEXT,
    total_physical_memory_bytes INTEGER NOT NULL DEFAULT 0,
    os_caption               TEXT,                  -- "Microsoft Windows 11 Pro"
    os_version               TEXT,                  -- "10.0.22631"
    os_build                 TEXT,                  -- "22631"
    os_ubr                   INTEGER NOT NULL DEFAULT 0, -- Update Build Revision
    os_display_version       TEXT,                  -- "23H2"
    os_product_name          TEXT,                  -- registry ProductName
    os_edition_id            TEXT,                  -- "Professional"
    os_architecture          TEXT,                  -- "64-bit" / "ARM 64-bit"
    install_date             TEXT,                  -- RFC3339
    last_boot_up_time        TEXT,                  -- RFC3339
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One row per asset.
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_info_asset
    ON host_windows_info(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_info_unsynced
    ON host_windows_info(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me domain-joined hosts outside the corp domain set".
CREATE INDEX IF NOT EXISTS idx_host_windows_info_domain
    ON host_windows_info(domain)
    WHERE is_domain_joined = 1;
