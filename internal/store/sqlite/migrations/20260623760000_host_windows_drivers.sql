-- 20260623760000_host_windows_drivers.sql: durable storage for
-- per-host Windows kernel driver inventory introduced by CDMS
-- iter 69.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_windows_drivers — one row per driver file discovered
--                          under C:\Windows\System32\drivers\
--                          (recursive). The Windows kernel loads
--                          .sys files from this directory; the
--                          DriverStore at
--                          C:\Windows\System32\DriverStore\FileRepository\
--                          is the staged copy. The audit pipeline
--                          cross-references (file_name, sha256) with
--                          the loldrivers.io BYOVD catalog and the
--                          Microsoft vulnerable-driver blocklist.
--
-- Audit value (MITRE T1068 — Exploitation for Privilege Escalation,
-- T1547.006 — Boot or Logon Autostart Execution: Kernel Modules
-- and Extensions, plus T1014 — Rootkit):
--   - The whole table is supply-chain evidence: every kernel
--     driver runs at ring 0. A single match against the
--     loldrivers blocklist = textbook BYOVD privesc primitive.
--   - `has_non_sys_extension=1` flags files with .exe, .dll, .ini,
--     or any non-.sys extension sitting in the drivers tree. .ini
--     manifest companions are normal; .exe / .dll inside the
--     drivers tree is a strong implant signal.
--   - `is_third_party_subdir=1` — the driver lives under a
--     vendor-named subdirectory inside drivers\ rather than
--     directly at the top. Vendor subdirectories are legitimate
--     but worth grouping in the audit report.
--   - Drift events — file_hash change on a driver = the kernel
--     surface was modified between scans. Always alert-worthy.

CREATE TABLE IF NOT EXISTS host_windows_drivers (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,        -- SHA-256 hex
    file_name                   TEXT NOT NULL,        -- "ntfs.sys"
    file_extension              TEXT NOT NULL,        -- ".sys"
    file_size_bytes             INTEGER NOT NULL DEFAULT 0,
    file_mtime                  INTEGER,              -- unix epoch
    parent_subdir               TEXT NOT NULL,        -- "" (top), "UMDF", "VendorX", "Setup", "DriverStore"
    source_root                 TEXT NOT NULL
                                CHECK (source_root IN (
                                    'system32-drivers',
                                    'driver-store',
                                    'unknown'
                                )),
    has_non_sys_extension       INTEGER NOT NULL DEFAULT 0
                                CHECK (has_non_sys_extension IN (0, 1)),
    is_third_party_subdir       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_third_party_subdir IN (0, 1)),
    is_top_level                INTEGER NOT NULL DEFAULT 0
                                CHECK (is_top_level IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_drivers_unique
    ON host_windows_drivers(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_windows_drivers_unsynced
    ON host_windows_drivers(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: BYOVD correlation. The audit pipeline joins on
-- (file_name, file_hash) against the loldrivers.io feed.
CREATE INDEX IF NOT EXISTS idx_host_windows_drivers_hash
    ON host_windows_drivers(asset_id, file_name, file_hash);

-- Fast path: "show me non-.sys files sitting in the drivers tree".
CREATE INDEX IF NOT EXISTS idx_host_windows_drivers_oddball
    ON host_windows_drivers(asset_id, file_path)
    WHERE has_non_sys_extension = 1 AND source_root = 'system32-drivers';

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_windows_drivers_drift
    ON host_windows_drivers(asset_id, file_path, file_hash);
