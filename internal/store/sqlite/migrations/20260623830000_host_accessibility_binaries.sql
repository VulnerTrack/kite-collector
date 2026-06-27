-- 20260623830000_host_accessibility_binaries.sql: durable storage
-- for per-host accessibility-binary hash audit introduced by CDMS
-- iter 76.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_accessibility_binaries — one row per curated accessibility
--                                 binary under %windir%\System32\.
--                                 The collector always emits a row
--                                 for every binary in the curated
--                                 set, even when the file is
--                                 missing — that itself is an
--                                 anomaly. The audit pipeline
--                                 cross-references (file_name,
--                                 file_hash) against the Microsoft
--                                 catalog to detect replacements.
--
-- Audit value (MITRE T1546.008 — Event Triggered Execution:
-- Accessibility Features, defender side):
--   - The classic attack: replace `C:\Windows\System32\sethc.exe`
--     with `cmd.exe`. At the logon screen, Shift x5 triggers
--     sethc.exe and spawns a SYSTEM shell.
--   - `is_cmd_size_match=1` — file size is within ±10% of the
--     well-known cmd.exe footprint (~289 KB on x64). Strong
--     signal that the original binary was overwritten.
--   - `is_powershell_size_match=1` — file size is within ±10% of
--     powershell.exe (~445 KB). The PowerShell-replacement
--     variant of the same attack.
--   - `is_missing=1` — the file is absent. Either a Windows
--     install variant (Server Core) or someone removed it; both
--     warrant investigation.
--   - Drift events — file_hash change on any of these binaries
--     between scans deserves a high-priority alert.

CREATE TABLE IF NOT EXISTS host_accessibility_binaries (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT,                     -- empty when missing
    file_name                   TEXT NOT NULL,            -- "sethc.exe"
    file_size_bytes             INTEGER NOT NULL DEFAULT 0,
    file_mtime                  INTEGER,
    is_missing                  INTEGER NOT NULL DEFAULT 0
                                CHECK (is_missing IN (0, 1)),
    is_cmd_size_match           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_cmd_size_match IN (0, 1)),
    is_powershell_size_match    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_powershell_size_match IN (0, 1)),
    is_replacement_suspect      INTEGER NOT NULL DEFAULT 0
                                CHECK (is_replacement_suspect IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_accessibility_binaries_unique
    ON host_accessibility_binaries(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_accessibility_binaries_unsynced
    ON host_accessibility_binaries(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: replacement candidates — T1546.008 headline.
CREATE INDEX IF NOT EXISTS idx_host_accessibility_binaries_replaced
    ON host_accessibility_binaries(asset_id, file_name)
    WHERE is_replacement_suspect = 1;

-- Fast path: missing binaries.
CREATE INDEX IF NOT EXISTS idx_host_accessibility_binaries_missing
    ON host_accessibility_binaries(asset_id, file_name)
    WHERE is_missing = 1;

-- Drift detection (hash change).
CREATE INDEX IF NOT EXISTS idx_host_accessibility_binaries_drift
    ON host_accessibility_binaries(asset_id, file_path, file_hash);
