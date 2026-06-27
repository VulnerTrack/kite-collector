-- 20260623850000_host_dsc_resources.sql: durable storage for
-- per-host Windows Desired State Configuration (DSC) resource
-- inventory introduced by CDMS iter 78.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_dsc_resources — one row per `instance of MSFT_*` block
--                        parsed out of any .mof file in the
--                        canonical DSC state directory:
--                          %windir%\System32\Configuration\Current.mof
--                          %windir%\System32\Configuration\Pending.mof
--                          %windir%\System32\Configuration\Previous.mof
--                          %windir%\System32\Configuration\MetaConfig*.mof
--                        DSC is Windows' declarative-state engine;
--                        the audit pipeline pairs this table with
--                        host_powershell_modules so each
--                        ModuleName cross-references to the
--                        actual installed module on disk.
--
-- Audit value (MITRE T1543 — Create or Modify System Process,
-- defender side, plus T1037.001 — Boot or Logon Initialization
-- Scripts via DSC-applied scripts):
--   - `is_third_party_module=1` — ModuleName is NOT one of the
--     Microsoft-shipped DSC modules. Third-party modules are
--     legitimate but every one expands the supply-chain surface.
--   - `is_pending_state=1` — resource came from `Pending.mof`;
--     diffing `Current` vs `Pending` between scans = pending
--     configuration drift.
--   - `is_auto_correct_mode=1` — surfaces on the LCM meta-config
--     row when `ConfigurationMode=ApplyAndAutoCorrect`. DSC
--     auto-reverts every manual change; sometimes desirable,
--     sometimes a way to lose detection.
--   - Drift events — file_hash change on any of the MOFs deserves
--     a high-priority alert. Manual `Apply-DscConfiguration` calls
--     leave no other on-disk trace.

CREATE TABLE IF NOT EXISTS host_dsc_resources (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    mof_kind                    TEXT NOT NULL
                                CHECK (mof_kind IN (
                                    'current', 'pending', 'previous',
                                    'metaconfig', 'backup', 'unknown'
                                )),
    instance_type               TEXT NOT NULL,           -- "MSFT_FileDirectoryConfiguration"
    resource_id                 TEXT,                    -- "[File]EnsureFooExists"
    module_name                 TEXT,                    -- "PSDesiredStateConfiguration"
    module_version              TEXT,
    configuration_name          TEXT,                    -- "MyConfig"
    source_info                 TEXT,
    is_meta_config              INTEGER NOT NULL DEFAULT 0
                                CHECK (is_meta_config IN (0, 1)),
    is_pending_state            INTEGER NOT NULL DEFAULT 0
                                CHECK (is_pending_state IN (0, 1)),
    is_microsoft_module         INTEGER NOT NULL DEFAULT 0
                                CHECK (is_microsoft_module IN (0, 1)),
    is_third_party_module       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_third_party_module IN (0, 1)),
    is_auto_correct_mode        INTEGER NOT NULL DEFAULT 0
                                CHECK (is_auto_correct_mode IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_dsc_resources_unique
    ON host_dsc_resources(asset_id, file_path, resource_id, instance_type);

CREATE INDEX IF NOT EXISTS idx_host_dsc_resources_unsynced
    ON host_dsc_resources(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: third-party DSC modules (supply-chain surface).
CREATE INDEX IF NOT EXISTS idx_host_dsc_resources_third_party
    ON host_dsc_resources(asset_id, module_name, file_path)
    WHERE is_third_party_module = 1;

-- Fast path: pending drift (Pending.mof != Current.mof).
CREATE INDEX IF NOT EXISTS idx_host_dsc_resources_pending
    ON host_dsc_resources(asset_id, file_path)
    WHERE is_pending_state = 1;

-- Fast path: LCM in auto-correct mode (every change auto-reverts).
CREATE INDEX IF NOT EXISTS idx_host_dsc_resources_auto_correct
    ON host_dsc_resources(asset_id, file_path)
    WHERE is_auto_correct_mode = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_dsc_resources_drift
    ON host_dsc_resources(asset_id, file_path, file_hash);
