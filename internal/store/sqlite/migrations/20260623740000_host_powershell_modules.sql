-- 20260623740000_host_powershell_modules.sql: durable storage for
-- per-host PowerShell module manifest inventory introduced by
-- CDMS iter 67.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_powershell_modules — one row per .psd1 manifest discovered
--                             under the standard PSModulePath roots:
--                               C:\Program Files\PowerShell\Modules
--                               C:\Program Files\PowerShell\7\Modules
--                               C:\Program Files\WindowsPowerShell\Modules
--                               C:\Windows\System32\WindowsPowerShell\v1.0\Modules
--                               %USERPROFILE%\Documents\PowerShell\Modules
--                               %USERPROFILE%\Documents\WindowsPowerShell\Modules
--                             The audit pipeline cross-references
--                             (module_name, module_version) against
--                             the supply-chain CVE feed for asset
--                             exposure.
--
-- Audit value (MITRE T1546 — Event Triggered Execution, defender
-- side, plus T1059.001 — PowerShell, T1195 — Supply Chain Compromise):
--   - CWE-732 (Incorrect Permission Assignment) —
--     `is_user_scoped=1` flags modules under the per-user Documents
--     path. Legitimate dev work happens here, but persistence
--     implants prefer this location because UAC isn't required.
--   - `has_binary_root_module=1` — RootModule points to a .dll
--     rather than a .psm1. Binary modules need Authenticode signing
--     to be trusted at scale; unsigned binaries are a T1059.001
--     execution surface.
--   - `is_missing_author=1` / `is_missing_company=1` — most
--     legitimate modules ship both. Missing values are common for
--     hand-rolled or implant modules.
--   - `has_root_module_outside_dir=1` — RootModule path escapes the
--     manifest's directory (e.g. `..\..\foo.dll`). Suspicious by
--     definition; legitimate manifests reference siblings only.
--   - Drift events — file_hash change on a .psd1 = the module
--     metadata was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_powershell_modules (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    module_name                 TEXT NOT NULL,         -- "Az.Accounts"
    module_version              TEXT,                  -- "2.12.1"
    guid                        TEXT,
    author                      TEXT,
    company_name                TEXT,
    copyright                   TEXT,
    description                 TEXT,
    powershell_version          TEXT,                  -- minimum
    clr_version                 TEXT,
    dotnet_framework_version    TEXT,
    root_module                 TEXT,                  -- "MyModule.psm1" or "bin/Foo.dll"
    install_scope               TEXT NOT NULL
                                CHECK (install_scope IN (
                                    'system', 'user', 'unknown'
                                )),
    is_user_scoped              INTEGER NOT NULL DEFAULT 0
                                CHECK (is_user_scoped IN (0, 1)),
    has_binary_root_module      INTEGER NOT NULL DEFAULT 0
                                CHECK (has_binary_root_module IN (0, 1)),
    is_missing_author           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_missing_author IN (0, 1)),
    is_missing_company          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_missing_company IN (0, 1)),
    has_root_module_outside_dir INTEGER NOT NULL DEFAULT 0
                                CHECK (has_root_module_outside_dir IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_powershell_modules_unique
    ON host_powershell_modules(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_powershell_modules_unsynced
    ON host_powershell_modules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me user-scoped modules" (potential T1546).
CREATE INDEX IF NOT EXISTS idx_host_powershell_modules_user_scope
    ON host_powershell_modules(asset_id, module_name)
    WHERE is_user_scoped = 1;

-- Fast path: "show me binary modules" (signing audit + supply chain).
CREATE INDEX IF NOT EXISTS idx_host_powershell_modules_binary
    ON host_powershell_modules(asset_id, module_name)
    WHERE has_binary_root_module = 1;

-- Fast path: "show me modules whose root escapes the module dir".
CREATE INDEX IF NOT EXISTS idx_host_powershell_modules_escape
    ON host_powershell_modules(asset_id, module_name)
    WHERE has_root_module_outside_dir = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_powershell_modules_file_hash
    ON host_powershell_modules(asset_id, file_path, file_hash);
