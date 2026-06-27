-- 20260623780000_host_office_addins.sql: durable storage for
-- per-host Office add-in / startup-folder inventory introduced
-- by CDMS iter 71.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_office_addins — one row per file discovered under any
--                        of the canonical Office add-in or
--                        application-startup directories. The
--                        Word/Excel/Outlook hosts load every
--                        file in these directories at app
--                        launch — they're the on-disk surface
--                        of MITRE T1137 Office Application
--                        Startup persistence.
--
-- Audit value (MITRE T1137 — Office Application Startup, plus
-- the per-product sub-techniques):
--   - T1137.001 (Office Template Macros) — `.dotm` / `.xltm` /
--     `.potm` etc. in Word's STARTUP\ or Excel's XLSTART\.
--   - T1137.002 (Office Test) — `.dll` referenced from registry
--     under HKCU\Software\Microsoft\Office test\Special\Perf;
--     this collector covers the on-disk file half — registry
--     audit lives elsewhere.
--   - T1137.003 (Outlook Forms / Rules / Home Page) — Outlook
--     `VbaProject.OTM` carries any custom Outlook VBA that
--     auto-runs on profile load.
--   - T1137.006 (Add-Ins) — `*.wll` / `*.xll` (Word/Excel
--     native add-in DLLs) plus `*.xla*` Excel auto-open
--     workbooks.
--
-- File-based discovery is the deliberate design choice: every
-- Office host walks these directories at launch; there's no
-- API to "list everything that will auto-load". The audit
-- pipeline cross-references (file_name, file_hash) against
-- vendor whitelists for known-good add-ins (e.g. Bloomberg,
-- ThinkOrSwim) and known-bad hashes for off-the-shelf VBA
-- droppers.

CREATE TABLE IF NOT EXISTS host_office_addins (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    file_name                   TEXT NOT NULL,
    file_extension              TEXT NOT NULL,
    file_size_bytes             INTEGER NOT NULL DEFAULT 0,
    file_mtime                  INTEGER,
    user_profile                TEXT,                  -- "" when machine-wide
    office_host                 TEXT NOT NULL          -- which Office host loads it
                                CHECK (office_host IN (
                                    'word', 'excel', 'powerpoint',
                                    'outlook', 'office-shared',
                                    'unknown'
                                )),
    scope                       TEXT NOT NULL          -- per-user vs. machine-wide
                                CHECK (scope IN (
                                    'per-user', 'machine-wide', 'unknown'
                                )),
    is_macro_enabled_extension  INTEGER NOT NULL DEFAULT 0
                                CHECK (is_macro_enabled_extension IN (0, 1)),
    is_native_addin_dll         INTEGER NOT NULL DEFAULT 0
                                CHECK (is_native_addin_dll IN (0, 1)),
    is_machine_wide             INTEGER NOT NULL DEFAULT 0
                                CHECK (is_machine_wide IN (0, 1)),
    is_outlook_vba_project      INTEGER NOT NULL DEFAULT 0
                                CHECK (is_outlook_vba_project IN (0, 1)),
    is_persistence_candidate    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_persistence_candidate IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_office_addins_unique
    ON host_office_addins(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_office_addins_unsynced
    ON host_office_addins(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me persistence candidates" (T1137 union).
CREATE INDEX IF NOT EXISTS idx_host_office_addins_persistence
    ON host_office_addins(asset_id, office_host, file_path)
    WHERE is_persistence_candidate = 1;

-- Fast path: "show me machine-wide add-ins" (runs for every user).
CREATE INDEX IF NOT EXISTS idx_host_office_addins_machine
    ON host_office_addins(asset_id, office_host, file_path)
    WHERE is_machine_wide = 1;

-- Fast path: "show me Outlook VBA project files" (T1137.003).
CREATE INDEX IF NOT EXISTS idx_host_office_addins_outlook_vba
    ON host_office_addins(asset_id, user_profile, file_path)
    WHERE is_outlook_vba_project = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_office_addins_drift
    ON host_office_addins(asset_id, file_path, file_hash);
