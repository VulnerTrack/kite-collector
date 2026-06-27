-- 20260623770000_host_startup_items.sql: durable storage for
-- per-host Windows Startup folder inventory introduced by CDMS
-- iter 70.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_startup_items — one row per file discovered under any of
--                        the canonical Startup directories:
--                          All-Users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*
--                          Per-User:  C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*
--                        Each .lnk gets a best-effort target_path
--                        extracted from the LinkInfo.LocalBasePath
--                        block; non-.lnk files are recorded as-is.
--
-- Audit value (MITRE T1547.001 — Boot or Logon Autostart Execution:
-- Registry Run Keys / Startup Folder, defender side):
--   - The entire table is a persistence ledger. Every file here
--     runs the next time a user (or any user, for All-Users
--     scope) logs in.
--   - `is_all_users_scope=1` is the headline: an attacker that
--     drops a .lnk under ProgramData gains persistence for every
--     account on the machine, not just one user.
--   - `is_executable_extension=1` flags .exe/.bat/.vbs/.ps1/.cmd
--     dropped *directly* in the Startup folder (skipping the
--     usual .lnk indirection). Microsoft installers always ship
--     .lnk; direct executables are a strong implant signal.
--   - `is_target_in_world_writable_dir=1` flags resolved .lnk
--     targets under C:\Users\Public, %TEMP%, etc. The audit
--     pipeline alerts even when the .lnk itself is signed.
--   - Drift events — file_hash change between scans = the
--     persistence surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_startup_items (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    file_name                       TEXT NOT NULL,
    file_extension                  TEXT NOT NULL,        -- ".lnk" / ".exe" / ".bat"
    file_size_bytes                 INTEGER NOT NULL DEFAULT 0,
    file_mtime                      INTEGER,              -- unix epoch
    user_profile                    TEXT,                 -- user name for per-user rows; "" for ProgramData
    scope                           TEXT NOT NULL
                                    CHECK (scope IN (
                                        'all-users', 'per-user', 'unknown'
                                    )),
    target_path                     TEXT,                 -- .lnk LocalBasePath when resolvable
    is_all_users_scope              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_all_users_scope IN (0, 1)),
    is_executable_extension         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_executable_extension IN (0, 1)),
    is_shortcut                     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_shortcut IN (0, 1)),
    is_target_in_world_writable_dir INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_target_in_world_writable_dir IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_startup_items_unique
    ON host_startup_items(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_startup_items_unsynced
    ON host_startup_items(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me All-Users startup items" (system-wide persistence).
CREATE INDEX IF NOT EXISTS idx_host_startup_items_all_users
    ON host_startup_items(asset_id, file_name)
    WHERE is_all_users_scope = 1;

-- Fast path: "show me executable drops" (no .lnk indirection).
CREATE INDEX IF NOT EXISTS idx_host_startup_items_exe_drop
    ON host_startup_items(asset_id, file_path)
    WHERE is_executable_extension = 1;

-- Fast path: "show me targets in world-writable dirs".
CREATE INDEX IF NOT EXISTS idx_host_startup_items_bad_target
    ON host_startup_items(asset_id, file_path, target_path)
    WHERE is_target_in_world_writable_dir = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_startup_items_drift
    ON host_startup_items(asset_id, file_path, file_hash);
