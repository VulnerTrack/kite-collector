-- 20260623700000_host_scheduled_tasks_xml.sql: durable storage for
-- per-host Windows Task Scheduler XML inventory introduced by CDMS
-- iter 63.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_scheduled_tasks_xml — one row per task XML file under
--                              C:\Windows\System32\Tasks\. The
--                              Task Scheduler stores every task as
--                              both an in-memory cache (HKLM Software
--                              \Microsoft\Windows NT\CurrentVersion
--                              \Schedule\TaskCache) AND as a single
--                              XML file on disk. This table mirrors
--                              the on-disk side so the audit pipeline
--                              has a hash for drift detection and a
--                              ground-truth view independent of the
--                              Task Scheduler service.
--
-- Audit value (MITRE T1053.005 — Scheduled Task/Job: Scheduled Task,
-- T1564 — Hide Artifacts):
--   - CWE-269 (Improper Privilege Management) — `is_third_party_system_persistence=1`
--     captures the headline implant shape: task under a non-Microsoft
--     directory, runs as SYSTEM, triggers on logon/boot, and is
--     marked Hidden=true.
--   - CWE-426 (Untrusted Search Path) — `is_command_in_world_writable_dir=1`
--     covers actions invoking a binary from C:\Users\Public,
--     %TEMP%, or any other path the local user can write.
--   - `is_hidden=1` on a non-Microsoft task = T1564.001 (Hidden
--     Files and Directories) signal; legitimate Apple-managed tools
--     never set Hidden=true.
--   - `runs_as_highest=1` paired with `runs_as_system=0` flags
--     tasks that elevate to the user's max token at run-time — the
--     common UAC-bypass primitive on UAC-protected admin accounts.
--   - Drift events — file_hash change on any task XML = the
--     persistence surface was modified. Always alert-worthy.

CREATE TABLE IF NOT EXISTS host_scheduled_tasks_xml (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    file_path                           TEXT NOT NULL,
    file_hash                           TEXT NOT NULL,
    task_path                           TEXT NOT NULL,         -- "\Microsoft\Windows\AppID\PolicyConverter"
    task_name                           TEXT NOT NULL,         -- "PolicyConverter"
    author                              TEXT,
    description                         TEXT,
    registration_date                   TEXT,
    uri                                 TEXT,
    principal_user_id                   TEXT,                  -- "S-1-5-18" / "EVILCORP\admin"
    principal_group_id                  TEXT,
    run_level                           TEXT,                  -- "LeastPrivilege" / "HighestAvailable"
    logon_type                          TEXT,                  -- "InteractiveToken" / "Password" / "S4U"
    triggers_json                       TEXT NOT NULL DEFAULT '[]',
    actions_json                        TEXT NOT NULL DEFAULT '[]',
    action_count                        INTEGER NOT NULL DEFAULT 0,
    trigger_count                       INTEGER NOT NULL DEFAULT 0,
    is_microsoft_managed                INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_microsoft_managed IN (0, 1)),
    is_enabled                          INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_enabled IN (0, 1)),
    is_hidden                           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_hidden IN (0, 1)),
    runs_as_system                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (runs_as_system IN (0, 1)),
    runs_as_highest                     INTEGER NOT NULL DEFAULT 0
                                        CHECK (runs_as_highest IN (0, 1)),
    has_logon_trigger                   INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_logon_trigger IN (0, 1)),
    has_boot_trigger                    INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_boot_trigger IN (0, 1)),
    has_idle_trigger                    INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_idle_trigger IN (0, 1)),
    has_event_trigger                   INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_event_trigger IN (0, 1)),
    is_command_in_world_writable_dir    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_command_in_world_writable_dir IN (0, 1)),
    is_third_party_system_persistence   INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_third_party_system_persistence IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_unique
    ON host_scheduled_tasks_xml(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_unsynced
    ON host_scheduled_tasks_xml(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me third-party SYSTEM persistence" (the headline
-- T1053.005 implant shape).
CREATE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_implant
    ON host_scheduled_tasks_xml(asset_id, task_path)
    WHERE is_third_party_system_persistence = 1;

-- Fast path: "show me commands invoked from world-writable dirs".
CREATE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_bad_path
    ON host_scheduled_tasks_xml(asset_id, task_path)
    WHERE is_command_in_world_writable_dir = 1;

-- Fast path: hidden non-Microsoft tasks (T1564.001).
CREATE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_hidden
    ON host_scheduled_tasks_xml(asset_id, task_path)
    WHERE is_hidden = 1 AND is_microsoft_managed = 0;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_scheduled_tasks_xml_file_hash
    ON host_scheduled_tasks_xml(asset_id, file_path, file_hash);
