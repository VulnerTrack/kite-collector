-- 20260623600000_host_launch_services.sql: durable storage for per-host
-- macOS launchd service inventory introduced by CDMS iter 53.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_launch_services — one row per plist found under
--                          /Library/LaunchDaemons,
--                          /Library/LaunchAgents,
--                          ~/Library/LaunchAgents and the System
--                          counterparts. plist_scope distinguishes
--                          system-daemon (root) from user-agent (per
--                          user session) and per-user-agent (lives in
--                          the home dir, runs as that user).
--
-- Audit value (MITRE T1543.004 — Launch Daemon, T1547.011 — Plist
-- Modification, T1546 — Event Triggered Execution):
--   - CWE-732 (Incorrect Permission Assignment) — `is_plist_writable_by_other=1`
--     on a /Library/LaunchDaemons plist means any local user can edit
--     what root executes at next boot. Headline persistence finding.
--   - CWE-426 (Untrusted Search Path) — `is_program_in_world_writable_dir=1`
--     covers /tmp/, /Users/Shared/, /private/var/folders/ targets.
--     The audit pipeline alerts on any daemon whose Program leaks
--     execution into a world-writable directory.
--   - CWE-269 (Improper Privilege Management) — `runs_as_root=1` on
--     non-Apple plists (LabelDomain not com.apple.*) marks third-party
--     services that boot with full root.
--   - Drift events — file_hash change on a plist = persistence
--     surface was modified, often the first signal of a Defense
--     Evasion campaign.

CREATE TABLE IF NOT EXISTS host_launch_services (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    file_path                           TEXT NOT NULL,
    file_hash                           TEXT NOT NULL,
    plist_scope                         TEXT NOT NULL
                                        CHECK (plist_scope IN (
                                            'system-daemon', 'system-agent',
                                            'user-agent', 'unknown'
                                        )),
    label                               TEXT NOT NULL,
    label_domain                        TEXT,                   -- "com.apple" / "com.docker" / etc
    program                             TEXT,
    program_arguments_json              TEXT NOT NULL DEFAULT '[]',
    watch_paths_json                    TEXT NOT NULL DEFAULT '[]',
    user_name                           TEXT,
    group_name                          TEXT,
    working_directory                   TEXT,
    standard_out_path                   TEXT,
    standard_error_path                 TEXT,
    start_interval_seconds              INTEGER,
    file_mode                           INTEGER,                -- octal int (0644 = 420)
    file_owner_uid                      INTEGER,
    file_owner_gid                      INTEGER,
    is_disabled                         INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_disabled IN (0, 1)),
    is_run_at_load                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_run_at_load IN (0, 1)),
    is_keep_alive                       INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_keep_alive IN (0, 1)),
    has_start_calendar_interval         INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_start_calendar_interval IN (0, 1)),
    has_watch_paths                     INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_watch_paths IN (0, 1)),
    runs_as_root                        INTEGER NOT NULL DEFAULT 0
                                        CHECK (runs_as_root IN (0, 1)),
    is_apple_signed_domain              INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_apple_signed_domain IN (0, 1)),
    is_plist_owned_by_root              INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_plist_owned_by_root IN (0, 1)),
    is_plist_writable_by_group          INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_plist_writable_by_group IN (0, 1)),
    is_plist_writable_by_other          INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_plist_writable_by_other IN (0, 1)),
    is_program_in_world_writable_dir    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_program_in_world_writable_dir IN (0, 1)),
    is_persistent_third_party_root      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_persistent_third_party_root IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_launch_services_unique
    ON host_launch_services(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_launch_services_unsynced
    ON host_launch_services(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me daemon plists writable by non-root"
-- (T1543.004 modify-the-thing-root-runs-at-boot).
CREATE INDEX IF NOT EXISTS idx_host_launch_services_writable
    ON host_launch_services(asset_id, file_path, label)
    WHERE is_plist_writable_by_other = 1 AND plist_scope = 'system-daemon';

-- Fast path: "show me third-party daemons that boot as root".
CREATE INDEX IF NOT EXISTS idx_host_launch_services_third_party_root
    ON host_launch_services(asset_id, label, program)
    WHERE is_persistent_third_party_root = 1;

-- Fast path: program in a world-writable dir.
CREATE INDEX IF NOT EXISTS idx_host_launch_services_bad_path
    ON host_launch_services(asset_id, label, program)
    WHERE is_program_in_world_writable_dir = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_launch_services_file_hash
    ON host_launch_services(asset_id, file_path, file_hash);
