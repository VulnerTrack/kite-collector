-- 20260623440000_host_udev_rules.sql: durable storage for per-host
-- udev rule inventory introduced by CDMS iter 33.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_udev_rules — one row per (asset_id, file_path, line_no).
--                     The collector parses /etc/udev/rules.d/*,
--                     /usr/lib/udev/rules.d/*, /lib/udev/rules.d/*,
--                     and /run/udev/rules.d/*. macOS uses IOKit (no
--                     equivalent); Windows uses INF + driver packages.
--
-- Audit value:
--   - MITRE T1547.010 / T1546 (Event Triggered Execution) — a udev
--     rule whose RUN+= invokes an attacker-controlled script on USB
--     attach is a one-line persistence primitive. Boot-time too:
--     ACTION=="add" + KERNEL=="sd*" triggers on every device-attach
--     while the host is up.
--   - CWE-732 (Incorrect Permission Assignment) — `MODE=0666` or
--     world-writable MODE values on critical device classes (disk,
--     network) flag write access for unprivileged users.
--   - CWE-426 (Untrusted Search Path) — `is_dangerous_run=1` flags
--     RUN+= paths that point inside /tmp, /home, /var/tmp, or any
--     world-writable directory. Even root execution of those triggers
--     is a privilege-escalation primitive.
--   - Drift events — file_hash change on any /etc/udev/rules.d file
--     = the device-attach behaviour was modified.

CREATE TABLE IF NOT EXISTS host_udev_rules (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    scope               TEXT NOT NULL
                        CHECK (scope IN (
                            'admin', 'vendor', 'runtime', 'unknown'
                        )),
    match_keys_json     TEXT NOT NULL DEFAULT '[]', -- ["SUBSYSTEM==usb","ACTION==add"]
    action_keys_json    TEXT NOT NULL DEFAULT '[]', -- ["RUN+=/usr/local/bin/x","MODE=0666"]
    subsystem           TEXT,                       -- "usb" / "block" / "net" / NULL
    kernel              TEXT,                       -- "sd*" / "wlan*" / NULL
    action              TEXT,                       -- "add" / "remove" / "change" / NULL
    run_command         TEXT,                       -- RUN+= command, NULL when absent
    mode_value          TEXT,                       -- "0660" / "0666" / NULL
    owner               TEXT,
    group_name          TEXT,
    has_run             INTEGER NOT NULL DEFAULT 0
                        CHECK (has_run IN (0, 1)),
    has_import          INTEGER NOT NULL DEFAULT 0
                        CHECK (has_import IN (0, 1)),
    is_world_writable_mode INTEGER NOT NULL DEFAULT 0
                        CHECK (is_world_writable_mode IN (0, 1)),
    is_dangerous_run    INTEGER NOT NULL DEFAULT 0
                        CHECK (is_dangerous_run IN (0, 1)),
    is_critical_subsystem INTEGER NOT NULL DEFAULT 0
                        CHECK (is_critical_subsystem IN (0, 1)),
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_udev_rules_unique
    ON host_udev_rules(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_udev_rules_unsynced
    ON host_udev_rules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me udev rules executing programs from sketchy paths".
CREATE INDEX IF NOT EXISTS idx_host_udev_rules_dangerous_run
    ON host_udev_rules(asset_id, run_command)
    WHERE is_dangerous_run = 1;

-- Fast path: "show me udev rules opening devices to world-write".
CREATE INDEX IF NOT EXISTS idx_host_udev_rules_world_writable
    ON host_udev_rules(asset_id, subsystem, kernel)
    WHERE is_world_writable_mode = 1;

-- Fast path: "show me RUN+= on critical subsystems (block/net/input)".
CREATE INDEX IF NOT EXISTS idx_host_udev_rules_run_critical
    ON host_udev_rules(asset_id, subsystem)
    WHERE has_run = 1 AND is_critical_subsystem = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_udev_rules_file_hash
    ON host_udev_rules(asset_id, file_path, file_hash);
