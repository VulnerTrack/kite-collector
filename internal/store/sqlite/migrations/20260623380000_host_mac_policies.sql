-- 20260623380000_host_mac_policies.sql: durable storage for per-host
-- Mandatory Access Control (MAC) state introduced by CDMS iter 27.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_mac_policies — one row per (asset_id, subsystem, profile_name).
--                       SELinux contributes the subsystem-wide row
--                       (profile_name=NULL) from /etc/selinux/config.
--                       AppArmor contributes one row per profile file
--                       in /etc/apparmor.d/. The live /sys/kernel/
--                       security/lsm list contributes one row per loaded
--                       LSM (profile_name=NULL, mode=enabled).
--
-- Audit value:
--   - MITRE T1562.001 (Disable or Modify Tools) — `is_enforcing=0` on
--     SELinux or `mode='complain'` on an AppArmor profile means MAC
--     no longer blocks the protected operations, only logs them.
--     Drift from enforcing → permissive is the canonical attacker
--     prep step before escalating exploits.
--   - CWE-693 (Protection Mechanism Failure) — the entire SELinux
--     subsystem being `mode='disabled'` is a complete bypass.
--   - Drift events — `file_hash` change on /etc/selinux/config or
--     any /etc/apparmor.d/* file = a policy modification. The
--     audit pipeline compares the configured mode vs the live LSM
--     row to detect "config says enforcing but kernel says permissive"
--     scenarios (runtime tamper without persistence).

CREATE TABLE IF NOT EXISTS host_mac_policies (
    id              TEXT PRIMARY KEY NOT NULL,
    asset_id        TEXT NOT NULL,
    subsystem       TEXT NOT NULL
                    CHECK (subsystem IN (
                        'selinux', 'apparmor', 'tomoyo', 'smack',
                        'yama', 'landlock', 'bpf-lsm', 'lsm-list',
                        'unknown'
                    )),
    profile_name    TEXT NOT NULL DEFAULT '',
    mode            TEXT NOT NULL
                    CHECK (mode IN (
                        'enforcing', 'permissive', 'disabled',
                        'complain', 'kill', 'enabled',
                        'audit', 'unknown'
                    )),
    policy_type     TEXT,                          -- targeted/mls/strict/...
    target_path     TEXT,                          -- binary path for AppArmor profiles
    is_enforcing    INTEGER NOT NULL DEFAULT 0
                    CHECK (is_enforcing IN (0, 1)),
    is_loaded       INTEGER NOT NULL DEFAULT 0
                    CHECK (is_loaded IN (0, 1)),
    file_path       TEXT,
    file_hash       TEXT,
    line_no         INTEGER NOT NULL DEFAULT 0,
    raw_line        TEXT,
    last_seen_at    TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    synced_at       INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_mac_policies_unique
    ON host_mac_policies(asset_id, subsystem, profile_name);

CREATE INDEX IF NOT EXISTS idx_host_mac_policies_unsynced
    ON host_mac_policies(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me MAC subsystems that aren't enforcing".
CREATE INDEX IF NOT EXISTS idx_host_mac_policies_not_enforcing
    ON host_mac_policies(asset_id, subsystem)
    WHERE is_enforcing = 0;

-- Fast path: "show me AppArmor profiles in complain mode".
CREATE INDEX IF NOT EXISTS idx_host_mac_policies_complain
    ON host_mac_policies(asset_id, profile_name)
    WHERE subsystem = 'apparmor' AND mode = 'complain';

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_mac_policies_file_hash
    ON host_mac_policies(asset_id, file_path, file_hash);
