-- 20260623370000_host_mounts.sql: durable storage for per-host
-- filesystem mount inventory introduced by CDMS iter 26.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_mounts — one row per (asset_id, source, mountpoint). The
--                 collector reads /etc/fstab (declared mounts) and
--                 /proc/self/mountinfo (live mounts). macOS draws from
--                 /etc/fstab + `mount` output; Windows mounts surface
--                 via DOS drive letters (future iteration).
--
-- Audit value:
--   - CIS 1.1.x (Filesystem partitions) — `is_critical_path=1` flags
--     mountpoints in the standard sensitive set (/tmp, /var/tmp, /home,
--     /dev/shm, /var/log, /var/log/audit). CIS demands `nodev,nosuid,
--     noexec` on most of them; `has_recommended_options=0` flags the
--     deviation.
--   - CWE-732 (Incorrect Permission Assignment) — `nosuid` missing on
--     /home permits set-uid binaries dropped by a user account. Same
--     class of finding as `nodev` allowing a user to mknod a backdoor
--     character device.
--   - T1078 (Valid Accounts) — `is_remote=1` flags NFS/CIFS/SSHFS
--     mounts; cross-correlation against the auth audit shows credentials
--     in scope when remote shares are mounted.
--   - T1052.001 (Exfil over USB) — `is_removable=1` flags udev/autofs
--     mounts pointing at /media/* + /run/media/*; surfaces transient
--     USB activity.
--   - Drift events — file_hash drift on /etc/fstab + (configured option
--     set vs live option set) drift = the boot-time mount config or
--     the runtime overlay was modified.

CREATE TABLE IF NOT EXISTS host_mounts (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    source                   TEXT NOT NULL
                             CHECK (source IN (
                                 'fstab',
                                 'proc-mounts',
                                 'macos-mount',
                                 'windows-volumes',
                                 'unknown'
                             )),
    device                   TEXT NOT NULL,     -- "/dev/sda2", "UUID=...", "nfs:/share"
    mountpoint               TEXT NOT NULL,
    fstype                   TEXT NOT NULL,
    options_json             TEXT NOT NULL DEFAULT '[]',
    dump                     INTEGER NOT NULL DEFAULT 0,
    fsck_pass                INTEGER NOT NULL DEFAULT 0,
    is_remote                INTEGER NOT NULL DEFAULT 0
                             CHECK (is_remote IN (0, 1)),
    is_removable             INTEGER NOT NULL DEFAULT 0
                             CHECK (is_removable IN (0, 1)),
    is_encrypted             INTEGER NOT NULL DEFAULT 0
                             CHECK (is_encrypted IN (0, 1)),
    is_critical_path         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_critical_path IN (0, 1)),
    has_nodev                INTEGER NOT NULL DEFAULT 0
                             CHECK (has_nodev IN (0, 1)),
    has_nosuid               INTEGER NOT NULL DEFAULT 0
                             CHECK (has_nosuid IN (0, 1)),
    has_noexec               INTEGER NOT NULL DEFAULT 0
                             CHECK (has_noexec IN (0, 1)),
    is_read_only             INTEGER NOT NULL DEFAULT 0
                             CHECK (is_read_only IN (0, 1)),
    has_recommended_options  INTEGER NOT NULL DEFAULT 0
                             CHECK (has_recommended_options IN (0, 1)),
    file_path                TEXT,
    file_hash                TEXT,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_mounts_unique
    ON host_mounts(asset_id, source, mountpoint);

CREATE INDEX IF NOT EXISTS idx_host_mounts_unsynced
    ON host_mounts(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me critical-path mounts that violate CIS options".
CREATE INDEX IF NOT EXISTS idx_host_mounts_critical_no_recs
    ON host_mounts(asset_id, mountpoint)
    WHERE is_critical_path = 1 AND has_recommended_options = 0;

-- Fast path: "show me remote mounts" (credential surface).
CREATE INDEX IF NOT EXISTS idx_host_mounts_remote
    ON host_mounts(asset_id, device, mountpoint)
    WHERE is_remote = 1;

-- Fast path: "show me removable / USB mounts" (exfil surface).
CREATE INDEX IF NOT EXISTS idx_host_mounts_removable
    ON host_mounts(asset_id, mountpoint)
    WHERE is_removable = 1;

-- Drift detection on /etc/fstab.
CREATE INDEX IF NOT EXISTS idx_host_mounts_file_hash
    ON host_mounts(asset_id, file_path, file_hash);
