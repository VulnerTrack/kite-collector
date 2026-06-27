-- 20260623140000_host_volumes.sql: durable storage for OS volume / mount
-- inventory introduced by CDMS iter 3.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_volumes — one row per (asset_id, mount_point) observed. Each
--                  rescan upserts; the DBOS bridge keeps historical
--                  capacity timelines in ClickHouse via synced_at.
--
-- `encryption` is the headline security signal: an `unencrypted` boot
-- volume on a portable device is a CWE-311 / CWE-312 finding (Cleartext
-- Storage of Sensitive Info). `encryption_state = locked` means the
-- volume is encrypted but currently sealed (e.g. unmounted BitLocker
-- container), which is a different posture than `unlocked`.

CREATE TABLE IF NOT EXISTS host_volumes (
    id                TEXT PRIMARY KEY NOT NULL,
    asset_id          TEXT NOT NULL,
    mount_point       TEXT NOT NULL,
    device            TEXT,
    filesystem        TEXT,
    label             TEXT,
    fs_uuid           TEXT,
    size_bytes        INTEGER,
    used_bytes        INTEGER,
    inodes_total      INTEGER,
    inodes_used       INTEGER,
    read_only         INTEGER NOT NULL DEFAULT 0
                      CHECK (read_only IN (0, 1)),
    removable         INTEGER NOT NULL DEFAULT 0
                      CHECK (removable IN (0, 1)),
    bootable          INTEGER NOT NULL DEFAULT 0
                      CHECK (bootable IN (0, 1)),
    encryption        TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (encryption IN (
                          'none', 'luks', 'luks2',
                          'bitlocker', 'filevault2',
                          'apfs-encrypted', 'unknown'
                      )),
    encryption_state  TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (encryption_state IN (
                          'locked', 'unlocked', 'unknown'
                      )),
    mount_opts        TEXT,
    last_seen_at      TEXT NOT NULL,
    collected_at      TEXT NOT NULL,
    synced_at         INTEGER,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_volumes_unique
    ON host_volumes(asset_id, mount_point);

CREATE INDEX IF NOT EXISTS idx_host_volumes_unsynced
    ON host_volumes(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-311 finding: "show me hosts with unencrypted boot volumes".
CREATE INDEX IF NOT EXISTS idx_host_volumes_unencrypted_boot
    ON host_volumes(asset_id, bootable, encryption)
    WHERE bootable = 1 AND encryption IN ('none', 'unknown');
