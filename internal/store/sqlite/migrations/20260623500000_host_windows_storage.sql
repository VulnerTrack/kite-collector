-- 20260623500000_host_windows_storage.sql: per-host Windows storage
-- inventory introduced by CDMS iter 39.
--
-- Two related tables in one migration:
--
--   host_windows_disks    — one row per physical disk (Win32_DiskDrive
--                           left-joined with MSFT_Disk via SerialNumber
--                           when both are available). Captures bus type,
--                           health, size, removable/boot flags.
--
--   host_windows_volumes  — one row per logical volume (Win32_LogicalDisk
--                           joined with Win32_Volume by DeviceID, plus
--                           Get-BitLockerVolume protection status). Captures
--                           drive letter, filesystem, capacity/free, BitLocker
--                           state.
--
-- Audit value (MITRE T1082 + adjacent techniques):
--   - CWE-311 (Cleartext Storage) — `bitlocker_protection_status` != 'On'
--     on a fixed local drive (drive_type=3) is the headline finding.
--     The audit pipeline correlates against host_windows_info to spot
--     domain-joined hosts shipping unencrypted laptops out the door.
--   - MITRE T1052.001 (Exfil over USB) — `drive_type=2` (removable)
--     rows expose ongoing USB-stick mounts; the audit pipeline alerts
--     when a USB drive appears for the first time on a fleet host.
--   - MITRE T1078 (Valid Accounts) — `drive_type=4` (network) rows
--     enumerate mounted SMB/CIFS shares with stored credentials in
--     scope.
--   - `is_dirty=1` flags volumes with the NTFS dirty bit — a forensic
--     marker that the file system shut down uncleanly.

CREATE TABLE IF NOT EXISTS host_windows_disks (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'powershell-cim', 'powershell-wmi', 'unknown'
                        )),
    device_id           TEXT NOT NULL,        -- "\\\\.\\PHYSICALDRIVE0"
    model               TEXT,
    manufacturer        TEXT,
    interface_type      TEXT,                  -- "IDE", "SCSI", "USB", "1394"
    serial_number       TEXT,
    firmware_revision   TEXT,
    media_type          TEXT,                  -- "Fixed hard disk media"
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    partition_count     INTEGER NOT NULL DEFAULT 0,
    bus_type            TEXT,                  -- MSFT_Disk: "NVMe","SATA","USB","SAS"
    health_status       TEXT,                  -- MSFT_Disk: "Healthy","Unhealthy"
    operational_status  TEXT,                  -- MSFT_Disk: "Online","Offline"
    is_boot             INTEGER NOT NULL DEFAULT 0 CHECK (is_boot IN (0, 1)),
    is_system           INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
    is_offline          INTEGER NOT NULL DEFAULT 0 CHECK (is_offline IN (0, 1)),
    is_read_only        INTEGER NOT NULL DEFAULT 0 CHECK (is_read_only IN (0, 1)),
    is_removable        INTEGER NOT NULL DEFAULT 0 CHECK (is_removable IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_disks_unique
    ON host_windows_disks(asset_id, device_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_disks_unsynced
    ON host_windows_disks(synced_at)
    WHERE synced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_host_windows_disks_unhealthy
    ON host_windows_disks(asset_id, device_id)
    WHERE health_status IS NOT NULL AND health_status != 'Healthy';

CREATE TABLE IF NOT EXISTS host_windows_volumes (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    source                      TEXT NOT NULL
                                CHECK (source IN (
                                    'powershell-cim', 'powershell-wmi', 'unknown'
                                )),
    device_id                   TEXT NOT NULL,   -- "C:" / "\\?\Volume{...}"
    drive_letter                TEXT,            -- "C:"  (NULL when unmounted)
    label                       TEXT,
    file_system                 TEXT,            -- "NTFS","ReFS","FAT32","exFAT"
    capacity_bytes              INTEGER NOT NULL DEFAULT 0,
    free_space_bytes            INTEGER NOT NULL DEFAULT 0,
    serial_number               TEXT,            -- Win32_Volume.SerialNumber (uint32)
    drive_type                  INTEGER NOT NULL DEFAULT 0,
                                -- 0=unknown 1=no-root 2=removable 3=local
                                -- 4=network 5=cdrom 6=ramdisk
    is_dirty                    INTEGER NOT NULL DEFAULT 0 CHECK (is_dirty IN (0, 1)),
    is_boot_volume              INTEGER NOT NULL DEFAULT 0 CHECK (is_boot_volume IN (0, 1)),
    is_system_volume            INTEGER NOT NULL DEFAULT 0 CHECK (is_system_volume IN (0, 1)),
    is_compressed               INTEGER NOT NULL DEFAULT 0 CHECK (is_compressed IN (0, 1)),
    bitlocker_protection_status TEXT,            -- "On","Off","Unknown","NotApplicable"
    bitlocker_encryption_method TEXT,            -- "Xts-Aes256","Aes256","None"
    bitlocker_volume_status     TEXT,            -- "FullyEncrypted","FullyDecrypted","..."
    is_unencrypted_fixed_drive  INTEGER NOT NULL DEFAULT 0
                                CHECK (is_unencrypted_fixed_drive IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_volumes_unique
    ON host_windows_volumes(asset_id, device_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_volumes_unsynced
    ON host_windows_volumes(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me unencrypted fixed drives" (CWE-311).
CREATE INDEX IF NOT EXISTS idx_host_windows_volumes_unencrypted
    ON host_windows_volumes(asset_id, drive_letter)
    WHERE is_unencrypted_fixed_drive = 1;

-- Fast path: "show me removable / network drives currently mounted".
CREATE INDEX IF NOT EXISTS idx_host_windows_volumes_external
    ON host_windows_volumes(asset_id, drive_letter)
    WHERE drive_type IN (2, 4);
