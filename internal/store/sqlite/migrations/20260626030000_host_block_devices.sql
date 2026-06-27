-- host_block_devices inventories enumerable block devices on
-- the host: disks (HDD/SSD/NVMe), removable media (USB stick,
-- SD card), virtio-blk, loop devices, RAID arrays, LVM logical
-- volumes, and dm-crypt mappings.
--
-- Linux source:   /sys/block/<dev>/{size,queue/rotational,...}
-- macOS source:   diskutil list -plist
-- Windows source: Get-PhysicalDisk + Get-Disk
--
-- Read-only by intent.

CREATE TABLE IF NOT EXISTS host_block_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    name            TEXT    NOT NULL,
    device_path     TEXT    NOT NULL DEFAULT '',
    bus             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (bus IN (
            'unknown','sata','sas','scsi','nvme','usb','virtio',
            'mmc','sd','xen-blk','floppy','iscsi','nbd','loop',
            'dm','md','zram','rbd','ata','pcie-direct','other'
        )),
    media_type      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (media_type IN (
            'unknown','hdd','ssd','nvme-ssd','removable',
            'optical','virtual','loop','ramdisk','tape','other'
        )),
    model           TEXT    NOT NULL DEFAULT '',
    vendor          TEXT    NOT NULL DEFAULT '',
    firmware        TEXT    NOT NULL DEFAULT '',
    serial_hash     TEXT    NOT NULL DEFAULT '',
    wwn             TEXT    NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    logical_sector  INTEGER NOT NULL DEFAULT 0,
    physical_sector INTEGER NOT NULL DEFAULT 0,
    queue_depth     INTEGER NOT NULL DEFAULT 0,
    rotation_rpm    INTEGER NOT NULL DEFAULT 0,
    is_rotational   INTEGER NOT NULL DEFAULT 0 CHECK (is_rotational IN (0,1)),
    is_removable    INTEGER NOT NULL DEFAULT 0 CHECK (is_removable IN (0,1)),
    is_read_only    INTEGER NOT NULL DEFAULT 0 CHECK (is_read_only IN (0,1)),
    has_smart       INTEGER NOT NULL DEFAULT 0 CHECK (has_smart IN (0,1)),
    is_encrypted    INTEGER NOT NULL DEFAULT 0 CHECK (is_encrypted IN (0,1)),
    holder_count    INTEGER NOT NULL DEFAULT 0,
    is_holder_of_lvm INTEGER NOT NULL DEFAULT 0 CHECK (is_holder_of_lvm IN (0,1)),
    is_holder_of_raid INTEGER NOT NULL DEFAULT 0 CHECK (is_holder_of_raid IN (0,1)),
    is_unencrypted_removable_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_unencrypted_removable_risk IN (0,1)),
    is_no_smart_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_no_smart_risk IN (0,1)),
    is_recent       INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_block_bus      ON host_block_devices(bus);
CREATE INDEX IF NOT EXISTS idx_block_media    ON host_block_devices(media_type);
CREATE INDEX IF NOT EXISTS idx_block_remov    ON host_block_devices(name) WHERE is_removable = 1;
CREATE INDEX IF NOT EXISTS idx_block_enc      ON host_block_devices(name) WHERE is_encrypted = 1;
CREATE INDEX IF NOT EXISTS idx_block_risk_un  ON host_block_devices(name) WHERE is_unencrypted_removable_risk = 1;
CREATE INDEX IF NOT EXISTS idx_block_no_smart ON host_block_devices(name) WHERE is_no_smart_risk = 1;
