-- host_dmi_smbios captures the SMBIOS (DMI) hardware fingerprint
-- of the host: BIOS vendor/version/date, motherboard, chassis,
-- system manufacturer / product / serial / UUID. Single-row per
-- machine (SMBIOS reports one System Information structure).
--
-- Linux source:   /sys/class/dmi/id/{bios_*,sys_*,board_*,chassis_*,product_*}
-- macOS source:   ioreg -d2 -c IOPlatformExpertDevice
-- Windows source: WMI Win32_BIOS, Win32_ComputerSystem, Win32_BaseBoard
-- FreeBSD source: kenv | grep smbios.
--
-- Security shapes:
--   * Out-of-date BIOS (bios_date older than N months)
--   * BMC-shipping vendor + ChassisType server → BMC inventory candidate
--   * Virtualized chassis (QEMU/VMware/Hyper-V) detected from manufacturer

CREATE TABLE IF NOT EXISTS host_dmi_smbios (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    bios_vendor              TEXT    NOT NULL DEFAULT '',
    bios_version             TEXT    NOT NULL DEFAULT '',
    bios_release_date        TEXT    NOT NULL DEFAULT '',
    bios_revision            TEXT    NOT NULL DEFAULT '',
    system_manufacturer      TEXT    NOT NULL DEFAULT '',
    system_product_name      TEXT    NOT NULL DEFAULT '',
    system_version           TEXT    NOT NULL DEFAULT '',
    system_serial_hash       TEXT    NOT NULL DEFAULT '',
    system_uuid_hash         TEXT    NOT NULL DEFAULT '',
    system_sku               TEXT    NOT NULL DEFAULT '',
    system_family            TEXT    NOT NULL DEFAULT '',
    board_manufacturer       TEXT    NOT NULL DEFAULT '',
    board_product            TEXT    NOT NULL DEFAULT '',
    board_version            TEXT    NOT NULL DEFAULT '',
    board_serial_hash        TEXT    NOT NULL DEFAULT '',
    board_asset_tag          TEXT    NOT NULL DEFAULT '',
    chassis_manufacturer     TEXT    NOT NULL DEFAULT '',
    chassis_type             TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (chassis_type IN (
            'unknown','desktop','laptop','notebook','server',
            'rack-mount','blade','tower','mini-tower',
            'all-in-one','tablet','convertible','detachable',
            'mini-pc','stick-pc','embedded','iot-gateway',
            'docking-station','other'
        )),
    chassis_serial_hash      TEXT    NOT NULL DEFAULT '',
    chassis_asset_tag        TEXT    NOT NULL DEFAULT '',
    is_virtualized           INTEGER NOT NULL DEFAULT 0 CHECK (is_virtualized IN (0,1)),
    hypervisor_hint          TEXT    NOT NULL DEFAULT '',
    is_uefi                  INTEGER NOT NULL DEFAULT 0 CHECK (is_uefi IN (0,1)),
    is_secure_boot           INTEGER NOT NULL DEFAULT 0 CHECK (is_secure_boot IN (0,1)),
    bios_age_days            INTEGER NOT NULL DEFAULT -1,
    is_bios_stale_risk       INTEGER NOT NULL DEFAULT 0 CHECK (is_bios_stale_risk IN (0,1)),
    is_recent                INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_dmi_vendor   ON host_dmi_smbios(system_manufacturer);
CREATE INDEX IF NOT EXISTS idx_dmi_product  ON host_dmi_smbios(system_product_name);
CREATE INDEX IF NOT EXISTS idx_dmi_bios     ON host_dmi_smbios(bios_vendor, bios_version);
CREATE INDEX IF NOT EXISTS idx_dmi_stale    ON host_dmi_smbios(bios_age_days) WHERE is_bios_stale_risk = 1;
CREATE INDEX IF NOT EXISTS idx_dmi_virt     ON host_dmi_smbios(hypervisor_hint) WHERE is_virtualized = 1;
