-- 20260623470000_host_windows_hardware.sql: durable storage for per-host
-- Windows hardware / serial inventory introduced by CDMS iter 36.
--
-- Second table in the MID Server-aligned Windows track. Joins against
-- host_windows_info via asset_id.
--
-- Sources (PowerShell shim):
--   - Get-CimInstance Win32_BIOS                  (Manufacturer, SerialNumber,
--                                                  SMBIOSBIOSVersion, ReleaseDate,
--                                                  SMBIOSMajorVersion, SMBIOSMinorVersion)
--   - Get-CimInstance Win32_BaseBoard             (Manufacturer, Product,
--                                                  Version, SerialNumber)
--   - Get-CimInstance Win32_ComputerSystemProduct (UUID, IdentifyingNumber,
--                                                  Vendor, Version, Name)
--   - Get-CimInstance Win32_SystemEnclosure       (ChassisTypes, SerialNumber,
--                                                  SMBIOSAssetTag, SecurityStatus)
--
-- Audit value:
--   - MITRE T1082 (System Information Discovery — defender side):
--     hardware-rooted CMDB primary key. The audit pipeline joins
--     `system_uuid` against cloud-provider inventories (AWS EC2 stores
--     the instance ID in Win32_ComputerSystemProduct.UUID; Azure stores
--     the VM ID in the same field via the chassis).
--   - `is_virtual_machine=1` is the heuristic the audit pipeline uses
--     to skip hardware-rooted findings (TPM-attestation gaps,
--     physical-tamper) that don't apply to VMs.
--   - `chassis_security_status=3` (None) flags hosts whose chassis
--     intrusion-detection switch is disabled or absent — physical
--     access alarms are off.
--   - `chassis_asset_tag` empty on managed hardware = asset-management
--     drift; the SOC operates on the assumption every laptop has an
--     asset tag.

CREATE TABLE IF NOT EXISTS host_windows_hardware (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    source                      TEXT NOT NULL
                                CHECK (source IN (
                                    'powershell-cim', 'powershell-wmi', 'unknown'
                                )),
    -- Win32_BIOS
    bios_manufacturer           TEXT,
    bios_version                TEXT,                  -- SMBIOSBIOSVersion
    bios_release_date           TEXT,                  -- RFC3339
    bios_serial                 TEXT,
    bios_smbios_version         TEXT,                  -- e.g. "3.4"
    -- Win32_BaseBoard
    baseboard_manufacturer      TEXT,
    baseboard_product           TEXT,
    baseboard_version           TEXT,
    baseboard_serial            TEXT,
    -- Win32_ComputerSystemProduct
    system_uuid                 TEXT,                  -- the cloud/CMDB join key
    system_identifying_number   TEXT,                  -- vendor serial
    system_vendor               TEXT,
    system_version              TEXT,
    system_name                 TEXT,
    -- Win32_SystemEnclosure
    chassis_serial              TEXT,
    chassis_asset_tag           TEXT,
    chassis_types_json          TEXT NOT NULL DEFAULT '[]',  -- ChassisTypes is an array
    chassis_security_status     INTEGER NOT NULL DEFAULT 0,
    -- Derived
    is_virtual_machine          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_virtual_machine IN (0, 1)),
    vm_family                   TEXT,                  -- "vmware" / "hyper-v" / "kvm" / etc.
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_hardware_asset
    ON host_windows_hardware(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_hardware_unsynced
    ON host_windows_hardware(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: cloud-correlation by system UUID.
CREATE INDEX IF NOT EXISTS idx_host_windows_hardware_system_uuid
    ON host_windows_hardware(system_uuid)
    WHERE system_uuid IS NOT NULL;

-- Fast path: VM vs physical bucket aggregations.
CREATE INDEX IF NOT EXISTS idx_host_windows_hardware_vm
    ON host_windows_hardware(asset_id)
    WHERE is_virtual_machine = 1;
