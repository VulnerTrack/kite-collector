-- 20260623480000_host_windows_cpu_memory.sql: per-host CPU + memory
-- physical inventory introduced by CDMS iter 37.
--
-- Two related tables in one migration (the audit pipeline always joins
-- them via asset_id):
--
--   host_windows_cpus           — one row per processor socket
--   host_windows_memory_modules — one row per physical DIMM
--
-- Sources (PowerShell shim, single round-trip):
--   - Get-CimInstance Win32_Processor       (one per socket, NOT per core)
--   - Get-CimInstance Win32_PhysicalMemory  (one per DIMM)
--
-- Audit value (MITRE T1082 — System Information Discovery / defender side):
--   - CPU virtualization flags surface hosts where VT-x/AMD-V is
--     disabled in BIOS — nested-virt / hyperthread-mitigation impact.
--   - Per-DIMM serial numbers feed asset-tracking for warranty
--     claims and detect surreptitious DIMM swaps.
--   - Aggregate `SUM(capacity_bytes) FROM host_windows_memory_modules`
--     reconciles against `total_physical_memory_bytes` in
--     host_windows_info — mismatches flag inventory drift.

CREATE TABLE IF NOT EXISTS host_windows_cpus (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    source                          TEXT NOT NULL
                                    CHECK (source IN (
                                        'powershell-cim', 'powershell-wmi', 'unknown'
                                    )),
    device_id                       TEXT NOT NULL,        -- "CPU0"
    socket_designation              TEXT,                 -- "U3E1"
    manufacturer                    TEXT,
    name                            TEXT,                 -- model marketing name
    description                     TEXT,
    family                          INTEGER NOT NULL DEFAULT 0,
    processor_id                    TEXT,                 -- CPUID string
    number_of_cores                 INTEGER NOT NULL DEFAULT 0,
    number_of_logical_processors    INTEGER NOT NULL DEFAULT 0,
    max_clock_speed_mhz             INTEGER NOT NULL DEFAULT 0,
    current_clock_speed_mhz         INTEGER NOT NULL DEFAULT 0,
    l2_cache_size_kb                INTEGER NOT NULL DEFAULT 0,
    l3_cache_size_kb                INTEGER NOT NULL DEFAULT 0,
    virtualization_firmware_enabled INTEGER NOT NULL DEFAULT 0
                                    CHECK (virtualization_firmware_enabled IN (0, 1)),
    vm_monitor_mode_extensions      INTEGER NOT NULL DEFAULT 0
                                    CHECK (vm_monitor_mode_extensions IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_cpus_unique
    ON host_windows_cpus(asset_id, device_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_cpus_unsynced
    ON host_windows_cpus(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts whose CPUs report virtualization disabled
-- in BIOS firmware" — nested-virt + Hyper-V Enabled features won't
-- start without this.
CREATE INDEX IF NOT EXISTS idx_host_windows_cpus_no_virt
    ON host_windows_cpus(asset_id, device_id)
    WHERE virtualization_firmware_enabled = 0;

CREATE TABLE IF NOT EXISTS host_windows_memory_modules (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    source                   TEXT NOT NULL
                             CHECK (source IN (
                                 'powershell-cim', 'powershell-wmi', 'unknown'
                             )),
    tag                      TEXT NOT NULL,        -- "Physical Memory 0"
    device_locator           TEXT,                 -- "DIMM_A1"
    bank_label               TEXT,                 -- "P0 CHANNEL A"
    capacity_bytes           INTEGER NOT NULL DEFAULT 0,
    manufacturer             TEXT,
    part_number              TEXT,
    serial_number            TEXT,
    speed_mhz                INTEGER NOT NULL DEFAULT 0,
    configured_clock_speed_mhz INTEGER NOT NULL DEFAULT 0,
    memory_type              INTEGER NOT NULL DEFAULT 0,  -- SMBIOS Type value
    form_factor              INTEGER NOT NULL DEFAULT 0,
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_memory_modules_unique
    ON host_windows_memory_modules(asset_id, tag);

CREATE INDEX IF NOT EXISTS idx_host_windows_memory_modules_unsynced
    ON host_windows_memory_modules(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts with empty DIMM slots" (capacity_bytes=0
-- on a row whose tag exists = slot reported but unpopulated).
CREATE INDEX IF NOT EXISTS idx_host_windows_memory_modules_empty
    ON host_windows_memory_modules(asset_id, device_locator)
    WHERE capacity_bytes = 0;
