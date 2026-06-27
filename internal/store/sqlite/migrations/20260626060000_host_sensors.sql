-- host_sensors enumerates thermal / fan / voltage / power /
-- current sensors exposed by the host's hardware monitor chips
-- (PCH PCIe, NCT677x, IT8728F, ADT74xx, NVIDIA GPU, IPMI BMC).
--
-- Linux source:   /sys/class/hwmon/hwmonN/{temp*,fan*,in*,curr*,power*}_{input,label,max}
-- macOS source:   ioreg / SMC keys (requires kext or DriverKit)
-- Windows source: WMI MSAcpi_ThermalZoneTemperature + LibreHardwareMonitor lib
--
-- Read-only.

CREATE TABLE IF NOT EXISTS host_sensors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    chip            TEXT    NOT NULL DEFAULT '',
    chip_driver     TEXT    NOT NULL DEFAULT '',
    sensor_name     TEXT    NOT NULL,
    sensor_label    TEXT    NOT NULL DEFAULT '',
    sensor_type     TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (sensor_type IN ('unknown','temp','fan','voltage','current','power','energy','humidity')),
    value_millis    INTEGER NOT NULL DEFAULT 0,
    unit            TEXT    NOT NULL DEFAULT ''
        CHECK (unit IN ('','milli-celsius','rpm','milli-volt','milli-amp','micro-watt','milli-joule','milli-percent','unknown')),
    max_millis      INTEGER NOT NULL DEFAULT 0,
    crit_millis     INTEGER NOT NULL DEFAULT 0,
    is_over_max     INTEGER NOT NULL DEFAULT 0 CHECK (is_over_max IN (0,1)),
    is_over_crit    INTEGER NOT NULL DEFAULT 0 CHECK (is_over_crit IN (0,1)),
    is_thermal_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_thermal_risk IN (0,1)),
    is_recent       INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    UNIQUE (chip, sensor_name)
);

CREATE INDEX IF NOT EXISTS idx_sens_type ON host_sensors(sensor_type);
CREATE INDEX IF NOT EXISTS idx_sens_chip ON host_sensors(chip);
CREATE INDEX IF NOT EXISTS idx_sens_risk ON host_sensors(chip, sensor_name) WHERE is_thermal_risk = 1;
