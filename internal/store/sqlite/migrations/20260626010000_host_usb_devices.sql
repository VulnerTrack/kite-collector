-- host_usb_devices inventories enumerable USB devices on the
-- host. USB enumeration captures human-interface devices
-- (keyboard, mouse, badges, smartcards, FIDO2 keys), removable
-- mass storage (BadUSB / Rubber Ducky surface), network adapters
-- (USB-Ethernet, cellular modems), and vendor-specific gadgets.
--
-- Linux source:   /sys/bus/usb/devices/<busnum>-<port>...
-- macOS source:   IORegistry IOServiceMatching("IOUSBDevice")
-- Windows source: WMI Win32_USBControllerDevice / PnPEntity
-- FreeBSD source: usbconfig list
--
-- Read-only by intent.
--
-- Security shapes this table surfaces:
--
--   * HID class on removable device → BadUSB / Rubber Ducky.
--   * Mass-storage with unusual VID:PID → unsanctioned media.
--   * Suspicious vendor (e.g. Hak5, O.MG Cable VID:PID).
--   * Device behind external hub on laptop → physical attacker.

CREATE TABLE IF NOT EXISTS host_usb_devices (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at               TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    bus_path                   TEXT    NOT NULL,
    bus_num                    INTEGER NOT NULL DEFAULT 0,
    dev_num                    INTEGER NOT NULL DEFAULT 0,
    port_path                  TEXT    NOT NULL DEFAULT '',
    vendor_id                  TEXT    NOT NULL DEFAULT '' CHECK (length(vendor_id) IN (0,4)),
    product_id                 TEXT    NOT NULL DEFAULT '' CHECK (length(product_id) IN (0,4)),
    bcd_device                 TEXT    NOT NULL DEFAULT '',
    vendor_name                TEXT    NOT NULL DEFAULT '',
    product_name               TEXT    NOT NULL DEFAULT '',
    serial                     TEXT    NOT NULL DEFAULT '',
    class_code                 TEXT    NOT NULL DEFAULT '' CHECK (length(class_code) IN (0,2)),
    subclass_code              TEXT    NOT NULL DEFAULT '' CHECK (length(subclass_code) IN (0,2)),
    protocol_code              TEXT    NOT NULL DEFAULT '' CHECK (length(protocol_code) IN (0,2)),
    class_name                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (class_name IN (
            'interface-specific','audio','communications','hid',
            'physical','image','printer','mass-storage','hub',
            'cdc-data','smart-card','content-security','video',
            'personal-healthcare','audio-video','billboard',
            'usb-type-c-bridge','diagnostic','wireless',
            'miscellaneous','application-specific','vendor-specific',
            'unknown'
        )),
    speed_mbps                 INTEGER NOT NULL DEFAULT 0,
    speed_name                 TEXT    NOT NULL DEFAULT ''
        CHECK (speed_name IN (
            '','low','full','high','super','super-plus','super-plus-20',
            'usb4-gen2x2','usb4-gen3x2','unknown'
        )),
    max_power_ma               INTEGER NOT NULL DEFAULT 0,
    interface_count            INTEGER NOT NULL DEFAULT 0,
    driver                     TEXT    NOT NULL DEFAULT '',
    is_hub                     INTEGER NOT NULL DEFAULT 0 CHECK (is_hub IN (0,1)),
    is_root_hub                INTEGER NOT NULL DEFAULT 0 CHECK (is_root_hub IN (0,1)),
    is_removable               INTEGER NOT NULL DEFAULT 0 CHECK (is_removable IN (0,1)),
    is_external_port           INTEGER NOT NULL DEFAULT 0 CHECK (is_external_port IN (0,1)),
    has_hid_interface          INTEGER NOT NULL DEFAULT 0 CHECK (has_hid_interface IN (0,1)),
    has_mass_storage_interface INTEGER NOT NULL DEFAULT 0 CHECK (has_mass_storage_interface IN (0,1)),
    has_network_interface      INTEGER NOT NULL DEFAULT 0 CHECK (has_network_interface IN (0,1)),
    is_badusb_risk             INTEGER NOT NULL DEFAULT 0 CHECK (is_badusb_risk IN (0,1)),
    is_unsanctioned_storage_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_unsanctioned_storage_risk IN (0,1)),
    is_unknown_vendor_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_unknown_vendor_risk IN (0,1)),
    is_recent                  INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    UNIQUE (bus_path)
);

CREATE INDEX IF NOT EXISTS idx_usb_vendor      ON host_usb_devices(vendor_id, product_id);
CREATE INDEX IF NOT EXISTS idx_usb_class       ON host_usb_devices(class_name);
CREATE INDEX IF NOT EXISTS idx_usb_driver      ON host_usb_devices(driver) WHERE driver != '';
CREATE INDEX IF NOT EXISTS idx_usb_hub         ON host_usb_devices(bus_path) WHERE is_hub = 1;
CREATE INDEX IF NOT EXISTS idx_usb_storage     ON host_usb_devices(bus_path) WHERE has_mass_storage_interface = 1;
CREATE INDEX IF NOT EXISTS idx_usb_hid         ON host_usb_devices(bus_path) WHERE has_hid_interface = 1;
CREATE INDEX IF NOT EXISTS idx_usb_badusb      ON host_usb_devices(bus_path) WHERE is_badusb_risk = 1;
CREATE INDEX IF NOT EXISTS idx_usb_unsanct     ON host_usb_devices(bus_path) WHERE is_unsanctioned_storage_risk = 1;
