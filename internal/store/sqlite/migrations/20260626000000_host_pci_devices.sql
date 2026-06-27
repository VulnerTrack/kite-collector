-- host_pci_devices inventories enumerable PCIe / PCI devices on
-- the host. PCIe is the universal root protocol for modern
-- peripheral connectivity — NVMe SSDs, GPUs, NICs, HBAs (SAS /
-- SATA / FC), USB host controllers, BMCs, sound, capture cards,
-- accelerators, and Thunderbolt-tunneled external devices all
-- speak it. Enumerating PCI yields a deterministic per-host
-- hardware-asset snapshot regardless of the device-specific
-- protocol on top.
--
-- Linux source:   /sys/bus/pci/devices/<bdf>/
-- macOS source:   IORegistry (IOServiceMatching("IOPCIDevice"))
-- Windows source: WMI Win32_PnPEntity / Win32_PnPSignedDriver
-- FreeBSD source: pciconf -lvbc / /dev/pci
--
-- Read-only by intent. The collector enumerates topology and
-- capability bits; it never binds, unbinds, resets, or
-- reconfigures any device.
--
-- Security shapes this table surfaces:
--
--   * Unbound endpoint   — endpoint device with no kernel driver
--                          bound (= unclassified hardware, possible
--                          rogue card, possible attack target).
--   * VFIO-bound device  — kernel driver = vfio-pci means the
--                          device has been handed to a userspace
--                          process or VM via passthrough (= an
--                          attack-surface signal worth catching).
--   * Thunderbolt-tunnel — endpoint whose path traverses a
--                          Thunderbolt PCIe switch (= external
--                          DMA-capable device → CVE-2019-6260
--                          Thunderclap class).
--   * SR-IOV active      — physical function exposing virtual
--                          functions in use (= shared-tenant
--                          surface).
--   * Hot-plug capable   — port marked Hotplug Capable (= live
--                          insertion / removal possible →
--                          requires Bus Master DMA Protection).
--
-- MITRE / CWE:
--
--   T1542         Pre-OS Boot (PCI option ROM)
--   T1212         Exploitation for Credential Access (PCI DMA)
--   CVE-2019-6260 Thunderclap (Thunderbolt DMA)
--   CWE-1242      Inclusion of Undocumented Features (rogue PCI)
--   CWE-1300      Improper Protection of Physical Side Channels

CREATE TABLE IF NOT EXISTS host_pci_devices (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    bdf                         TEXT    NOT NULL,
    domain                      INTEGER NOT NULL DEFAULT 0,
    bus                         INTEGER NOT NULL DEFAULT 0,
    device                      INTEGER NOT NULL DEFAULT 0,
    function                    INTEGER NOT NULL DEFAULT 0,
    vendor_id                   TEXT    NOT NULL DEFAULT '' CHECK (length(vendor_id) IN (0,4)),
    device_id                   TEXT    NOT NULL DEFAULT '' CHECK (length(device_id) IN (0,4)),
    subsystem_vendor_id         TEXT    NOT NULL DEFAULT '' CHECK (length(subsystem_vendor_id) IN (0,4)),
    subsystem_device_id         TEXT    NOT NULL DEFAULT '' CHECK (length(subsystem_device_id) IN (0,4)),
    class_code                  TEXT    NOT NULL DEFAULT '' CHECK (length(class_code) IN (0,6)),
    class_name                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (class_name IN (
            'unclassified','storage','network','display',
            'multimedia','memory','bridge','communication',
            'peripheral','input','docking','processor',
            'serial-bus','wireless','intelligent','satellite',
            'crypto','signal-processing','accelerator',
            'non-essential','coprocessor','unknown'
        )),
    vendor_name                 TEXT    NOT NULL DEFAULT '',
    device_name                 TEXT    NOT NULL DEFAULT '',
    revision                    TEXT    NOT NULL DEFAULT '' CHECK (length(revision) IN (0,2,4)),
    driver                      TEXT    NOT NULL DEFAULT '',
    numa_node                   INTEGER NOT NULL DEFAULT -1,
    iommu_group                 INTEGER NOT NULL DEFAULT -1,
    link_speed_gts              TEXT    NOT NULL DEFAULT ''
        CHECK (link_speed_gts IN (
            '','2.5','5','8','16','32','64','unknown'
        )),
    link_width                  INTEGER NOT NULL DEFAULT 0
        CHECK (link_width IN (0,1,2,4,8,12,16,32)),
    is_root_complex             INTEGER NOT NULL DEFAULT 0 CHECK (is_root_complex IN (0,1)),
    is_pci_bridge               INTEGER NOT NULL DEFAULT 0 CHECK (is_pci_bridge IN (0,1)),
    is_endpoint                 INTEGER NOT NULL DEFAULT 0 CHECK (is_endpoint IN (0,1)),
    is_removable                INTEGER NOT NULL DEFAULT 0 CHECK (is_removable IN (0,1)),
    is_unbound                  INTEGER NOT NULL DEFAULT 0 CHECK (is_unbound IN (0,1)),
    is_vfio_bound               INTEGER NOT NULL DEFAULT 0 CHECK (is_vfio_bound IN (0,1)),
    is_thunderbolt_tunneled     INTEGER NOT NULL DEFAULT 0 CHECK (is_thunderbolt_tunneled IN (0,1)),
    has_msi                     INTEGER NOT NULL DEFAULT 0 CHECK (has_msi IN (0,1)),
    has_msix                    INTEGER NOT NULL DEFAULT 0 CHECK (has_msix IN (0,1)),
    has_sr_iov                  INTEGER NOT NULL DEFAULT 0 CHECK (has_sr_iov IN (0,1)),
    num_vfs                     INTEGER NOT NULL DEFAULT 0,
    aer_enabled                 INTEGER NOT NULL DEFAULT 0 CHECK (aer_enabled IN (0,1)),
    is_recent                   INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_unbound_endpoint_risk    INTEGER NOT NULL DEFAULT 0 CHECK (is_unbound_endpoint_risk IN (0,1)),
    is_vfio_passthrough_risk    INTEGER NOT NULL DEFAULT 0 CHECK (is_vfio_passthrough_risk IN (0,1)),
    is_thunderbolt_dma_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_thunderbolt_dma_risk IN (0,1)),
    is_sr_iov_active_risk       INTEGER NOT NULL DEFAULT 0 CHECK (is_sr_iov_active_risk IN (0,1)),
    UNIQUE (bdf)
);

CREATE INDEX IF NOT EXISTS idx_pci_vendor
    ON host_pci_devices(vendor_id, device_id);

CREATE INDEX IF NOT EXISTS idx_pci_class
    ON host_pci_devices(class_name, class_code);

CREATE INDEX IF NOT EXISTS idx_pci_driver
    ON host_pci_devices(driver) WHERE driver != '';

CREATE INDEX IF NOT EXISTS idx_pci_unbound
    ON host_pci_devices(bdf) WHERE is_unbound = 1;

CREATE INDEX IF NOT EXISTS idx_pci_vfio
    ON host_pci_devices(bdf) WHERE is_vfio_bound = 1;

CREATE INDEX IF NOT EXISTS idx_pci_thunderbolt
    ON host_pci_devices(bdf) WHERE is_thunderbolt_tunneled = 1;

CREATE INDEX IF NOT EXISTS idx_pci_sr_iov
    ON host_pci_devices(bdf, num_vfs) WHERE has_sr_iov = 1;

CREATE INDEX IF NOT EXISTS idx_pci_unbound_endpoint
    ON host_pci_devices(bdf) WHERE is_unbound_endpoint_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pci_vfio_risk
    ON host_pci_devices(bdf) WHERE is_vfio_passthrough_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pci_thunderbolt_risk
    ON host_pci_devices(bdf) WHERE is_thunderbolt_dma_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pci_sr_iov_risk
    ON host_pci_devices(bdf) WHERE is_sr_iov_active_risk = 1;

CREATE INDEX IF NOT EXISTS idx_pci_iommu
    ON host_pci_devices(iommu_group) WHERE iommu_group >= 0;
