-- host_gpu_devices inventories GPU / accelerator devices on
-- the host: discrete GPUs (NVIDIA, AMD, Intel Arc), integrated
-- GPUs (Intel UHD, AMD APU, Apple Silicon), and AI accelerators
-- (NVIDIA H100, AMD MI300X, Habana Gaudi, Google TPU passthrough).
--
-- Linux source:   /sys/class/drm/cardN/device/... (PCI-backed)
-- macOS source:   ioreg -l -c IOAccelerator
-- Windows source: WMI Win32_VideoController
--
-- Read-only.

CREATE TABLE IF NOT EXISTS host_gpu_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    card_name       TEXT    NOT NULL,
    pci_bdf         TEXT    NOT NULL DEFAULT '',
    vendor          TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (vendor IN (
            'unknown','nvidia','amd','intel','apple','arm','imagination',
            'matrox','vmware','qemu','google','aws','huawei',
            'habana','graphcore','cerebras','sambanova','other'
        )),
    accelerator_type TEXT   NOT NULL DEFAULT 'unknown'
        CHECK (accelerator_type IN (
            'unknown','discrete-gpu','integrated-gpu','virtual-gpu',
            'ai-accelerator','asic','fpga','tpu','npu','dpu','other'
        )),
    model           TEXT    NOT NULL DEFAULT '',
    driver          TEXT    NOT NULL DEFAULT '',
    vendor_id       TEXT    NOT NULL DEFAULT '' CHECK (length(vendor_id) IN (0,4)),
    device_id       TEXT    NOT NULL DEFAULT '' CHECK (length(device_id) IN (0,4)),
    vram_bytes      INTEGER NOT NULL DEFAULT 0,
    is_passthrough  INTEGER NOT NULL DEFAULT 0 CHECK (is_passthrough IN (0,1)),
    has_compute     INTEGER NOT NULL DEFAULT 0 CHECK (has_compute IN (0,1)),
    has_display     INTEGER NOT NULL DEFAULT 0 CHECK (has_display IN (0,1)),
    is_render_only  INTEGER NOT NULL DEFAULT 0 CHECK (is_render_only IN (0,1)),
    is_recent       INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_vfio_passthrough_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_vfio_passthrough_risk IN (0,1)),
    is_ai_accelerator_risk   INTEGER NOT NULL DEFAULT 0 CHECK (is_ai_accelerator_risk IN (0,1)),
    UNIQUE (card_name)
);

CREATE INDEX IF NOT EXISTS idx_gpu_vendor ON host_gpu_devices(vendor);
CREATE INDEX IF NOT EXISTS idx_gpu_type   ON host_gpu_devices(accelerator_type);
CREATE INDEX IF NOT EXISTS idx_gpu_pci    ON host_gpu_devices(pci_bdf) WHERE pci_bdf != '';
CREATE INDEX IF NOT EXISTS idx_gpu_pass   ON host_gpu_devices(card_name) WHERE is_passthrough = 1;
CREATE INDEX IF NOT EXISTS idx_gpu_ai     ON host_gpu_devices(card_name) WHERE is_ai_accelerator_risk = 1;
