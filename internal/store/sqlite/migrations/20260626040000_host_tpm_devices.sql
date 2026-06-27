-- host_tpm_devices inventories Trusted Platform Module devices.
-- Most hosts have at most one TPM (firmware fTPM, dTPM Infineon /
-- ST / Nuvoton, or PTT Intel). Each row is one TPM instance.
--
-- Linux source:   /sys/class/tpm/tpm0/...
-- macOS source:   IORegistry "AppleSEPManager" / "AppleT2"
-- Windows source: Get-Tpm + Win32_TPM
--
-- Read-only.

CREATE TABLE IF NOT EXISTS host_tpm_devices (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    name              TEXT    NOT NULL,
    spec_version      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (spec_version IN ('unknown','1.2','2.0','apple-sep')),
    manufacturer_id   TEXT    NOT NULL DEFAULT '',
    manufacturer_name TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (manufacturer_name IN (
            'unknown','infineon','stmicro','nuvoton','atmel',
            'broadcom','intel-ptt','amd-ftpm','google','microsoft',
            'ibm','nationz','samsung','apple','qemu-swtpm','other'
        )),
    firmware_version  TEXT    NOT NULL DEFAULT '',
    vendor_string     TEXT    NOT NULL DEFAULT '',
    is_active         INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0,1)),
    is_owned          INTEGER NOT NULL DEFAULT 0 CHECK (is_owned IN (0,1)),
    is_firmware_tpm   INTEGER NOT NULL DEFAULT 0 CHECK (is_firmware_tpm IN (0,1)),
    has_sha1_bank     INTEGER NOT NULL DEFAULT 0 CHECK (has_sha1_bank IN (0,1)),
    has_sha256_bank   INTEGER NOT NULL DEFAULT 0 CHECK (has_sha256_bank IN (0,1)),
    has_sha384_bank   INTEGER NOT NULL DEFAULT 0 CHECK (has_sha384_bank IN (0,1)),
    has_sha512_bank   INTEGER NOT NULL DEFAULT 0 CHECK (has_sha512_bank IN (0,1)),
    has_sm3_256_bank  INTEGER NOT NULL DEFAULT 0 CHECK (has_sm3_256_bank IN (0,1)),
    is_legacy_tpm12_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_legacy_tpm12_risk IN (0,1)),
    is_disabled_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_disabled_risk IN (0,1)),
    is_unowned_risk   INTEGER NOT NULL DEFAULT 0 CHECK (is_unowned_risk IN (0,1)),
    is_recent         INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_tpm_mfg   ON host_tpm_devices(manufacturer_name);
CREATE INDEX IF NOT EXISTS idx_tpm_spec  ON host_tpm_devices(spec_version);
CREATE INDEX IF NOT EXISTS idx_tpm_risk  ON host_tpm_devices(name) WHERE is_legacy_tpm12_risk = 1 OR is_disabled_risk = 1 OR is_unowned_risk = 1;
