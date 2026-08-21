-- 20260820100000_host_windows_license.sql: per-host Windows OS licence
-- and activation posture.
--
-- Singleton table per machine. The collector queries the same CIM
-- surface slmgr.vbs reads (SoftwareLicensingProduct filtered to the
-- Windows application GUID + the SoftwareLicensingService singleton)
-- through the PowerShell shim, joinable against host_windows_info via
-- machine_id.
--
-- Product keys are NEVER stored verbatim (same contract as
-- host_software_licences). The OA3 firmware-embedded key is hashed to
-- SHA-256 inside the PowerShell probe; only the 5-character partial
-- key slmgr /dli already shows any local user is kept in clear.
--
-- Audit value:
--   - ISO/IEC 27001:2022 A.5.32 (intellectual-property compliance) —
--     the OS licence is the first licence an inventory must prove.
--     `is_license_compliance_risk=1` is the headline rollup.
--   - Non-genuine / notification-mode hosts (`is_non_genuine=1`,
--     `is_notification_mode=1`) correlate with cracked activators —
--     a well-worn malware delivery vehicle on unmanaged endpoints.
--   - Evaluation builds in production (`is_evaluation=1`) hard-stop
--     at `evaluation_end_date` (Server eval reboots hourly past it) —
--     an availability risk the fleet view must surface early.
--   - KMS wiring (`kms_*`) proves WHICH activation path a host used;
--     a rogue/unexpected KMS server name is lateral-movement signal.
--   - `is_grace_expiring_soon=1` warns before the desktop lockout,
--     while `remaining_windows_rearm_count=0` proves the grace budget
--     cannot be extended again.

CREATE TABLE IF NOT EXISTS host_windows_license (
    id                                  TEXT PRIMARY KEY NOT NULL,
    machine_id                          TEXT NOT NULL,
    source                              TEXT NOT NULL
                                        CHECK (source IN (
                                            'powershell-cim',
                                            'unknown'
                                        )),
    -- SoftwareLicensingProduct (Windows application row)
    product_name                        TEXT,
    description                         TEXT,
    license_status                      TEXT NOT NULL
                                        CHECK (license_status IN (
                                            'unlicensed',
                                            'licensed',
                                            'oob-grace',
                                            'oot-grace',
                                            'non-genuine-grace',
                                            'notification',
                                            'extended-grace',
                                            'unknown'
                                        )),
    license_status_code                 INTEGER NOT NULL DEFAULT -1,
    license_status_reason               TEXT,                  -- HRESULT, 0x%08X
    partial_product_key                 TEXT,                  -- last 5 chars only
    license_family                      TEXT,
    product_key_channel                 TEXT,                  -- raw, e.g. 'OEM:DM'
    channel                             TEXT NOT NULL
                                        CHECK (channel IN (
                                            'retail',
                                            'oem',
                                            'volume-kms-client',
                                            'volume-mak',
                                            'evaluation',
                                            'unknown'
                                        )),
    grace_period_remaining_minutes      INTEGER NOT NULL DEFAULT 0,
    evaluation_end_date                 TEXT,                  -- RFC3339
    remaining_sku_rearm_count           INTEGER NOT NULL DEFAULT -1,
    -- SoftwareLicensingService (singleton)
    remaining_windows_rearm_count       INTEGER NOT NULL DEFAULT -1,
    kms_configured_server               TEXT,
    kms_configured_port                 INTEGER NOT NULL DEFAULT 0,
    kms_discovered_server               TEXT,
    kms_discovered_port                 INTEGER NOT NULL DEFAULT 0,
    is_kms_host                         INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_kms_host IN (0, 1)),
    has_firmware_embedded_key           INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_firmware_embedded_key IN (0, 1)),
    firmware_key_hash                   TEXT,                  -- 'sha256:…', never raw
    firmware_key_description            TEXT,
    -- Derived
    is_activated                        INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_activated IN (0, 1)),
    is_grace_period                     INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_grace_period IN (0, 1)),
    is_non_genuine                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_non_genuine IN (0, 1)),
    is_notification_mode                INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_notification_mode IN (0, 1)),
    is_unlicensed                       INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_unlicensed IN (0, 1)),
    is_evaluation                       INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_evaluation IN (0, 1)),
    is_evaluation_expired               INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_evaluation_expired IN (0, 1)),
    is_kms_client                       INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_kms_client IN (0, 1)),
    is_grace_expiring_soon              INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_grace_expiring_soon IN (0, 1)),
    is_rearm_exhausted                  INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_rearm_exhausted IN (0, 1)),
    is_license_compliance_risk          INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_license_compliance_risk IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_license_machine
    ON host_windows_license(machine_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_license_unsynced
    ON host_windows_license(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts out of licence compliance" (A.5.32).
CREATE INDEX IF NOT EXISTS idx_host_windows_license_risk
    ON host_windows_license(machine_id)
    WHERE is_license_compliance_risk = 1;

-- Fast path: grace-window early warning.
CREATE INDEX IF NOT EXISTS idx_host_windows_license_grace
    ON host_windows_license(machine_id, grace_period_remaining_minutes)
    WHERE is_grace_expiring_soon = 1;
