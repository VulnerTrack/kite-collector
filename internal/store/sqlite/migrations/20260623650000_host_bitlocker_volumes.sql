-- 20260623650000_host_bitlocker_volumes.sql: durable storage for per-host
-- Windows BitLocker volume inventory introduced by CDMS iter 58.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_bitlocker_volumes — one row per volume returned by
--                            Get-BitLockerVolume. Volumes BitLocker
--                            cannot manage (network shares, ReFS in
--                            some cases) are not enumerated; the
--                            audit pipeline joins to host_volumes for
--                            the complementary "should be encrypted
--                            but isn't enumerated" finding.
--
-- Audit value (MITRE T1486 — Data Encrypted for Impact, defender
-- side, plus T1078 — Valid Accounts via offline-attack lateral):
--   - CWE-311 (Missing Encryption) — `is_system_drive_unencrypted=1`
--     captures the headline: C: drive has no BitLocker protection.
--     An offline-attack (drive yank, mount on attacker laptop) reads
--     every byte plain.
--   - CWE-326 (Inadequate Encryption Strength) — `is_weak_cipher=1`
--     flags volumes still using Aes128 (the pre-2020 default) when
--     the host supports the modern XtsAes256.
--   - CWE-310 (key recoverability) — `has_no_recovery_protector=1`
--     means a TPM-only volume with no RecoveryPassword backup; a
--     firmware update can render the data unrecoverable.
--   - `has_no_tpm_protector=1` flags password-only protection: any
--     keyboard logger gets the disk; the TPM-anchored hardware bind
--     is missing.
--   - Drift events — `encryption_method` flip between scans (e.g.
--     re-encrypted from Xts to Aes) deserves an alert.

CREATE TABLE IF NOT EXISTS host_bitlocker_volumes (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    source                          TEXT NOT NULL
                                    CHECK (source IN (
                                        'powershell-bitlocker', 'no-probe', 'unknown'
                                    )),
    mount_point                     TEXT NOT NULL,         -- "C:" / "D:" / "\\?\Volume{...}"
    volume_type                     TEXT,                  -- "OperatingSystem" / "FixedData" / "Removable"
    protection_status               TEXT,                  -- "On" / "Off" / "Unknown"
    lock_status                     TEXT,                  -- "Locked" / "Unlocked"
    volume_status                   TEXT,                  -- "FullyEncrypted" / "EncryptionInProgress" / "FullyDecrypted"
    encryption_method               TEXT,                  -- "Aes128" / "Aes256" / "XtsAes128" / "XtsAes256" / "None"
    encryption_percentage           INTEGER NOT NULL DEFAULT 0,
    auto_unlock_enabled             INTEGER NOT NULL DEFAULT 0
                                    CHECK (auto_unlock_enabled IN (0, 1)),
    key_protectors_json             TEXT NOT NULL DEFAULT '[]',  -- ["Tpm","RecoveryPassword",...]
    is_protection_off               INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_protection_off IN (0, 1)),
    is_fully_encrypted              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_fully_encrypted IN (0, 1)),
    is_system_drive                 INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_system_drive IN (0, 1)),
    is_system_drive_unencrypted     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_system_drive_unencrypted IN (0, 1)),
    is_removable_unencrypted        INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_removable_unencrypted IN (0, 1)),
    is_weak_cipher                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_weak_cipher IN (0, 1)),
    has_tpm_protector               INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_tpm_protector IN (0, 1)),
    has_recovery_protector          INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_recovery_protector IN (0, 1)),
    has_no_tpm_protector            INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_tpm_protector IN (0, 1)),
    has_no_recovery_protector       INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_no_recovery_protector IN (0, 1)),
    is_hardened                     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_hardened IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_unique
    ON host_bitlocker_volumes(asset_id, mount_point);

CREATE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_unsynced
    ON host_bitlocker_volumes(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts whose system drive isn't encrypted"
-- (CWE-311 + T1486).
CREATE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_unencrypted_os
    ON host_bitlocker_volumes(asset_id, mount_point)
    WHERE is_system_drive_unencrypted = 1;

-- Fast path: weak cipher (Aes128) on a fixed-data or system volume.
CREATE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_weak_cipher
    ON host_bitlocker_volumes(asset_id, mount_point, encryption_method)
    WHERE is_weak_cipher = 1;

-- Fast path: removable drives running unprotected.
CREATE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_removable
    ON host_bitlocker_volumes(asset_id, mount_point)
    WHERE is_removable_unencrypted = 1;

-- Fast path: encryption is on but no RecoveryPassword backup exists.
CREATE INDEX IF NOT EXISTS idx_host_bitlocker_volumes_no_recovery
    ON host_bitlocker_volumes(asset_id, mount_point)
    WHERE has_no_recovery_protector = 1 AND is_fully_encrypted = 1;
