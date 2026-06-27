-- 20260623550000_host_windows_defender.sql: per-host Windows Defender
-- antimalware posture introduced by CDMS iter 48.
--
-- Singleton table per asset. The collector queries the Defender
-- PowerShell module (Get-MpComputerStatus + Get-MpPreference). On
-- hosts where a third-party AV is installed Defender disables
-- itself; the row still gets written with defender_running=0 so
-- the audit pipeline can prove "Defender deliberately stood down"
-- rather than "no signal".
--
-- Audit value:
--   - MITRE T1562.001 (Disable or Modify Tools) — the headline
--     attacker move. The audit pipeline alerts on
--     `is_full_protection_active=0` and on individual flips of
--     real-time / tamper / cloud protection.
--   - MITRE T1112 (Modify Registry) — Defender exclusion lists live
--     in the registry. Attacker-injected exclusion paths covering
--     `%TEMP%`, `C:\Users\Public`, or wide globs are persistence
--     primitives. `has_suspicious_exclusion=1` flags entries that
--     match the curated watch-set.
--   - CWE-693 (Protection Mechanism Failure) — stale signatures
--     (>7 days) miss known-bad evasion. `is_signature_stale=1`
--     surfaces them directly.
--   - CWE-1188 (Insecure Default Initialization) — tamper protection
--     off lets an unprivileged-with-admin-token attacker disable
--     Defender via the registry without a UAC prompt.

CREATE TABLE IF NOT EXISTS host_windows_defender (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    source                              TEXT NOT NULL
                                        CHECK (source IN (
                                            'powershell-defender',
                                            'no-probe',
                                            'unknown'
                                        )),
    -- Get-MpComputerStatus
    defender_running                    INTEGER NOT NULL DEFAULT 0
                                        CHECK (defender_running IN (0, 1)),
    am_running_mode                     TEXT,                  -- Normal/Passive/SxSPassive/EDRBlockMode
    am_service_version                  TEXT,
    am_engine_version                   TEXT,
    antivirus_signature_version         TEXT,
    antivirus_signature_last_updated    TEXT,                  -- RFC3339
    antivirus_signature_age_days        INTEGER NOT NULL DEFAULT 0,
    behavior_monitor_enabled            INTEGER NOT NULL DEFAULT 0
                                        CHECK (behavior_monitor_enabled IN (0, 1)),
    on_access_protection_enabled        INTEGER NOT NULL DEFAULT 0
                                        CHECK (on_access_protection_enabled IN (0, 1)),
    ioav_protection_enabled             INTEGER NOT NULL DEFAULT 0
                                        CHECK (ioav_protection_enabled IN (0, 1)),
    nis_enabled                         INTEGER NOT NULL DEFAULT 0
                                        CHECK (nis_enabled IN (0, 1)),
    antispyware_enabled                 INTEGER NOT NULL DEFAULT 0
                                        CHECK (antispyware_enabled IN (0, 1)),
    tamper_protection_enabled           INTEGER NOT NULL DEFAULT 0
                                        CHECK (tamper_protection_enabled IN (0, 1)),
    last_quick_scan_time                TEXT,
    last_full_scan_time                 TEXT,
    -- Get-MpPreference
    pua_protection_enabled              INTEGER NOT NULL DEFAULT 0
                                        CHECK (pua_protection_enabled IN (0, 1)),
    cloud_protection_enabled            INTEGER NOT NULL DEFAULT 0
                                        CHECK (cloud_protection_enabled IN (0, 1)),
    exclusion_paths_json                TEXT NOT NULL DEFAULT '[]',
    exclusion_extensions_json           TEXT NOT NULL DEFAULT '[]',
    exclusion_processes_json            TEXT NOT NULL DEFAULT '[]',
    suspicious_exclusion_paths_json     TEXT NOT NULL DEFAULT '[]',
    -- Derived
    is_full_protection_active           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_full_protection_active IN (0, 1)),
    is_signature_stale                  INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_signature_stale IN (0, 1)),
    has_suspicious_exclusion            INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_suspicious_exclusion IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_defender_asset
    ON host_windows_defender(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_windows_defender_unsynced
    ON host_windows_defender(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts not fully protected" (T1562.001).
CREATE INDEX IF NOT EXISTS idx_host_windows_defender_not_full
    ON host_windows_defender(asset_id)
    WHERE is_full_protection_active = 0;

-- Fast path: stale-signature audit.
CREATE INDEX IF NOT EXISTS idx_host_windows_defender_stale_sig
    ON host_windows_defender(asset_id, antivirus_signature_last_updated)
    WHERE is_signature_stale = 1;

-- Fast path: suspicious-exclusion alert.
CREATE INDEX IF NOT EXISTS idx_host_windows_defender_susp_excl
    ON host_windows_defender(asset_id)
    WHERE has_suspicious_exclusion = 1;
