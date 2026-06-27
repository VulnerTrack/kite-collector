-- 20260623670000_host_macos_posture.sql: durable storage for per-host
-- macOS security-posture singleton introduced by CDMS iter 60.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_macos_posture — singleton per asset capturing the three
--                        canonical macOS defender baselines:
--                        SIP (System Integrity Protection),
--                        Gatekeeper (`spctl --status`), and FileVault
--                        (`fdesetup status`). Each is a single
--                        boolean Apple commits to backward-stable
--                        text output for.
--
-- Audit value (MITRE T1562.001 — Disable or Modify Tools, T1486 —
-- Data Encrypted for Impact, T1553 — Subvert Trust Controls):
--   - CWE-862 (Missing Authorization) — `is_sip_disabled=1` removes
--     the kernel's protection of /System, /usr (non-/usr/local), and
--     a curated set of Apple-signed binaries. Required for most
--     persistent-rootkit deployments.
--   - CWE-345 (Insufficient Verification of Data Authenticity) —
--     `is_gatekeeper_disabled=1` means user-downloaded binaries are
--     no longer signature-checked; the "drag-the-app-from-Internet"
--     path runs anything (T1553.001).
--   - CWE-311 (Missing Encryption of Sensitive Data) —
--     `is_filevault_disabled=1` exposes the entire SSD plaintext to
--     anyone with physical access (T1486 + T1078.003 lateral via
--     extracted credentials).
--   - Drift events — flips in any of the three booleans between
--     scans are individually alert-worthy.

CREATE TABLE IF NOT EXISTS host_macos_posture (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    source                      TEXT NOT NULL
                                CHECK (source IN (
                                    'darwin-cli', 'no-probe', 'unknown'
                                )),
    sip_status_raw              TEXT,                  -- "enabled" / "disabled" / "unknown"
    gatekeeper_status_raw       TEXT,                  -- "enabled" / "disabled" / "unknown"
    filevault_status_raw        TEXT,                  -- "on" / "off" / "deferred" / "unknown"
    csrutil_raw_output          TEXT,
    spctl_raw_output            TEXT,
    fdesetup_raw_output         TEXT,
    is_sip_enabled              INTEGER NOT NULL DEFAULT 0
                                CHECK (is_sip_enabled IN (0, 1)),
    is_sip_disabled             INTEGER NOT NULL DEFAULT 0
                                CHECK (is_sip_disabled IN (0, 1)),
    is_gatekeeper_enabled       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_gatekeeper_enabled IN (0, 1)),
    is_gatekeeper_disabled      INTEGER NOT NULL DEFAULT 0
                                CHECK (is_gatekeeper_disabled IN (0, 1)),
    is_filevault_enabled        INTEGER NOT NULL DEFAULT 0
                                CHECK (is_filevault_enabled IN (0, 1)),
    is_filevault_disabled       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_filevault_disabled IN (0, 1)),
    is_filevault_deferred       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_filevault_deferred IN (0, 1)),
    is_full_protection_active   INTEGER NOT NULL DEFAULT 0
                                CHECK (is_full_protection_active IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_macos_posture_unique
    ON host_macos_posture(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_macos_posture_unsynced
    ON host_macos_posture(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me hosts with SIP off" (the kernel-protection
-- regression — usually pairs with rootkit deployment).
CREATE INDEX IF NOT EXISTS idx_host_macos_posture_sip_off
    ON host_macos_posture(asset_id)
    WHERE is_sip_disabled = 1;

-- Fast path: "show me hosts with Gatekeeper off" (unsigned-binary
-- exec path is wide open).
CREATE INDEX IF NOT EXISTS idx_host_macos_posture_gk_off
    ON host_macos_posture(asset_id)
    WHERE is_gatekeeper_disabled = 1;

-- Fast path: "show me unencrypted disks" — the offline-attack
-- doorway (T1486 ransomware, T1078 lateral via extracted creds).
CREATE INDEX IF NOT EXISTS idx_host_macos_posture_fv_off
    ON host_macos_posture(asset_id)
    WHERE is_filevault_disabled = 1;
