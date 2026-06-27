-- 20260623800000_host_local_gpo.sql: durable storage for per-host
-- Local Group Policy (GPO) artifact inventory introduced by CDMS
-- iter 73.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_local_gpo — one row per GPO artifact discovered on disk:
--                    `gpt.ini`, `Registry.pol`, or any script
--                    inside the `Scripts\{Startup,Shutdown,Logon,
--                    Logoff}\` subdirectory. The audit pipeline
--                    flags scripts in particular — they are the
--                    canonical T1037.001 (Logon Script: Windows)
--                    persistence primitive.
--
-- Locations walked:
--   %windir%\System32\GroupPolicy\                — local machine
--                                                  + user policy
--   %windir%\System32\GroupPolicyUsers\<SID>\     — per-user local
--                                                  GPOs (admin-
--                                                  targeted; rare
--                                                  outside SAW
--                                                  workstations)
--
-- Audit value (MITRE T1037.001 — Logon Script: Windows, plus
-- T1547.002 — Authentication Package, T1562.001 — Disable or
-- Modify Tools via Group Policy):
--   - `is_script_artifact=1` + `is_machine_scope=1` flags scripts
--     that run with SYSTEM at boot/shutdown. The headline finding.
--   - `is_per_user_gpo=1` flags local GPOs targeted at a specific
--     user SID — uncommon outside admin workstations and a
--     potential indicator of a misconfigured (or attacker-pushed)
--     policy.
--   - `is_pol_signature_invalid=1` flags Registry.pol files whose
--     `PReg` header is missing or corrupted. Either a deployment
--     bug or tampering.
--   - Drift events — gpt.ini Version number change OR Registry.pol
--     file_hash change = group policy was modified. Always
--     alert-worthy.

CREATE TABLE IF NOT EXISTS host_local_gpo (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    file_size_bytes             INTEGER NOT NULL DEFAULT 0,
    file_mtime                  INTEGER,
    gpo_scope                   TEXT NOT NULL
                                CHECK (gpo_scope IN (
                                    'machine', 'user', 'per-user', 'unknown'
                                )),
    artifact_kind               TEXT NOT NULL
                                CHECK (artifact_kind IN (
                                    'gpt-ini', 'registry-pol',
                                    'script-startup', 'script-shutdown',
                                    'script-logon', 'script-logoff',
                                    'unknown'
                                )),
    target_sid                  TEXT,                     -- per-user GPOs only
    gpo_version                 INTEGER,                  -- from gpt.ini
    extension_names             TEXT,                     -- gpt.ini gPCMachineExtensionNames
    has_pol_signature           INTEGER NOT NULL DEFAULT 0
                                CHECK (has_pol_signature IN (0, 1)),
    is_pol_signature_invalid    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_pol_signature_invalid IN (0, 1)),
    is_machine_scope            INTEGER NOT NULL DEFAULT 0
                                CHECK (is_machine_scope IN (0, 1)),
    is_user_scope               INTEGER NOT NULL DEFAULT 0
                                CHECK (is_user_scope IN (0, 1)),
    is_per_user_gpo             INTEGER NOT NULL DEFAULT 0
                                CHECK (is_per_user_gpo IN (0, 1)),
    is_script_artifact          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_script_artifact IN (0, 1)),
    is_persistence_candidate    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_persistence_candidate IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_local_gpo_unique
    ON host_local_gpo(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_local_gpo_unsynced
    ON host_local_gpo(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: T1037.001 startup/shutdown scripts running as SYSTEM.
CREATE INDEX IF NOT EXISTS idx_host_local_gpo_persistence
    ON host_local_gpo(asset_id, file_path, artifact_kind)
    WHERE is_persistence_candidate = 1;

-- Fast path: per-user GPO targeting (uncommon, possibly suspicious).
CREATE INDEX IF NOT EXISTS idx_host_local_gpo_per_user
    ON host_local_gpo(asset_id, target_sid, file_path)
    WHERE is_per_user_gpo = 1;

-- Fast path: Registry.pol corruption / tampering.
CREATE INDEX IF NOT EXISTS idx_host_local_gpo_invalid_pol
    ON host_local_gpo(asset_id, file_path)
    WHERE is_pol_signature_invalid = 1;

-- Drift detection (hash + version change).
CREATE INDEX IF NOT EXISTS idx_host_local_gpo_drift
    ON host_local_gpo(asset_id, file_path, file_hash);
