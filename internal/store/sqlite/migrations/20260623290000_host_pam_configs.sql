-- 20260623290000_host_pam_configs.sql: durable storage for per-host
-- PAM (Pluggable Authentication Modules) inventory introduced by CDMS
-- iter 18.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_pam_configs — one row per (asset_id, file_path, line_no). Each
--                      scan re-parses every file in /etc/pam.d/ and
--                      records every directive. Drift between scans
--                      (added/removed/reordered lines) surfaces via the
--                      file_hash column.
--
-- Audit value (MITRE T1556.003 — Modify Authentication Process:
-- Pluggable Authentication Modules):
--   - `module='pam_permit.so' AND type='auth'` → unconditional auth
--     pass. Catastrophic when present in /etc/pam.d/sshd.
--   - `arguments_json LIKE '%"nullok"%'` on pam_unix.so → empty
--     passwords accepted.
--   - `control='sufficient' AND module='pam_permit.so'` short-circuits
--     the auth stack regardless of later lines.
--   - `module_path NOT LIKE '/usr/lib%' AND module_path NOT LIKE '/lib%'`
--     → PAM module loaded from non-standard location (CWE-829 —
--     Inclusion of Functionality from Untrusted Control Sphere).
--   - File `file_hash` drift between scans on /etc/pam.d/* = auth
--     policy modification event — always worth alerting on.

CREATE TABLE IF NOT EXISTS host_pam_configs (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    file_hash           TEXT NOT NULL,
    line_no             INTEGER NOT NULL,
    service             TEXT NOT NULL,            -- "sshd", "sudo", "login", "system-auth"...
    type                TEXT NOT NULL
                        CHECK (type IN (
                            'auth', 'account', 'session', 'password',
                            'include', 'substack', 'unknown'
                        )),
    control             TEXT NOT NULL,             -- "required" / "sufficient" / "[success=2 default=ignore]" / ...
    module              TEXT NOT NULL,             -- "pam_unix.so", "pam_google_authenticator.so"
    module_path         TEXT,                      -- resolved absolute path when control included it
    arguments_json      TEXT NOT NULL DEFAULT '[]',
    is_unconditional_pass INTEGER NOT NULL DEFAULT 0
                        CHECK (is_unconditional_pass IN (0, 1)),
    is_nullok           INTEGER NOT NULL DEFAULT 0
                        CHECK (is_nullok IN (0, 1)),
    is_nonstandard_path INTEGER NOT NULL DEFAULT 0
                        CHECK (is_nonstandard_path IN (0, 1)),
    short_circuits_stack INTEGER NOT NULL DEFAULT 0
                        CHECK (short_circuits_stack IN (0, 1)),
    raw_line            TEXT,                       -- whitespace-collapsed
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_pam_configs_unique
    ON host_pam_configs(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_pam_configs_unsynced
    ON host_pam_configs(synced_at)
    WHERE synced_at IS NULL;

-- For T1556.003 fast path: "show me unconditional auth-pass directives".
CREATE INDEX IF NOT EXISTS idx_host_pam_configs_unconditional
    ON host_pam_configs(asset_id, service)
    WHERE is_unconditional_pass = 1;

-- For nullok detection on pam_unix.
CREATE INDEX IF NOT EXISTS idx_host_pam_configs_nullok
    ON host_pam_configs(asset_id, service)
    WHERE is_nullok = 1;

-- For drift-detection joins on per-file hash.
CREATE INDEX IF NOT EXISTS idx_host_pam_configs_file_hash
    ON host_pam_configs(asset_id, file_path, file_hash);
