-- 20260623820000_host_psreadline_suspicious.sql: durable storage
-- for per-host PSReadLine suspicious-command audit introduced by
-- CDMS iter 75.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_psreadline_suspicious — one row per suspicious command
--                                line found in a user's PSReadLine
--                                ConsoleHost_history.txt file
--                                (PowerShell logs every interactive
--                                line by default, persisted at
--                                %APPDATA%\Microsoft\Windows\
--                                PowerShell\PSReadLine\). The audit
--                                pipeline alerts on any row in this
--                                table — by definition every entry
--                                hit at least one curated bad
--                                pattern.
--
-- Audit value (MITRE T1552.003 — Credentials in Files: Bash History
-- equivalent, plus T1059.001 — PowerShell, T1562.001 — Disable or
-- Modify Tools when defender-tamper rules hit, T1105 — Ingress Tool
-- Transfer for download-cradle rules):
--   - `finding_kind='credential'` — the line contains password,
--     token, secret, api key, or Bearer string. T1552.003.
--   - `finding_kind='recon'` — the line runs an enumeration
--     command attackers use to map the environment (whoami /priv,
--     net group "Domain Admins", query user).
--   - `finding_kind='download-cradle'` — the line uses the
--     classic PowerShell IEX + Net.WebClient pattern to pull and
--     execute remote content (T1105 + T1059.001).
--   - `finding_kind='defender-tamper'` — Set-MpPreference /
--     Add-MpPreference with -ExclusionPath / -DisableRealtime…
--     (T1562.001).

CREATE TABLE IF NOT EXISTS host_psreadline_suspicious (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    user_profile                TEXT NOT NULL,         -- "alice" / "" if unknown
    line_no                     INTEGER NOT NULL,
    command                     TEXT NOT NULL,
    finding_kind                TEXT NOT NULL
                                CHECK (finding_kind IN (
                                    'credential', 'recon',
                                    'download-cradle',
                                    'defender-tamper',
                                    'unknown'
                                )),
    is_credential_leak          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_credential_leak IN (0, 1)),
    is_recon                    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_recon IN (0, 1)),
    is_download_cradle          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_download_cradle IN (0, 1)),
    is_defender_tamper          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_defender_tamper IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_unique
    ON host_psreadline_suspicious(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_unsynced
    ON host_psreadline_suspicious(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: credential leaks (T1552.003 — top priority).
CREATE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_cred
    ON host_psreadline_suspicious(asset_id, user_profile, line_no)
    WHERE is_credential_leak = 1;

-- Fast path: defender-tamper attempts.
CREATE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_defender
    ON host_psreadline_suspicious(asset_id, user_profile, line_no)
    WHERE is_defender_tamper = 1;

-- Fast path: download cradles (Net.WebClient / IEX) — T1105.
CREATE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_download
    ON host_psreadline_suspicious(asset_id, user_profile, line_no)
    WHERE is_download_cradle = 1;

-- Drift detection: hash change on history file = new commands
-- were appended since last scan.
CREATE INDEX IF NOT EXISTS idx_host_psreadline_suspicious_drift
    ON host_psreadline_suspicious(asset_id, file_path, file_hash);
