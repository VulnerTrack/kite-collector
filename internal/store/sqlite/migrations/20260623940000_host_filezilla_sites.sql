-- host_filezilla_sites inventories FileZilla's saved-site
-- registry (`sitemanager.xml`) on Windows, Linux, and macOS.
-- FileZilla stores credentials as plain base64 by default; the
-- "Normal" logon type (Logontype=1) means the password is fully
-- recoverable by anyone who can read the XML file. Master-
-- password protection (Logontype=4) is opt-in and rarely set
-- in the wild.
--
-- MITRE ATT&CK / CWE:
--   T1552.001 (Credentials in Files) — plain base64 password
--   T1078.001 (Default Accounts) — anonymous sites surface
--               unintended exposure on prod hosts
--   CWE-256 (plaintext credential storage)
--   CWE-732 (insecure perms on credential file)
--
-- Headline finding shapes:
--   is_password_plaintext  — Logontype=1, password is a recoverable
--                            base64 string. Rolled-up immediate
--                            incident when combined with a readable
--                            file.
--   is_password_protected_by_master — Logontype=4, password is
--                            wrapped behind FileZilla's master
--                            password (PBKDF2). Safer but still
--                            offline-crackable.
--   is_anonymous_logon     — Logontype=0, no creds; surfaces
--                            shadow access to internal hosts.
--   is_credential_exposure_risk — alias kept for cross-collector
--                            reporting parity.
--
-- Drift is captured via file_hash (SHA-256 of the raw XML).
-- Passwords are NEVER persisted — only their length so the audit
-- pipeline can correlate rotations without holding the secret.

CREATE TABLE IF NOT EXISTS host_filezilla_sites (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    site_name                   TEXT    NOT NULL DEFAULT '',
    site_host                   TEXT    NOT NULL DEFAULT '',
    site_port                   INTEGER NOT NULL DEFAULT 0,
    site_protocol               TEXT    NOT NULL DEFAULT '',
    site_user                   TEXT    NOT NULL DEFAULT '',
    logon_type                  INTEGER NOT NULL DEFAULT -1,
    password_length             INTEGER NOT NULL DEFAULT 0,
    is_password_plaintext       INTEGER NOT NULL DEFAULT 0 CHECK (is_password_plaintext IN (0,1)),
    is_password_protected_by_master INTEGER NOT NULL DEFAULT 0 CHECK (is_password_protected_by_master IN (0,1)),
    is_anonymous_logon          INTEGER NOT NULL DEFAULT 0 CHECK (is_anonymous_logon IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_fz_sites_plaintext
    ON host_filezilla_sites(site_host) WHERE is_password_plaintext = 1;

CREATE INDEX IF NOT EXISTS idx_fz_sites_anonymous
    ON host_filezilla_sites(site_host) WHERE is_anonymous_logon = 1;

CREATE INDEX IF NOT EXISTS idx_fz_sites_exposure
    ON host_filezilla_sites(site_host) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_fz_sites_drift
    ON host_filezilla_sites(file_path, file_hash);
