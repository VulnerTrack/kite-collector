-- 20260623890000_host_aws_profiles.sql: durable storage for per-
-- host AWS credentials / config profile inventory introduced by
-- CDMS iter 82.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_aws_profiles — one row per AWS profile discovered on the
--                       host. Profiles live across both
--                       `credentials` (static keys + sessions) and
--                       `config` (role-assumption + region) files;
--                       we surface a single union row per
--                       `(file, profile_name)` so the audit
--                       pipeline can correlate static-key
--                       findings with the corresponding
--                       role-assumption alternative.
--
-- Locations walked:
--   Windows: C:\Users\<u>\.aws\credentials, ...\config
--   Linux/macOS: ~/.aws/credentials, ~/.aws/config
--   plus paths in AWS_SHARED_CREDENTIALS_FILE / AWS_CONFIG_FILE
--
-- Audit value (MITRE T1552.001 — Credentials in Files,
-- T1078.004 — Valid Accounts: Cloud Accounts):
--   - `has_access_key=1` AND `is_world_readable=1` =
--     immediate-incident shape. One readable static key = full
--     cloud-account compromise blast radius.
--   - `has_session_token=1` lowers the urgency on the same row
--     because session tokens expire within hours; the
--     `aws_access_key_id` still leaks but the secret has a
--     shorter window.
--   - `has_role_arn=1` + `has_mfa_serial=0` = MFA not required
--     for role assumption (CWE-308 single-factor authentication
--     on a privileged role).
--   - `is_world_readable=1` / `is_group_readable=1` on the
--     credentials file = the credentials are exposed to every
--     local user (CWE-732 + T1552.001).

CREATE TABLE IF NOT EXISTS host_aws_profiles (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    file_mode                       INTEGER NOT NULL DEFAULT 0,
    file_owner_uid                  INTEGER NOT NULL DEFAULT 0,
    user_profile                    TEXT,
    file_kind                       TEXT NOT NULL
                                    CHECK (file_kind IN (
                                        'credentials', 'config', 'unknown'
                                    )),
    profile_name                    TEXT NOT NULL,         -- "default" / "production"
    access_key_id_fingerprint       TEXT,                  -- first 4 chars (AKIA…) of the AKID
    region                          TEXT,
    output                          TEXT,                  -- "json" / "yaml" / "text"
    source_profile                  TEXT,                  -- chained profile
    role_arn                        TEXT,
    mfa_serial                      TEXT,
    sso_account_id                  TEXT,
    sso_role_name                   TEXT,
    has_access_key                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_access_key IN (0, 1)),
    has_secret_access_key           INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_secret_access_key IN (0, 1)),
    has_session_token               INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_session_token IN (0, 1)),
    has_role_arn                    INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_role_arn IN (0, 1)),
    has_mfa_serial                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_mfa_serial IN (0, 1)),
    has_sso                         INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_sso IN (0, 1)),
    is_world_readable               INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_world_readable IN (0, 1)),
    is_group_readable               INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_group_readable IN (0, 1)),
    is_credential_exposure_risk     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_credential_exposure_risk IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_aws_profiles_unique
    ON host_aws_profiles(asset_id, file_path, profile_name);

CREATE INDEX IF NOT EXISTS idx_host_aws_profiles_unsynced
    ON host_aws_profiles(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: world/group-readable static keys (immediate-incident).
CREATE INDEX IF NOT EXISTS idx_host_aws_profiles_world_readable
    ON host_aws_profiles(asset_id, file_path, profile_name)
    WHERE is_credential_exposure_risk = 1;

-- Fast path: any static access key (T1552.001 surface).
CREATE INDEX IF NOT EXISTS idx_host_aws_profiles_static_key
    ON host_aws_profiles(asset_id, file_path, profile_name,
                         access_key_id_fingerprint)
    WHERE has_access_key = 1;

-- Fast path: role-assumption profiles without MFA.
CREATE INDEX IF NOT EXISTS idx_host_aws_profiles_no_mfa
    ON host_aws_profiles(asset_id, file_path, profile_name, role_arn)
    WHERE has_role_arn = 1 AND has_mfa_serial = 0;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_aws_profiles_drift
    ON host_aws_profiles(asset_id, file_path, file_hash);
