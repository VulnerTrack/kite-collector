-- 20260623260000_host_cloud_credentials.sql: durable storage for
-- per-host cloud credential inventory introduced by CDMS iter 15.
--
-- One additive table. No existing rows or columns are touched.
--
-- IMPORTANT — privacy + security invariant:
--   This table NEVER stores secret material. The only "secret-ish"
--   columns are key_id (non-secret AWS access-key IDs like AKIA…
--   which are publicly exposed in CloudTrail anyway) and account_id
--   (likewise publicly exposed). Secret access keys, service-account
--   JSON private_key fields, bearer tokens, refresh tokens, and
--   kubeconfig client-key-data are NEVER read into memory and NEVER
--   persisted. The collector inspects file presence and structural
--   markers only.
--
--   host_cloud_credentials — one row per (asset_id, provider, profile,
--                            source_path). A user with named-profile
--                            credentials gets one row per profile;
--                            kubeconfig contexts each get their own row.
--
-- Audit value (T1552.001 — Unsecured Credentials in Files):
--   - `is_long_lived=1` AND `expires_at IS NULL` is the canonical
--     anti-pattern (static access keys with no rotation horizon).
--   - `has_mfa=0` AND `is_long_lived=1` → CWE-308 (Use of
--     Single-Factor Authentication) for the cloud control plane.
--   - Fleet-wide rotation drift — `created_at` plus current
--     scan-time minus AWS IAM's last-used data feeds the
--     "stale credential" audit.
--   - Cross-host duplicate detection — same `key_id` on multiple
--     hosts indicates a shared key (CWE-1004 — Sensitive Default
--     Account), which AWS and Google specifically flag as policy
--     violations.

CREATE TABLE IF NOT EXISTS host_cloud_credentials (
    id                      TEXT PRIMARY KEY NOT NULL,
    asset_id                TEXT NOT NULL,
    provider                TEXT NOT NULL
                            CHECK (provider IN (
                                'aws', 'gcp', 'azure',
                                'kubernetes', 'kubeconfig',
                                'github', 'gitlab', 'bitbucket',
                                'docker', 'helm', 'npm', 'pypi',
                                'terraform-cloud', 'hashicorp-vault',
                                'cloudflare', 'digitalocean',
                                'unknown'
                            )),
    credential_type         TEXT NOT NULL
                            CHECK (credential_type IN (
                                'access-key', 'session-token',
                                'service-account-key',
                                'oauth-refresh-token', 'oauth-access-token',
                                'sso-cache', 'kubeconfig-context',
                                'bearer-token', 'basic-auth',
                                'api-key', 'unknown'
                            )),
    profile                 TEXT NOT NULL,                  -- "default" / named profile / k8s context name
    owner_user              TEXT,                            -- $HOME owner ("alice" / "root")
    account_id              TEXT,                            -- AWS account ID / GCP project / Azure subscription / k8s cluster server
    region                  TEXT,                            -- AWS region / GCP location (when scoped)
    key_id                  TEXT,                            -- AKIA… for AWS; not-secret
    role_arn                TEXT,                            -- AWS assume-role chain target
    is_long_lived           INTEGER NOT NULL DEFAULT 0
                            CHECK (is_long_lived IN (0, 1)),
    session_token_present   INTEGER NOT NULL DEFAULT 0
                            CHECK (session_token_present IN (0, 1)),
    has_mfa                 INTEGER NOT NULL DEFAULT 0
                            CHECK (has_mfa IN (0, 1)),
    federated_via           TEXT,                            -- "sso" | "oidc" | "iam-identity-center" | "" when static
    expires_at              TEXT,                            -- RFC3339 when known
    source_path             TEXT NOT NULL,
    source_format           TEXT NOT NULL DEFAULT 'unknown'  -- "ini" | "json" | "yaml" | "unknown"
                            CHECK (source_format IN (
                                'ini', 'json', 'yaml', 'unknown'
                            )),
    last_seen_at            TEXT NOT NULL,
    collected_at            TEXT NOT NULL,
    synced_at               INTEGER,
    created_at              INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_cloud_credentials_unique
    ON host_cloud_credentials(asset_id, provider, profile, source_path);

CREATE INDEX IF NOT EXISTS idx_host_cloud_credentials_unsynced
    ON host_cloud_credentials(synced_at)
    WHERE synced_at IS NULL;

-- For T1552.001: "show me long-lived static credentials with no MFA".
CREATE INDEX IF NOT EXISTS idx_host_cloud_credentials_long_lived_no_mfa
    ON host_cloud_credentials(asset_id, provider)
    WHERE is_long_lived = 1 AND has_mfa = 0;

-- For cross-host duplicate detection on AWS access-key IDs etc.
CREATE INDEX IF NOT EXISTS idx_host_cloud_credentials_key_id
    ON host_cloud_credentials(key_id)
    WHERE key_id IS NOT NULL;

-- For expiry range scans (renewal alerts).
CREATE INDEX IF NOT EXISTS idx_host_cloud_credentials_expires_at
    ON host_cloud_credentials(asset_id, expires_at)
    WHERE expires_at IS NOT NULL;
