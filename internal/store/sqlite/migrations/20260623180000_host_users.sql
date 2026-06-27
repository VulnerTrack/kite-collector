-- 20260623180000_host_users.sql: durable storage for per-host local
-- user inventory introduced by CDMS iter 7.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_users — one row per (asset_id, source, uid). `source` discriminates
--                between purely local accounts and ones synced from a
--                directory (AD via SSSD, OpenLDAP, Entra Cloud Sync), so a
--                user that exists both locally and in AD shows up twice
--                rather than colliding.
--
-- Audit value:
--   - CWE-1004 (Sensitive Default Cookie/Account) — `is_admin=1` accounts
--     other than the OS-provided root/Administrator are a finding.
--   - CWE-862 (Missing Authorization) — `shell` set to /bin/bash on a
--     service account that should be /sbin/nologin.
--   - CWE-521 (Weak Password Requirements) — `password_status='active'`
--     combined with stale `password_age_days` > policy threshold.
--   - Pairs with host_processes.username for "running as which user"
--     queries that join the runtime-state to the credential-state.

CREATE TABLE IF NOT EXISTS host_users (
    id                TEXT PRIMARY KEY NOT NULL,
    asset_id          TEXT NOT NULL,
    username          TEXT NOT NULL,
    uid               TEXT NOT NULL,        -- numeric on Unix, SID on Windows; TEXT to fit both
    primary_gid       TEXT,
    full_name         TEXT,                 -- GECOS / display name
    home              TEXT,
    shell             TEXT,
    source            TEXT NOT NULL DEFAULT 'local'
                      CHECK (source IN (
                          'local', 'ad', 'ldap', 'azure-ad',
                          'sssd', 'open-directory', 'unknown'
                      )),
    is_admin          INTEGER NOT NULL DEFAULT 0
                      CHECK (is_admin IN (0, 1)),
    is_interactive    INTEGER NOT NULL DEFAULT 0
                      CHECK (is_interactive IN (0, 1)),
    is_locked         INTEGER NOT NULL DEFAULT 0
                      CHECK (is_locked IN (0, 1)),
    password_status   TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (password_status IN (
                          'active', 'locked', 'expired',
                          'disabled', 'no-password', 'unknown'
                      )),
    password_age_days INTEGER,
    last_login_at     TEXT,
    groups_json       TEXT NOT NULL DEFAULT '[]',
    last_seen_at      TEXT NOT NULL,
    collected_at      TEXT NOT NULL,
    synced_at         INTEGER,
    created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_users_unique
    ON host_users(asset_id, source, uid);

CREATE INDEX IF NOT EXISTS idx_host_users_unsynced
    ON host_users(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-1004 finding: "show me admin accounts other than root".
CREATE INDEX IF NOT EXISTS idx_host_users_admin
    ON host_users(asset_id, source)
    WHERE is_admin = 1;

-- For the CWE-862 finding: "interactive shell on a service account".
CREATE INDEX IF NOT EXISTS idx_host_users_interactive
    ON host_users(asset_id, is_interactive)
    WHERE is_interactive = 1;
