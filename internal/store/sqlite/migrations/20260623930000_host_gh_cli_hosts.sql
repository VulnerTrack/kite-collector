-- host_gh_cli_hosts inventories GitHub CLI (`gh`) credential
-- bindings: every (host, user) row that `gh` will use to talk
-- to github.com or a GitHub Enterprise instance. The CLI stores
-- a long-lived OAuth token in plain YAML at
-- `~/.config/gh/hosts.yml` (Linux / macOS) or
-- `%APPDATA%\GitHub CLI\hosts.yml` (Windows). Anyone who can
-- read that file gets full repo write + workflow-trigger on
-- every org the token can reach.
--
-- MITRE ATT&CK / CWE:
--   T1552.001 (Credentials In Files) — plaintext oauth_token
--   T1078.004 (Valid Accounts: Cloud Accounts) — GitHub OAuth
--   CWE-256, CWE-732 (insecure perms on credential file)
--
-- Headline finding shapes:
--   is_oauth_token_present  — `oauth_token:` row found.
--   is_unencrypted_token    — token present AND file is
--                             world- or group-readable. The
--                             rolled-up immediate-incident flag.
--   is_credential_exposure_risk — alias kept for cross-collector
--                             reporting parity.
--
-- Token rotation drift is captured via file_hash (SHA-256 of the
-- raw hosts.yml body). The token value itself is NEVER stored —
-- only its 4-char prefix (token_family: `ghp_`/`gho_`/`ghu_`/
-- `ghs_`/`ghr_`) so the audit pipeline can correlate rotations
-- without holding the secret.

CREATE TABLE IF NOT EXISTS host_gh_cli_hosts (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at                TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    file_path                   TEXT    NOT NULL,
    file_hash                   TEXT    NOT NULL,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT    NOT NULL DEFAULT '',
    host                        TEXT    NOT NULL,
    gh_user                     TEXT    NOT NULL DEFAULT '',
    git_protocol                TEXT    NOT NULL DEFAULT '',
    token_family                TEXT    NOT NULL DEFAULT '',
    is_enterprise_host          INTEGER NOT NULL DEFAULT 0 CHECK (is_enterprise_host IN (0,1)),
    is_oauth_token_present      INTEGER NOT NULL DEFAULT 0 CHECK (is_oauth_token_present IN (0,1)),
    is_world_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable IN (0,1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0 CHECK (is_group_readable IN (0,1)),
    is_unencrypted_token        INTEGER NOT NULL DEFAULT 0 CHECK (is_unencrypted_token IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_gh_hosts_token
    ON host_gh_cli_hosts(host) WHERE is_oauth_token_present = 1;

CREATE INDEX IF NOT EXISTS idx_gh_hosts_unencrypted
    ON host_gh_cli_hosts(host) WHERE is_unencrypted_token = 1;

CREATE INDEX IF NOT EXISTS idx_gh_hosts_exposure
    ON host_gh_cli_hosts(host) WHERE is_credential_exposure_risk = 1;

CREATE INDEX IF NOT EXISTS idx_gh_hosts_drift
    ON host_gh_cli_hosts(file_path, file_hash);
