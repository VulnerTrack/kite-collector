-- 20260623450000_host_git_repos.sql: durable storage for per-host
-- git repository inventory introduced by CDMS iter 34.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_git_repos — one row per (asset_id, repo_path, remote_name).
--                    A repository with two remotes (`origin` + `upstream`)
--                    appears as two rows; a repository with no remotes
--                    appears as one row with remote_name='' and
--                    remote_url=''. Cross-platform: the same walker
--                    handles Linux, macOS, and Windows working trees.
--
-- Audit value:
--   - MITRE T1213.003 (Data from Information Repositories: Code
--     Repositories) — local clones of internal source trees on a
--     non-developer host = unexpected exposure. The audit pipeline
--     joins this against host_users to spot user-account drift.
--   - MITRE T1552.004 (Unsecured Credentials: Private Keys + Tokens)
--     — `is_credential_in_url=1` flags remote URLs of the shape
--     `https://user:token@github.com/...` (PAT leakage) or any URL
--     with a userinfo component.
--   - MITRE T1546.005 (Event Triggered Execution: Trap) — git hooks
--     under .git/hooks/ run with the user's privileges on every
--     `git commit` / `git push`. `has_executable_hook=1` flags
--     repos with custom hooks beyond the default .sample shipped
--     files. Combined with a recently-modified mtime it's a strong
--     persistence indicator.
--   - CWE-200 — `is_world_readable=1` flags repos whose .git
--     directory is mode 0755+ (i.e., world-readable). Source code +
--     reflog + packed-objects all become readable.
--   - CWE-915 (Improperly Controlled Modification) — `has_insteadof=1`
--     flags `url.<base>.insteadOf` rewrites that silently redirect
--     `git fetch` to a different URL. Classic supply-chain primitive.
--   - Drift events — file_hash change on .git/config = remote/credential
--     reconfiguration. Always worth alerting on.

CREATE TABLE IF NOT EXISTS host_git_repos (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    repo_path                TEXT NOT NULL,            -- working-tree root
    git_dir                  TEXT NOT NULL,            -- absolute path to .git
    is_bare                  INTEGER NOT NULL DEFAULT 0
                             CHECK (is_bare IN (0, 1)),
    head_branch              TEXT,                     -- "main", "trunk", NULL when detached
    remote_name              TEXT NOT NULL DEFAULT '', -- "origin" / "upstream" / "" when none
    remote_url               TEXT,                     -- raw URL from .git/config
    remote_host              TEXT,                     -- "github.com" / "gitlab.corp.local"
    user_email               TEXT,                     -- user.email from git config
    user_name                TEXT,
    credential_helper        TEXT,                     -- "store", "manager-core", etc.
    ssh_command              TEXT,                     -- core.sshCommand override
    insteadof_pairs_json     TEXT NOT NULL DEFAULT '[]',
    executable_hooks_json    TEXT NOT NULL DEFAULT '[]',
    is_credential_in_url     INTEGER NOT NULL DEFAULT 0
                             CHECK (is_credential_in_url IN (0, 1)),
    has_executable_hook      INTEGER NOT NULL DEFAULT 0
                             CHECK (has_executable_hook IN (0, 1)),
    has_insteadof            INTEGER NOT NULL DEFAULT 0
                             CHECK (has_insteadof IN (0, 1)),
    has_ssh_command_override INTEGER NOT NULL DEFAULT 0
                             CHECK (has_ssh_command_override IN (0, 1)),
    is_world_readable        INTEGER NOT NULL DEFAULT 0
                             CHECK (is_world_readable IN (0, 1)),
    owner_uid                INTEGER,
    config_mode              INTEGER,
    file_path                TEXT,                     -- .git/config absolute path
    file_hash                TEXT,                     -- sha256 of .git/config
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_git_repos_unique
    ON host_git_repos(asset_id, repo_path, remote_name);

CREATE INDEX IF NOT EXISTS idx_host_git_repos_unsynced
    ON host_git_repos(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me remote URLs with embedded credentials".
CREATE INDEX IF NOT EXISTS idx_host_git_repos_cred_in_url
    ON host_git_repos(asset_id, remote_host)
    WHERE is_credential_in_url = 1;

-- Fast path: "show me repos with custom (non-.sample) hooks".
CREATE INDEX IF NOT EXISTS idx_host_git_repos_hooks
    ON host_git_repos(asset_id, repo_path)
    WHERE has_executable_hook = 1;

-- Fast path: "show me insteadOf URL rewrites" (supply-chain hijack).
CREATE INDEX IF NOT EXISTS idx_host_git_repos_insteadof
    ON host_git_repos(asset_id, repo_path)
    WHERE has_insteadof = 1;

-- Drift detection on per-repo .git/config.
CREATE INDEX IF NOT EXISTS idx_host_git_repos_file_hash
    ON host_git_repos(asset_id, file_path, file_hash);
