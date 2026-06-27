-- 20260623910000_host_git_config.sql: durable storage for per-host
-- Git configuration + credentials inventory introduced by CDMS
-- iter 84.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_git_config — one row per (file, section, subsection,
--                     key) tuple discovered in any Git config
--                     OR a separate row per entry in a
--                     `~/.git-credentials` file. Each row carries
--                     the file_hash so credential rotations /
--                     URL-rewrite additions surface as diffs
--                     between scans.
--
-- Locations walked:
--   Per-user:   ~/.gitconfig, ~/.git-credentials
--               XDG_CONFIG_HOME/git/config (Linux preferred)
--   System:     /etc/gitconfig
--
-- Audit value (MITRE T1552.001 — Credentials in Files,
-- T1557 — Adversary-in-the-Middle for url-rewrite redirects,
-- T1547.013 — XDG Autostart adjacent for hookspath persistence,
-- T1059 — Command and Scripting Interpreter for command-set
-- knobs):
--   - `key='credential.helper'` with `value='store'` or `''`
--     forces git to store credentials in plaintext at
--     `~/.git-credentials`. The audit pipeline cross-references
--     `entry_kind='credential-record'` rows to see what leaked.
--   - `key='url.<remote>.insteadOf'` rewrites every `git push` /
--     `git fetch` URL transparently — an attacker who can
--     write the gitconfig can MITM every git operation.
--   - `key='core.hookspath'` to a world-writable directory
--     makes every commit/push/checkout run attacker code.
--   - `key='core.sshcommand'` / `key='core.editor'` /
--     `key='core.pager'` set to a non-vendor binary = covert
--     command-execution channel triggered by routine git use.

CREATE TABLE IF NOT EXISTS host_git_config (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    file_mode                       INTEGER NOT NULL DEFAULT 0,
    file_owner_uid                  INTEGER NOT NULL DEFAULT 0,
    user_profile                    TEXT,
    file_scope                      TEXT NOT NULL
                                    CHECK (file_scope IN (
                                        'system', 'global', 'xdg',
                                        'credentials', 'unknown'
                                    )),
    entry_kind                      TEXT NOT NULL
                                    CHECK (entry_kind IN (
                                        'setting', 'credential-record', 'unknown'
                                    )),
    section                         TEXT,                  -- "core" / "credential" / "url"
    subsection                      TEXT,                  -- "git@github.com:" inside `url`
    key                             TEXT NOT NULL,         -- normalised "section.subsection.key" or credential URL
    value                           TEXT,                  -- raw value (credentials redacted on the way in — only host kept)
    is_credential_store_helper      INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_credential_store_helper IN (0, 1)),
    is_no_credential_helper         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_no_credential_helper IN (0, 1)),
    is_url_rewrite                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_url_rewrite IN (0, 1)),
    is_external_hookspath           INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_external_hookspath IN (0, 1)),
    has_command_override            INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_command_override IN (0, 1)),
    is_plaintext_credential         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_plaintext_credential IN (0, 1)),
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_git_config_unique
    ON host_git_config(asset_id, file_path, key, value);

CREATE INDEX IF NOT EXISTS idx_host_git_config_unsynced
    ON host_git_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: plaintext credential leaks (T1552.001 headline).
CREATE INDEX IF NOT EXISTS idx_host_git_config_plaintext_cred
    ON host_git_config(asset_id, file_path)
    WHERE is_plaintext_credential = 1;

-- Fast path: URL-rewrite redirects (T1557 MITM).
CREATE INDEX IF NOT EXISTS idx_host_git_config_url_rewrite
    ON host_git_config(asset_id, file_path, key, value)
    WHERE is_url_rewrite = 1;

-- Fast path: world-writable hookspath (T1547.013).
CREATE INDEX IF NOT EXISTS idx_host_git_config_external_hooks
    ON host_git_config(asset_id, file_path, value)
    WHERE is_external_hookspath = 1;

-- Fast path: command-override knobs set.
CREATE INDEX IF NOT EXISTS idx_host_git_config_command_override
    ON host_git_config(asset_id, file_path, key, value)
    WHERE has_command_override = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_git_config_drift
    ON host_git_config(asset_id, file_path, file_hash);
