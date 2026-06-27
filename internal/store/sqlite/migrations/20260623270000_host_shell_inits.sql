-- 20260623270000_host_shell_inits.sql: durable storage for per-host
-- shell-initialization-file inventory introduced by CDMS iter 16.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_shell_inits — one row per (asset_id, file_path, file_hash).
--                      file_hash is part of the key so drift between
--                      scans surfaces as a new row + old row stale,
--                      rather than overwriting in place. The DBOS
--                      bridge can emit a "shell-init modified" audit
--                      event on the hash change.
--
-- Audit value (MITRE T1546.004 — Event-Triggered Execution: Unix Shell
-- Configuration Modification):
--   - `aliases_json` containing a command name that shadows a system
--     binary (e.g. `alias ls='rm -rf /' ; alias sudo='evilbin'`).
--   - `path_prepends_json` containing world-writable directories
--     (/tmp, /var/tmp, /home/<other-user>/bin) → CWE-426 (Untrusted
--     Search Path).
--   - `sourced_files_json` referencing paths outside system-owned
--     directories — every source = transitive include of attacker-
--     controllable code.
--   - `contains_eval=1` is a heuristic for dynamic-code-execution
--     patterns; combined with `exports_json` referencing env vars
--     from $SSH_CONNECTION / $REMOTE_ADDR etc. = command-injection
--     opportunity.
--   - `file_hash` drift between scans = persistence-mechanism change
--     event, even when nobody has notified the change-management
--     workflow.

CREATE TABLE IF NOT EXISTS host_shell_inits (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    shell               TEXT NOT NULL
                        CHECK (shell IN (
                            'bash', 'zsh', 'fish', 'sh', 'dash',
                            'csh', 'tcsh', 'ksh', 'powershell',
                            'unknown'
                        )),
    scope               TEXT NOT NULL
                        CHECK (scope IN ('system', 'user')),
    file_role           TEXT NOT NULL
                        CHECK (file_role IN (
                            'rc', 'profile', 'login', 'logout',
                            'env', 'drop-in', 'unknown'
                        )),
    file_path           TEXT NOT NULL,
    owner_user          TEXT,
    file_hash           TEXT NOT NULL,            -- sha256 hex of file contents
    file_size_bytes     INTEGER NOT NULL DEFAULT 0,
    aliases_json        TEXT NOT NULL DEFAULT '{}',  -- {"ls": "ls --color=auto"}
    exports_json        TEXT NOT NULL DEFAULT '{}',  -- {"EDITOR": "vim"}
    path_prepends_json  TEXT NOT NULL DEFAULT '[]',  -- paths prepended/appended to $PATH
    sourced_files_json  TEXT NOT NULL DEFAULT '[]',  -- paths sourced via `source` or `.`
    contains_eval       INTEGER NOT NULL DEFAULT 0
                        CHECK (contains_eval IN (0, 1)),
    contains_curl_pipe  INTEGER NOT NULL DEFAULT 0  -- `curl … | sh` / `wget … | bash`
                        CHECK (contains_curl_pipe IN (0, 1)),
    has_untrusted_path  INTEGER NOT NULL DEFAULT 0  -- PATH prepend includes /tmp/, /var/tmp/, /home/<other>/bin
                        CHECK (has_untrusted_path IN (0, 1)),
    has_shadow_alias    INTEGER NOT NULL DEFAULT 0  -- alias name shadows a common system binary
                        CHECK (has_shadow_alias IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_shell_inits_unique
    ON host_shell_inits(asset_id, file_path, file_hash);

CREATE INDEX IF NOT EXISTS idx_host_shell_inits_unsynced
    ON host_shell_inits(synced_at)
    WHERE synced_at IS NULL;

-- For T1546.004: "show me anything with shadow aliases on this host".
CREATE INDEX IF NOT EXISTS idx_host_shell_inits_shadow
    ON host_shell_inits(asset_id, shell)
    WHERE has_shadow_alias = 1;

-- For CWE-426 (Untrusted Search Path) fast-path.
CREATE INDEX IF NOT EXISTS idx_host_shell_inits_untrusted_path
    ON host_shell_inits(asset_id, shell)
    WHERE has_untrusted_path = 1;

-- For drift detection — find the latest hash per file across scans.
CREATE INDEX IF NOT EXISTS idx_host_shell_inits_by_file
    ON host_shell_inits(asset_id, file_path, last_seen_at);
