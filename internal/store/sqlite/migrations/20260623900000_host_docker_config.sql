-- 20260623900000_host_docker_config.sql: durable storage for per-
-- host Docker CLI `config.json` inventory introduced by CDMS
-- iter 83.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_docker_config — one row per entry parsed out of a
--                        per-user `~/.docker/config.json`. The
--                        Docker CLI walks the same file for
--                        registry credentials, credential
--                        helpers, HTTP proxies, and plugin
--                        directories — every shape lands in
--                        this table tagged by entry_kind.
--
-- Audit value (MITRE T1552.001 — Credentials in Files,
-- T1048 — Exfiltration Over Alternative Protocol for proxy
-- redirects, T1574.005 — Hijack Execution Flow for plugin
-- search paths):
--   - `entry_kind='auth'` with `has_inline_auth=1` is the
--     headline incident shape: the credential store contains
--     base64(`username:password`) for one or more registries,
--     in plaintext on disk.
--   - `entry_kind='cred-helper'` with `credential_helper_name=""`
--     means the operator opted INTO inline credentials over a
--     secure-helper store. The audit pipeline cross-references
--     the helper name against the curated approved set
--     (`osxkeychain`, `wincred`, `secretservice`, `pass`,
--     `ecr-login`, `gcloud`, `desktop`).
--   - `entry_kind='proxy'` with `proxy_target_is_external=1`
--     means the proxy URL points outside the curated corporate
--     allowlist (T1048 covert exfil channel).
--   - `entry_kind='cli-plugin-dir'` with
--     `is_world_writable_dir=1` is a CWE-426 search-path-
--     poisoning target.
--   - `is_world_readable=1` / `is_group_readable=1` on the
--     file itself — combined with any `has_inline_auth=1` row
--     promotes immediate-incident.

CREATE TABLE IF NOT EXISTS host_docker_config (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    file_mode                   INTEGER NOT NULL DEFAULT 0,
    file_owner_uid              INTEGER NOT NULL DEFAULT 0,
    user_profile                TEXT,
    entry_kind                  TEXT NOT NULL
                                CHECK (entry_kind IN (
                                    'auth', 'cred-helper', 'proxy',
                                    'cli-plugin-dir', 'cli-config',
                                    'unknown'
                                )),
    entry_name                  TEXT NOT NULL,        -- registry / proxy-key / dir-path / cli-key
    -- auth-specific
    registry_host               TEXT,
    has_inline_auth             INTEGER NOT NULL DEFAULT 0
                                CHECK (has_inline_auth IN (0, 1)),
    has_identitytoken           INTEGER NOT NULL DEFAULT 0
                                CHECK (has_identitytoken IN (0, 1)),
    -- credential helper
    credential_helper_name      TEXT,
    is_secure_credential_helper INTEGER NOT NULL DEFAULT 0
                                CHECK (is_secure_credential_helper IN (0, 1)),
    -- proxy
    proxy_url                   TEXT,
    proxy_target_is_external    INTEGER NOT NULL DEFAULT 0
                                CHECK (proxy_target_is_external IN (0, 1)),
    -- plugin dir
    cli_plugin_dir              TEXT,
    is_world_writable_dir       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_world_writable_dir IN (0, 1)),
    -- file-level rollups (replicated on every row)
    is_world_readable           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_world_readable IN (0, 1)),
    is_group_readable           INTEGER NOT NULL DEFAULT 0
                                CHECK (is_group_readable IN (0, 1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0
                                CHECK (is_credential_exposure_risk IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_docker_config_unique
    ON host_docker_config(asset_id, file_path, entry_kind, entry_name);

CREATE INDEX IF NOT EXISTS idx_host_docker_config_unsynced
    ON host_docker_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: inline registry credentials in a readable file.
CREATE INDEX IF NOT EXISTS idx_host_docker_config_inline_auth
    ON host_docker_config(asset_id, file_path, registry_host)
    WHERE has_inline_auth = 1;

-- Fast path: credential-helper not in the curated secure set.
CREATE INDEX IF NOT EXISTS idx_host_docker_config_unsafe_helper
    ON host_docker_config(asset_id, file_path, credential_helper_name)
    WHERE entry_kind = 'cred-helper' AND is_secure_credential_helper = 0;

-- Fast path: external-target proxy (potential exfil channel).
CREATE INDEX IF NOT EXISTS idx_host_docker_config_external_proxy
    ON host_docker_config(asset_id, file_path, proxy_url)
    WHERE proxy_target_is_external = 1;

-- Fast path: world-writable plugin directories (CWE-426).
CREATE INDEX IF NOT EXISTS idx_host_docker_config_plugin_wwd
    ON host_docker_config(asset_id, file_path, cli_plugin_dir)
    WHERE is_world_writable_dir = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_docker_config_drift
    ON host_docker_config(asset_id, file_path, file_hash);
