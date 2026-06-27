-- 20260623920000_host_npmrc_entries.sql: durable storage for per-
-- host `.npmrc` configuration + token inventory introduced by
-- CDMS iter 85.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_npmrc_entries — one row per `key = value` entry parsed
--                        out of any `.npmrc` file on the host:
--                          Per-user:  ~/.npmrc (Windows %USERPROFILE%\.npmrc)
--                          Global:    $PREFIX/etc/npmrc, /etc/npmrc
--                          Built-in:  /usr/lib/node_modules/npm/npmrc
--                          Plus paths in NPM_CONFIG_USERCONFIG /
--                                        NPM_CONFIG_GLOBALCONFIG
--
-- Audit value (MITRE T1552.001 — Credentials in Files, plus
-- T1195.002 — Compromise Software Supply Chain when a stolen
-- `_authToken` is used to push malicious package versions):
--   - `is_auth_token=1` — `//registry/:_authToken=` row. Bearer
--     tokens are full-publish credentials on npmjs.org and
--     equivalent for most private registries.
--   - `is_password_secret=1` — `//registry/:_password=` row
--     (base64-encoded password from legacy basic-auth flows).
--   - `is_strict_ssl_disabled=1` — `strict-ssl=false` disables
--     TLS validation on every `npm install`; on-path attacker
--     swaps package contents (CWE-295 + T1565.002).
--   - `is_script_shell_override=1` — `script-shell` swapped to
--     a non-vendor binary; every `npm run <script>` invocation
--     funnels through it (T1059).
--   - `is_world_readable=1` / `is_group_readable=1` on the file
--     combined with `is_auth_token=1` promotes immediate-
--     incident.

CREATE TABLE IF NOT EXISTS host_npmrc_entries (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    file_mode                       INTEGER NOT NULL DEFAULT 0,
    file_owner_uid                  INTEGER NOT NULL DEFAULT 0,
    user_profile                    TEXT,
    file_scope                      TEXT NOT NULL
                                    CHECK (file_scope IN (
                                        'user', 'global', 'builtin',
                                        'project', 'unknown'
                                    )),
    entry_kind                      TEXT NOT NULL
                                    CHECK (entry_kind IN (
                                        'auth-token', 'password',
                                        'username', 'registry',
                                        'scope-registry', 'setting',
                                        'unknown'
                                    )),
    key                             TEXT NOT NULL,
    value                           TEXT,                   -- redacted: hash/host only for secrets
    registry_host                   TEXT,                   -- registry URL host for credential rows
    scope                           TEXT,                   -- @org for scoped-registry rows
    is_auth_token                   INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_auth_token IN (0, 1)),
    is_password_secret              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_password_secret IN (0, 1)),
    is_strict_ssl_disabled          INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_strict_ssl_disabled IN (0, 1)),
    is_script_shell_override        INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_script_shell_override IN (0, 1)),
    is_prefix_in_world_writable_dir INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_prefix_in_world_writable_dir IN (0, 1)),
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_npmrc_entries_unique
    ON host_npmrc_entries(asset_id, file_path, key);

CREATE INDEX IF NOT EXISTS idx_host_npmrc_entries_unsynced
    ON host_npmrc_entries(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: auth tokens (T1552.001 + T1195.002 publish-access).
CREATE INDEX IF NOT EXISTS idx_host_npmrc_entries_auth_token
    ON host_npmrc_entries(asset_id, file_path, registry_host)
    WHERE is_auth_token = 1;

-- Fast path: strict-ssl=false (TLS-bypass MITM exposure).
CREATE INDEX IF NOT EXISTS idx_host_npmrc_entries_strict_ssl
    ON host_npmrc_entries(asset_id, file_path)
    WHERE is_strict_ssl_disabled = 1;

-- Fast path: world-readable file holding credentials.
CREATE INDEX IF NOT EXISTS idx_host_npmrc_entries_credentialrisk
    ON host_npmrc_entries(asset_id, file_path, key)
    WHERE is_credential_exposure_risk = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_npmrc_entries_drift
    ON host_npmrc_entries(asset_id, file_path, file_hash);
