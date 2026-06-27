-- 20260623630000_host_mongod_config.sql: durable storage for per-host
-- MongoDB server configuration introduced by CDMS iter 56.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_mongod_config — singleton per asset capturing mongod.conf
--                        (YAML). MongoDB's default-deny posture
--                        flipped only in 3.6 to bind 127.0.0.1; the
--                        long tail of 2015-2017 deployments still
--                        ships with the old "everyone, no auth"
--                        defaults that fuelled the 2017 ransom waves.
--
-- Audit value (MITRE T1190 — Exploit Public-Facing Application,
-- T1486 — Data Encrypted for Impact):
--   - CWE-306 (Missing Authentication) — `is_authorization_disabled=1`
--     is the canonical MongoDB ransom shape: connect, drop every db,
--     leave a ransom note. The MongoCrypt wave (Jan 2017) hit ~28k
--     unauthenticated instances in a week.
--   - CWE-94 (Improper Control of Generated Code) — `is_scripting_enabled=1`
--     means server-side JavaScript (`$where`, `mapReduce`) executes
--     inside mongod. Combined with auth-disabled = unauth RCE.
--   - CWE-287 (Improper Authentication) — `is_localhost_auth_bypass_enabled=1`
--     lets the first connection from 127.0.0.1 create users without
--     auth. Safe in a hardened deploy, dangerous on shared hosts.
--   - CWE-319 (Cleartext Transmission) — `is_tls_disabled_with_external_bind=1`
--     captures mongod serving plaintext on a non-loopback interface.
--   - Drift events — file_hash change on mongod.conf = the data
--     plane was reconfigured; alert verbatim.

CREATE TABLE IF NOT EXISTS host_mongod_config (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    source                              TEXT NOT NULL
                                        CHECK (source IN (
                                            'config-yaml', 'no-config',
                                            'no-probe', 'unknown'
                                        )),
    config_path                         TEXT,
    file_hash                           TEXT,
    bind_ips_json                       TEXT NOT NULL DEFAULT '[]',
    port                                INTEGER,
    db_path                             TEXT,
    log_path                            TEXT,
    log_destination                     TEXT,
    authorization_mode                  TEXT,                  -- "enabled" / "disabled"
    cluster_auth_mode                   TEXT,
    tls_mode                            TEXT,                  -- "disabled" / "allowTLS" / "preferTLS" / "requireTLS"
    tls_cert_key_file                   TEXT,
    tls_ca_file                         TEXT,
    keyfile_path                        TEXT,
    replica_set_name                    TEXT,
    is_externally_bound                 INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_externally_bound IN (0, 1)),
    is_bound_to_loopback_only           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_bound_to_loopback_only IN (0, 1)),
    is_authorization_disabled           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_authorization_disabled IN (0, 1)),
    is_localhost_auth_bypass_enabled    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_localhost_auth_bypass_enabled IN (0, 1)),
    is_scripting_enabled                INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_scripting_enabled IN (0, 1)),
    is_http_interface_enabled           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_http_interface_enabled IN (0, 1)),
    is_tls_enabled                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_tls_enabled IN (0, 1)),
    is_tls_disabled_with_external_bind  INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_tls_disabled_with_external_bind IN (0, 1)),
    is_unauthenticated_world_exposed    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_unauthenticated_world_exposed IN (0, 1)),
    is_hardened                         INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_hardened IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_mongod_config_unique
    ON host_mongod_config(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_mongod_config_unsynced
    ON host_mongod_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me unauthenticated Mongo exposed to the world"
-- (CWE-306 + T1190 + T1486 — the canonical 2017-ransom shape).
CREATE INDEX IF NOT EXISTS idx_host_mongod_config_open
    ON host_mongod_config(asset_id)
    WHERE is_unauthenticated_world_exposed = 1;

-- Fast path: "scripting enabled + auth disabled = unauth RCE".
CREATE INDEX IF NOT EXISTS idx_host_mongod_config_unauth_rce
    ON host_mongod_config(asset_id)
    WHERE is_scripting_enabled = 1 AND is_authorization_disabled = 1;

-- Fast path: "TLS off + external bind = plaintext on the wire".
CREATE INDEX IF NOT EXISTS idx_host_mongod_config_plaintext
    ON host_mongod_config(asset_id)
    WHERE is_tls_disabled_with_external_bind = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_mongod_config_file_hash
    ON host_mongod_config(asset_id, file_hash);
