-- 20260623610000_host_redis_config.sql: durable storage for per-host
-- Redis server configuration introduced by CDMS iter 54.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_redis_config — singleton per asset (one row per redis.conf
--                       file we discover; most hosts have a single
--                       instance, but a Sentinel + primary side-car
--                       layout is two rows tagged by config_role).
--
-- Audit value (MITRE T1190 — Exploit Public-Facing Application,
-- T1078 — Valid Accounts):
--   - CWE-306 (Missing Authentication) — `is_unauthenticated_world_exposed=1`
--     captures the canonical "internet-facing Redis with no
--     requirepass" shape that yields pre-auth RCE via
--     `CONFIG SET dir / SLAVEOF / MODULE LOAD`. Most-exploited Redis
--     misconfiguration of the last decade.
--   - CWE-326 (Inadequate Encryption Strength) — `is_password_weak=1`
--     flags requirepass < 16 chars or matching one of Redis's stock
--     defaults ("foobared", "redis").
--   - CWE-862 (Missing Authorization) — `has_dangerous_unrenamed_commands=1`
--     is true when CONFIG, EVAL, MODULE, DEBUG, FLUSHALL, SHUTDOWN
--     remain at their default names on a host without ACL gating.
--   - CWE-319 (Cleartext Transmission) — `is_tls_disabled_with_external_bind=1`
--     captures Redis serving plaintext on a non-loopback interface.
--   - Drift events — file_hash change on redis.conf = the data
--     plane was reconfigured; alert verbatim.

CREATE TABLE IF NOT EXISTS host_redis_config (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    file_path                           TEXT NOT NULL,
    file_hash                           TEXT NOT NULL,
    config_role                         TEXT NOT NULL
                                        CHECK (config_role IN (
                                            'server', 'sentinel', 'cluster', 'unknown'
                                        )),
    port                                INTEGER,
    tls_port                            INTEGER,
    bind_addresses_json                 TEXT NOT NULL DEFAULT '[]',
    dir                                 TEXT,
    dbfilename                          TEXT,
    appendonly                          TEXT,
    appendfilename                      TEXT,
    aclfile                             TEXT,
    renamed_commands_json               TEXT NOT NULL DEFAULT '[]',
    includes_json                       TEXT NOT NULL DEFAULT '[]',
    requirepass_present                 INTEGER NOT NULL DEFAULT 0
                                        CHECK (requirepass_present IN (0, 1)),
    masterauth_present                  INTEGER NOT NULL DEFAULT 0
                                        CHECK (masterauth_present IN (0, 1)),
    is_protected_mode_enabled           INTEGER NOT NULL DEFAULT 1
                                        CHECK (is_protected_mode_enabled IN (0, 1)),
    is_bound_to_loopback_only           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_bound_to_loopback_only IN (0, 1)),
    is_externally_bound                 INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_externally_bound IN (0, 1)),
    is_password_weak                    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_password_weak IN (0, 1)),
    is_acl_enabled                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_acl_enabled IN (0, 1)),
    has_dangerous_unrenamed_commands    INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_dangerous_unrenamed_commands IN (0, 1)),
    is_tls_enabled                      INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_tls_enabled IN (0, 1)),
    is_tls_disabled_with_external_bind  INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_tls_disabled_with_external_bind IN (0, 1)),
    is_unauthenticated_world_exposed    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_unauthenticated_world_exposed IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_redis_config_unique
    ON host_redis_config(asset_id, file_path);

CREATE INDEX IF NOT EXISTS idx_host_redis_config_unsynced
    ON host_redis_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me unauthenticated Redis exposed to the world"
-- (CWE-306 + T1190 — the canonical pre-auth RCE).
CREATE INDEX IF NOT EXISTS idx_host_redis_config_open
    ON host_redis_config(asset_id, file_path)
    WHERE is_unauthenticated_world_exposed = 1;

-- Fast path: "weak password = brute force away".
CREATE INDEX IF NOT EXISTS idx_host_redis_config_weak_pass
    ON host_redis_config(asset_id, file_path)
    WHERE requirepass_present = 1 AND is_password_weak = 1;

-- Fast path: "TLS off on a non-loopback bind".
CREATE INDEX IF NOT EXISTS idx_host_redis_config_plaintext
    ON host_redis_config(asset_id, file_path)
    WHERE is_tls_disabled_with_external_bind = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_redis_config_file_hash
    ON host_redis_config(asset_id, file_path, file_hash);
