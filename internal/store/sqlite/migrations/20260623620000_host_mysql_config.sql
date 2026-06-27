-- 20260623620000_host_mysql_config.sql: durable storage for per-host
-- MySQL / MariaDB server configuration introduced by CDMS iter 55.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_mysql_config — one row per [section] discovered in any
--                       my.cnf file. section_kind separates real
--                       server sections ([mysqld], [mariadb]) from
--                       client-side ([client]) and shared/common
--                       defaults — only the server sections drive
--                       most findings, but [client] gives us the
--                       cleartext credential leak shape.
--
-- Audit value (MITRE T1190 — Exploit Public-Facing Application,
-- T1078.003 — Local Accounts, T1552.001 — Credentials In Files):
--   - CWE-306 (Missing Authentication) — `is_grant_tables_skipped=1`
--     boots MySQL with the privilege subsystem disabled. Any local
--     connect is implicitly root. Often left on after a one-time
--     password reset and never reverted.
--   - CWE-732 (file privilege) — `has_unrestricted_secure_file_priv=1`
--     means LOAD DATA / SELECT INTO can touch any path the mysqld
--     user can read/write — the LDAP-style local file disclosure
--     and the UDF-write-then-load lateral movement both rely on it.
--   - CWE-552 (Files Accessible to External Parties) — `is_local_infile_enabled=1`
--     pairs with a malicious client to read arbitrary mysqld-readable
--     files off the server (CVE-2017-3306 family).
--   - CWE-256 (Cleartext Storage of Password) —
--     `has_cleartext_client_password=1` flags [client] sections that
--     store `password = …` instead of using mysql_config_editor.
--   - CWE-319 (Cleartext Transmission) — `is_secure_transport_required=0`
--     + external bind = plaintext SQL on the wire.
--   - Drift events — file_hash change on any my.cnf = the database
--     surface was reconfigured; alert verbatim.

CREATE TABLE IF NOT EXISTS host_mysql_config (
    id                                  TEXT PRIMARY KEY NOT NULL,
    asset_id                            TEXT NOT NULL,
    file_path                           TEXT NOT NULL,
    file_hash                           TEXT NOT NULL,
    section_name                        TEXT NOT NULL,         -- raw "[mysqld-5.7]" → "mysqld-5.7"
    section_kind                        TEXT NOT NULL
                                        CHECK (section_kind IN (
                                            'server', 'client', 'common', 'unknown'
                                        )),
    bind_address                        TEXT,
    port                                INTEGER,
    socket_path                         TEXT,
    datadir                             TEXT,
    user_name                           TEXT,                  -- runtime user (--user=)
    secure_file_priv                    TEXT,                  -- "" / "NULL" / "/var/lib/mysql-files/"
    tls_version                         TEXT,
    log_error_path                      TEXT,
    general_log                         TEXT,
    plugin_load                         TEXT,
    is_grant_tables_skipped             INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_grant_tables_skipped IN (0, 1)),
    is_networking_skipped               INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_networking_skipped IN (0, 1)),
    is_name_resolve_skipped             INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_name_resolve_skipped IN (0, 1)),
    is_local_infile_enabled             INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_local_infile_enabled IN (0, 1)),
    has_unrestricted_secure_file_priv   INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_unrestricted_secure_file_priv IN (0, 1)),
    is_secure_transport_required        INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_secure_transport_required IN (0, 1)),
    is_externally_bound                 INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_externally_bound IN (0, 1)),
    is_bound_to_loopback_only           INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_bound_to_loopback_only IN (0, 1)),
    has_cleartext_client_password       INTEGER NOT NULL DEFAULT 0
                                        CHECK (has_cleartext_client_password IN (0, 1)),
    is_unauthenticated_world_exposed    INTEGER NOT NULL DEFAULT 0
                                        CHECK (is_unauthenticated_world_exposed IN (0, 1)),
    last_seen_at                        TEXT NOT NULL,
    collected_at                        TEXT NOT NULL,
    synced_at                           INTEGER,
    created_at                          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_mysql_config_unique
    ON host_mysql_config(asset_id, file_path, section_name);

CREATE INDEX IF NOT EXISTS idx_host_mysql_config_unsynced
    ON host_mysql_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me MySQL booted without the grant tables"
-- (CWE-306 — implicit root for every connection).
CREATE INDEX IF NOT EXISTS idx_host_mysql_config_skip_grants
    ON host_mysql_config(asset_id, file_path)
    WHERE is_grant_tables_skipped = 1;

-- Fast path: "unauthenticated world-exposed" (CWE-306 + T1190).
CREATE INDEX IF NOT EXISTS idx_host_mysql_config_open
    ON host_mysql_config(asset_id, file_path, section_name)
    WHERE is_unauthenticated_world_exposed = 1;

-- Fast path: cleartext client passwords (CWE-256 / T1552.001).
CREATE INDEX IF NOT EXISTS idx_host_mysql_config_cleartext_pw
    ON host_mysql_config(asset_id, file_path)
    WHERE has_cleartext_client_password = 1;

-- Fast path: unrestricted secure_file_priv (UDF + arbitrary read).
CREATE INDEX IF NOT EXISTS idx_host_mysql_config_unrestricted_files
    ON host_mysql_config(asset_id, file_path)
    WHERE has_unrestricted_secure_file_priv = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_mysql_config_file_hash
    ON host_mysql_config(asset_id, file_path, file_hash);
