-- 20260623590000_host_docker_daemon.sql: durable storage for per-host
-- Docker daemon configuration introduced by CDMS iter 52.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_docker_daemon — singleton per asset capturing
--                        /etc/docker/daemon.json + the running engine
--                        version/storage driver. The Docker daemon is
--                        the most privileged service on a container
--                        host; misconfiguring it is the difference
--                        between contained workloads and a full host
--                        compromise.
--
-- Audit value (MITRE T1610 — Deploy Container, T1611 — Escape to Host):
--   - CWE-306 (Missing Authentication) — `is_tcp_socket_exposed=1`
--     means the daemon listens on a TCP socket. With `is_tls_enabled=0`
--     this is the classic "anyone with network reach gets root on the
--     host" path: `docker -H host:2375 run --privileged -v /:/host …`.
--   - CWE-295 (Improper Cert Validation) — `has_insecure_registries=1`
--     means the engine pulls images over plaintext / with self-signed
--     certs, opening MITM image substitution (T1525 image tampering).
--   - CWE-269 (Improper Privilege Management):
--       - `is_no_new_privileges_default=0` lets containers regain
--         privileges via setuid binaries.
--       - `is_userns_remapped=0` means container UID 0 = host UID 0.
--       - `is_iptables_managed=0` disables daemon firewall rules; the
--         operator may not have replacement rules in place.
--   - Drift events — file_hash change on daemon.json = the container
--     plane was reconfigured. Always worth alerting.

CREATE TABLE IF NOT EXISTS host_docker_daemon (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    source                          TEXT NOT NULL
                                    CHECK (source IN (
                                        'daemon-json', 'no-config',
                                        'no-probe', 'unknown'
                                    )),
    config_path                     TEXT,
    file_hash                       TEXT,
    raw_config_json                 TEXT,                  -- pretty-printed daemon.json or "{}"
    hosts_json                      TEXT NOT NULL DEFAULT '[]',
    insecure_registries_json        TEXT NOT NULL DEFAULT '[]',
    registry_mirrors_json           TEXT NOT NULL DEFAULT '[]',
    default_runtime                 TEXT,
    cgroup_parent                   TEXT,
    storage_driver                  TEXT,
    log_driver                      TEXT,
    userns_remap                    TEXT,                  -- "default", "uid:gid", "" = off
    seccomp_profile                 TEXT,
    is_tcp_socket_exposed           INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_tcp_socket_exposed IN (0, 1)),
    is_tcp_socket_world_exposed     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_tcp_socket_world_exposed IN (0, 1)),
    is_tls_enabled                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_tls_enabled IN (0, 1)),
    is_tls_verify_enabled           INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_tls_verify_enabled IN (0, 1)),
    has_insecure_registries         INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_insecure_registries IN (0, 1)),
    is_userns_remapped              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_userns_remapped IN (0, 1)),
    is_no_new_privileges_default    INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_no_new_privileges_default IN (0, 1)),
    is_iptables_managed             INTEGER NOT NULL DEFAULT 1
                                    CHECK (is_iptables_managed IN (0, 1)),
    is_live_restore_enabled         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_live_restore_enabled IN (0, 1)),
    is_selinux_enabled              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_selinux_enabled IN (0, 1)),
    is_experimental_enabled         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_experimental_enabled IN (0, 1)),
    is_hardened                     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_hardened IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_docker_daemon_unique
    ON host_docker_daemon(asset_id);

CREATE INDEX IF NOT EXISTS idx_host_docker_daemon_unsynced
    ON host_docker_daemon(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me daemons with the API exposed to the world"
-- (CWE-306 + T1610 — unauthenticated container run on a remote host).
CREATE INDEX IF NOT EXISTS idx_host_docker_daemon_world_api
    ON host_docker_daemon(asset_id)
    WHERE is_tcp_socket_world_exposed = 1 AND is_tls_verify_enabled = 0;

-- Fast path: "insecure registry trust = MITM image pulls".
CREATE INDEX IF NOT EXISTS idx_host_docker_daemon_insecure_reg
    ON host_docker_daemon(asset_id)
    WHERE has_insecure_registries = 1;

-- Fast path: "container UID 0 = host UID 0".
CREATE INDEX IF NOT EXISTS idx_host_docker_daemon_no_userns
    ON host_docker_daemon(asset_id)
    WHERE is_userns_remapped = 0;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_docker_daemon_file_hash
    ON host_docker_daemon(asset_id, file_hash);
