-- 20260623520000_host_windows_iis.sql: per-host Windows IIS inventory
-- introduced by CDMS iter 45.
--
-- Two related tables in one migration:
--
--   host_windows_iis_sites      — one row per IIS website. Bindings
--                                 (protocol/IP/port/cert) live in
--                                 bindings_json; the audit pipeline
--                                 fans them out when joining against
--                                 host_listeners + the certificate
--                                 store.
--
--   host_windows_iis_app_pools  — one row per application pool.
--                                 Identity (LocalSystem/Specific/etc)
--                                 + managed runtime + 32-bit flag.
--
-- Audit value (MITRE T1190 — Exploit Public-Facing Application,
-- defender side):
--   - CWE-319 (Cleartext Transmission) — sites with `has_http_binding=1
--     AND has_https_binding=0` serve plain HTTP without TLS.
--   - CWE-250 (Unnecessary Privileges) — app pools running as
--     LocalSystem are an instant SYSTEM-shell on RCE. The audit
--     pipeline alerts on `is_privileged_identity=1` for any pool
--     hosting a public-facing site.
--   - CWE-295 (Improper Cert Validation) — the audit pipeline joins
--     bindings_json cert thumbprints against host_certificates to
--     spot HTTPS bindings using self-signed / expired certs.
--   - `is_running=0` on a site whose physical_path still exists =
--     forensic surface (residual webroot from a decommissioned app).

CREATE TABLE IF NOT EXISTS host_windows_iis_sites (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'powershell-iisadmin',
                            'powershell-webadmin',
                            'unknown'
                        )),
    site_id             INTEGER NOT NULL DEFAULT 0,
    site_name           TEXT NOT NULL,
    state               TEXT,                  -- "Started" / "Stopped" / "Unknown"
    physical_path       TEXT,
    app_pool_name       TEXT,
    enabled_protocols   TEXT,                  -- csv: "http,https,net.tcp"
    bindings_json       TEXT NOT NULL DEFAULT '[]',
    log_directory       TEXT,
    is_running          INTEGER NOT NULL DEFAULT 0
                        CHECK (is_running IN (0, 1)),
    has_http_binding    INTEGER NOT NULL DEFAULT 0
                        CHECK (has_http_binding IN (0, 1)),
    has_https_binding   INTEGER NOT NULL DEFAULT 0
                        CHECK (has_https_binding IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_iis_sites_unique
    ON host_windows_iis_sites(asset_id, site_name);

CREATE INDEX IF NOT EXISTS idx_host_windows_iis_sites_unsynced
    ON host_windows_iis_sites(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me sites running plain HTTP with no HTTPS counterpart".
CREATE INDEX IF NOT EXISTS idx_host_windows_iis_sites_http_only
    ON host_windows_iis_sites(asset_id, site_name)
    WHERE has_http_binding = 1 AND has_https_binding = 0;

CREATE TABLE IF NOT EXISTS host_windows_iis_app_pools (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    source                   TEXT NOT NULL
                             CHECK (source IN (
                                 'powershell-iisadmin',
                                 'powershell-webadmin',
                                 'unknown'
                             )),
    pool_name                TEXT NOT NULL,
    state                    TEXT,                  -- "Started" / "Stopped"
    managed_runtime_version  TEXT,                  -- "v4.0" / "" (No Managed Code)
    managed_pipeline_mode    TEXT,                  -- "Integrated" / "Classic"
    identity_type            TEXT,                  -- "LocalSystem" / "LocalService" / ...
    identity_username        TEXT,                  -- when identity_type = SpecificUser
    enable_32bit_on_64bit    INTEGER NOT NULL DEFAULT 0
                             CHECK (enable_32bit_on_64bit IN (0, 1)),
    idle_timeout_minutes     INTEGER NOT NULL DEFAULT 0,
    start_mode               TEXT,                  -- "OnDemand" / "AlwaysRunning"
    auto_start               INTEGER NOT NULL DEFAULT 0
                             CHECK (auto_start IN (0, 1)),
    is_running               INTEGER NOT NULL DEFAULT 0
                             CHECK (is_running IN (0, 1)),
    is_privileged_identity   INTEGER NOT NULL DEFAULT 0
                             CHECK (is_privileged_identity IN (0, 1)),
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_iis_app_pools_unique
    ON host_windows_iis_app_pools(asset_id, pool_name);

CREATE INDEX IF NOT EXISTS idx_host_windows_iis_app_pools_unsynced
    ON host_windows_iis_app_pools(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me pools running as LocalSystem".
CREATE INDEX IF NOT EXISTS idx_host_windows_iis_app_pools_privileged
    ON host_windows_iis_app_pools(asset_id, pool_name)
    WHERE is_privileged_identity = 1;
