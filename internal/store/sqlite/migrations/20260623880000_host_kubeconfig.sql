-- 20260623880000_host_kubeconfig.sql: durable storage for per-host
-- kubeconfig artifact inventory introduced by CDMS iter 81.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_kubeconfig — one row per (cluster | user | context)
--                     entry discovered in any kubeconfig file on
--                     the host. Each row carries the file_hash so
--                     the audit pipeline catches credential
--                     additions / removals between scans.
--
-- Locations walked:
--   Windows: C:\Users\<u>\.kube\config
--   Linux:   /root/.kube/config, /home/<u>/.kube/config
--   macOS:   /Users/<u>/.kube/config
--   plus every path listed in the `KUBECONFIG` env var.
--
-- Audit value (MITRE T1552.001 — Credentials in Files, plus
-- T1102 — Web Service for exec-plugin token brokers,
-- T1078.004 — Valid Accounts: Cloud Accounts):
--   - `is_insecure_skip_tls_verify=1` on a cluster row =
--     CWE-295 (Improper Cert Validation). An attacker on-path
--     can intercept every API call AND the credentials
--     transiting them.
--   - `has_inline_token=1` on a user row = a long-lived bearer
--     token embedded directly in the kubeconfig. Anyone who
--     reads the file gets cluster access. Stop alerting the
--     audit pipeline; promote to incident.
--   - `has_exec_plugin=1` on a user row = the credential is
--     brokered by an external `command` (e.g. `aws eks
--     get-token`, `gcloud config config-helper`). Legitimate
--     when the path is a known cloud CLI; suspicious when it
--     points at a vendor-unknown binary.
--   - `is_world_readable=1` / `is_group_readable=1` on the file
--     row = CWE-732. Tokens leak to every local user.

CREATE TABLE IF NOT EXISTS host_kubeconfig (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    file_mode                       INTEGER NOT NULL DEFAULT 0,
    file_owner_uid                  INTEGER NOT NULL DEFAULT 0,
    user_profile                    TEXT,
    entry_kind                      TEXT NOT NULL
                                    CHECK (entry_kind IN (
                                        'cluster', 'user', 'context'
                                    )),
    entry_name                      TEXT NOT NULL,
    -- cluster-specific fields
    server                          TEXT,                 -- URL when entry_kind=cluster
    has_certificate_authority       INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_certificate_authority IN (0, 1)),
    is_insecure_skip_tls_verify     INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_insecure_skip_tls_verify IN (0, 1)),
    is_loopback_server              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_loopback_server IN (0, 1)),
    -- user-specific fields
    auth_kind                       TEXT,                 -- "token" / "cert" / "exec" / "auth-provider" / "basic" / "none"
    exec_command                    TEXT,
    auth_provider_name              TEXT,
    has_inline_token                INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_inline_token IN (0, 1)),
    has_inline_certificate          INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_inline_certificate IN (0, 1)),
    has_exec_plugin                 INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_exec_plugin IN (0, 1)),
    has_basic_auth                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (has_basic_auth IN (0, 1)),
    -- context-specific fields
    context_cluster                 TEXT,
    context_user                    TEXT,
    context_namespace               TEXT,
    is_current_context              INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_current_context IN (0, 1)),
    -- file-level rollups (replicated on every row for query convenience)
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_kubeconfig_unique
    ON host_kubeconfig(asset_id, file_path, entry_kind, entry_name);

CREATE INDEX IF NOT EXISTS idx_host_kubeconfig_unsynced
    ON host_kubeconfig(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: inline tokens are immediate-incident material.
CREATE INDEX IF NOT EXISTS idx_host_kubeconfig_inline_token
    ON host_kubeconfig(asset_id, file_path, entry_name)
    WHERE has_inline_token = 1;

-- Fast path: TLS validation disabled.
CREATE INDEX IF NOT EXISTS idx_host_kubeconfig_insecure_tls
    ON host_kubeconfig(asset_id, file_path, entry_name)
    WHERE is_insecure_skip_tls_verify = 1;

-- Fast path: world/group-readable kubeconfigs (token leak vector).
CREATE INDEX IF NOT EXISTS idx_host_kubeconfig_world_readable
    ON host_kubeconfig(asset_id, file_path)
    WHERE is_world_readable = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_kubeconfig_drift
    ON host_kubeconfig(asset_id, file_path, file_hash);
