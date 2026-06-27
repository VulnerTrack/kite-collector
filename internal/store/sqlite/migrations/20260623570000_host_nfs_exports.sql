-- 20260623570000_host_nfs_exports.sql: durable storage for per-host
-- NFS export inventory introduced by CDMS iter 50.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_nfs_exports — one row per (asset_id, file_path, line_no,
--                      client). An exports(5) line can grant access
--                      to multiple clients with different option
--                      sets; each tuple gets its own row so the
--                      audit pipeline can join on client without
--                      string-splitting at query time.
--
-- Audit value:
--   - CWE-732 (Incorrect Permission Assignment) — `is_no_root_squash=1`
--     lets remote root processes write files as local root. Combined
--     with `is_read_write=1` this is the textbook NFS-share container-
--     escape primitive.
--   - MITRE T1135 (Network Share Discovery, defender side) — every
--     row is a candidate share for SOC inventory; `is_world_exposed=1`
--     surfaces shares reachable from any client.
--   - CWE-285 (Improper Authorization) — `is_insecure=1` flags
--     `insecure` option (allow client to connect from non-privileged
--     source ports), defeating the historical authentication assumption
--     that "real" NFS clients use ports < 1024.
--   - CWE-1188 — `is_async=1` is a data-integrity hazard (writes can
--     be acknowledged before disk commit); not strictly a security
--     issue but the audit pipeline surfaces it as a reliability check.
--   - Drift events — file_hash change on any /etc/exports* file =
--     network share topology was modified.

CREATE TABLE IF NOT EXISTS host_nfs_exports (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    file_path                TEXT NOT NULL,
    file_hash                TEXT NOT NULL,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    export_path              TEXT NOT NULL,
    client                   TEXT NOT NULL,         -- "*" / "10.0.0.0/24" / "*.corp.local"
    options                  TEXT,                  -- raw comma-separated
    options_json             TEXT NOT NULL DEFAULT '[]',
    is_read_write            INTEGER NOT NULL DEFAULT 0
                             CHECK (is_read_write IN (0, 1)),
    is_no_root_squash        INTEGER NOT NULL DEFAULT 0
                             CHECK (is_no_root_squash IN (0, 1)),
    is_all_squash            INTEGER NOT NULL DEFAULT 0
                             CHECK (is_all_squash IN (0, 1)),
    is_async                 INTEGER NOT NULL DEFAULT 0
                             CHECK (is_async IN (0, 1)),
    is_insecure              INTEGER NOT NULL DEFAULT 0
                             CHECK (is_insecure IN (0, 1)),
    is_world_exposed         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_world_exposed IN (0, 1)),
    is_subtree_check         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_subtree_check IN (0, 1)),
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_nfs_exports_unique
    ON host_nfs_exports(asset_id, file_path, line_no, client);

CREATE INDEX IF NOT EXISTS idx_host_nfs_exports_unsynced
    ON host_nfs_exports(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me shares granting remote-root write access" —
-- the CWE-732 alert query.
CREATE INDEX IF NOT EXISTS idx_host_nfs_exports_root_write
    ON host_nfs_exports(asset_id, export_path, client)
    WHERE is_no_root_squash = 1 AND is_read_write = 1;

-- Fast path: "show me world-exposed shares".
CREATE INDEX IF NOT EXISTS idx_host_nfs_exports_world
    ON host_nfs_exports(asset_id, export_path)
    WHERE is_world_exposed = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_nfs_exports_file_hash
    ON host_nfs_exports(asset_id, file_path, file_hash);
