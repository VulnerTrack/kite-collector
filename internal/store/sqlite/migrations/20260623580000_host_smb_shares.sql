-- 20260623580000_host_smb_shares.sql: durable storage for per-host
-- Samba share inventory introduced by CDMS iter 51.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_smb_shares — one row per share section in smb.conf and
--                     every drop-in under /etc/samba/smb.conf.d/.
--                     [global], [printers], [print$], [homes] are
--                     parsed too (they carry security-relevant
--                     defaults), each with section_kind set so the
--                     audit pipeline can filter to "real" shares.
--
-- Audit value (MITRE T1135 — Network Share Discovery, defender side):
--   - CWE-732 (Incorrect Permission Assignment) — `is_guest_writable=1`
--     allows anonymous SMB clients to write files into the share.
--     Headline alert on any internet-reachable host.
--   - CWE-285 (Improper Authorization) — `is_world_exposed=1` flags
--     shares without a `hosts allow` restriction. Combined with
--     `is_guest_writable=1` = "anyone can drop files here".
--   - CWE-269 (Improper Privilege Management) — `is_force_user_root=1`
--     means every file Samba writes lands as local root regardless of
--     the SMB client's identity.
--   - CWE-732 (file mode) — `create_mask` / `directory_mask` looser
--     than 0750 surface as `is_wide_create_mask=1`.
--   - Drift events — file_hash change on smb.conf = the share
--     surface was modified. Always worth alerting.

CREATE TABLE IF NOT EXISTS host_smb_shares (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    file_path                TEXT NOT NULL,
    file_hash                TEXT NOT NULL,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    section_name             TEXT NOT NULL,         -- "global","share-name","homes","printers"
    section_kind             TEXT NOT NULL
                             CHECK (section_kind IN (
                                 'global', 'share', 'homes', 'printers',
                                 'print$', 'unknown'
                             )),
    path                     TEXT,
    comment                  TEXT,
    valid_users              TEXT,                  -- raw semicolon-separated
    invalid_users            TEXT,
    admin_users              TEXT,
    read_list                TEXT,
    write_list               TEXT,
    hosts_allow              TEXT,
    hosts_deny               TEXT,
    create_mask              TEXT,                  -- "0664" / "0666"
    directory_mask           TEXT,
    force_user               TEXT,
    force_group              TEXT,
    is_browseable            INTEGER NOT NULL DEFAULT 0
                             CHECK (is_browseable IN (0, 1)),
    is_guest_ok              INTEGER NOT NULL DEFAULT 0
                             CHECK (is_guest_ok IN (0, 1)),
    is_writable              INTEGER NOT NULL DEFAULT 0
                             CHECK (is_writable IN (0, 1)),
    is_read_only             INTEGER NOT NULL DEFAULT 0
                             CHECK (is_read_only IN (0, 1)),
    is_public                INTEGER NOT NULL DEFAULT 0
                             CHECK (is_public IN (0, 1)),
    is_guest_writable        INTEGER NOT NULL DEFAULT 0
                             CHECK (is_guest_writable IN (0, 1)),
    is_world_exposed         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_world_exposed IN (0, 1)),
    is_wide_create_mask      INTEGER NOT NULL DEFAULT 0
                             CHECK (is_wide_create_mask IN (0, 1)),
    is_force_user_root       INTEGER NOT NULL DEFAULT 0
                             CHECK (is_force_user_root IN (0, 1)),
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_smb_shares_unique
    ON host_smb_shares(asset_id, file_path, section_name);

CREATE INDEX IF NOT EXISTS idx_host_smb_shares_unsynced
    ON host_smb_shares(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me guest-writable shares" (CWE-732 / T1135 alert).
CREATE INDEX IF NOT EXISTS idx_host_smb_shares_guest_write
    ON host_smb_shares(asset_id, section_name, path)
    WHERE is_guest_writable = 1;

-- Fast path: "show me world-exposed shares" (no hosts allow).
CREATE INDEX IF NOT EXISTS idx_host_smb_shares_world
    ON host_smb_shares(asset_id, section_name)
    WHERE is_world_exposed = 1 AND section_kind = 'share';

-- Fast path: force_user=root shares (CWE-269).
CREATE INDEX IF NOT EXISTS idx_host_smb_shares_force_root
    ON host_smb_shares(asset_id, section_name)
    WHERE is_force_user_root = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_smb_shares_file_hash
    ON host_smb_shares(asset_id, file_path, file_hash);
