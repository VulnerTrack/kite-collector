-- 20260623280000_host_sudoers.sql: durable storage for per-host sudoers
-- rule inventory introduced by CDMS iter 17.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_sudoers — one row per (asset_id, file_path, line_no). Each
--                  scan re-parses every file; the unique key is the
--                  triple so drift between scans (added/removed lines)
--                  surfaces cleanly to the DBOS bridge.
--
-- Audit value (MITRE T1548.003 — Abuse Elevation Control Mechanism:
-- Sudo and Sudo Caching):
--   - `is_passwordless=1` rows are persistence + privilege-escalation
--     primitives. Combined with `is_total_privilege=1` (ALL=(ALL) ALL
--     style), it's full root with no auth — the single highest-signal
--     Linux finding from this collector.
--   - `defaults_key='timestamp_timeout'` with a value > 30 indicates
--     a wider ticket-reuse window (T1548.003 caching window).
--   - `defaults_key='env_keep'` rows reveal which env vars sudo
--     preserves across the privilege boundary (CWE-526 — Exposure of
--     Sensitive Information Through Environmental Variables).
--   - `entry_type='include'` rows reveal additional sudoers fragment
--     sources (potential persistence injection point if directory is
--     world-writable).

CREATE TABLE IF NOT EXISTS host_sudoers (
    id                    TEXT PRIMARY KEY NOT NULL,
    asset_id              TEXT NOT NULL,
    file_path             TEXT NOT NULL,
    file_hash             TEXT NOT NULL,           -- sha256 of the file (drift detection)
    line_no               INTEGER NOT NULL,
    entry_type            TEXT NOT NULL
                          CHECK (entry_type IN (
                              'user-spec', 'defaults',
                              'user-alias', 'runas-alias',
                              'host-alias', 'cmnd-alias',
                              'include', 'unknown'
                          )),
    principal             TEXT,                     -- user / %group / alias name on user-spec
    runas_user            TEXT,                     -- the (user) part — "ALL", "root", etc.
    runas_group           TEXT,                     -- after `:` in (user:group)
    hosts                 TEXT,                     -- machine list — typically "ALL"
    commands_json         TEXT NOT NULL DEFAULT '[]',  -- JSON array — granted command paths
    tags_json             TEXT NOT NULL DEFAULT '[]',  -- NOPASSWD / SETENV / NOEXEC / LOG_INPUT / etc.
    is_passwordless       INTEGER NOT NULL DEFAULT 0
                          CHECK (is_passwordless IN (0, 1)),
    is_total_privilege    INTEGER NOT NULL DEFAULT 0  -- ALL=(ALL:ALL) ALL pattern
                          CHECK (is_total_privilege IN (0, 1)),
    is_dangerous_default  INTEGER NOT NULL DEFAULT 0  -- e.g. !requiretty / env_keep widening
                          CHECK (is_dangerous_default IN (0, 1)),
    defaults_key          TEXT,                     -- for entry_type='defaults'
    defaults_value        TEXT,
    alias_name            TEXT,                     -- for entry_type='*-alias'
    alias_members_json    TEXT NOT NULL DEFAULT '[]',  -- members of an alias
    includes_path         TEXT,                     -- for entry_type='include' (path or directory)
    raw_line              TEXT,                     -- normalised line text (whitespace-collapsed)
    last_seen_at          TEXT NOT NULL,
    collected_at          TEXT NOT NULL,
    synced_at             INTEGER,
    created_at            INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_sudoers_unique
    ON host_sudoers(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_sudoers_unsynced
    ON host_sudoers(synced_at)
    WHERE synced_at IS NULL;

-- For T1548.003 fast path: "show me NOPASSWD grants".
CREATE INDEX IF NOT EXISTS idx_host_sudoers_nopasswd
    ON host_sudoers(asset_id, principal)
    WHERE is_passwordless = 1;

-- For the worst-case finding: total privilege without password.
CREATE INDEX IF NOT EXISTS idx_host_sudoers_unrestricted
    ON host_sudoers(asset_id, principal)
    WHERE is_passwordless = 1 AND is_total_privilege = 1;

-- For drift-detection joins on per-file hash.
CREATE INDEX IF NOT EXISTS idx_host_sudoers_file_hash
    ON host_sudoers(asset_id, file_path, file_hash);
