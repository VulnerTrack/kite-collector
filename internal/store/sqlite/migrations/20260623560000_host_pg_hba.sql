-- 20260623560000_host_pg_hba.sql: durable storage for per-host
-- PostgreSQL pg_hba.conf inventory introduced by CDMS iter 49.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_pg_hba — one row per non-comment line in every
--                 pg_hba.conf the collector finds. The walker
--                 covers the conventional locations:
--                   /etc/postgresql/<ver>/main/pg_hba.conf  (Debian/Ubuntu)
--                   /var/lib/pgsql/data/pg_hba.conf         (RHEL/Fedora default)
--                   /var/lib/pgsql/<ver>/data/pg_hba.conf   (RHEL versioned)
--                   /var/lib/postgresql/<ver>/main/pg_hba.conf (Debian alt)
--                   /usr/local/var/postgres/pg_hba.conf     (macOS Homebrew)
--
-- Audit value (MITRE T1078 — Valid Accounts, defender side):
--   - CWE-306 (Missing Authentication) — `is_trust=1` rows allow
--     connections with no auth at all. Combined with `is_internet_exposed=1`
--     this is a "publicly-reachable Postgres with no password" finding.
--   - CWE-326 (Inadequate Encryption Strength) — `is_weak_method=1`
--     flags `md5` / `password` / `ident` / `peer`. SCRAM-SHA-256 is
--     the modern baseline.
--   - CWE-285 (Improper Authorization) — `is_internet_exposed=1`
--     plus `database='all'` + `user='all'` = the database is open
--     to anyone on the internet.
--   - Replication entries (`database='replication'`) need their own
--     audit lane — they grant streaming-replication rights which an
--     attacker can use to clone the primary off-host.
--   - Drift events — file_hash change on any pg_hba.conf is a
--     T1098 (Account Manipulation) candidate; the audit pipeline
--     always alerts on this.

CREATE TABLE IF NOT EXISTS host_pg_hba (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    file_hash           TEXT NOT NULL,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    connection_type     TEXT NOT NULL
                        CHECK (connection_type IN (
                            'local', 'host', 'hostssl', 'hostnossl',
                            'hostgssenc', 'hostnogssenc', 'unknown'
                        )),
    database            TEXT,                  -- "all" / "replication" / csv list
    db_role             TEXT,                  -- column is `user` in pg_hba; CSV list / "all"
    address             TEXT,                  -- CIDR / hostname / NULL for local
    method              TEXT NOT NULL
                        CHECK (method IN (
                            'trust', 'reject', 'md5', 'scram-sha-256',
                            'password', 'gss', 'sspi', 'ident', 'peer',
                            'ldap', 'radius', 'cert', 'pam', 'bsd',
                            'unknown'
                        )),
    options             TEXT,                  -- raw remainder
    is_trust            INTEGER NOT NULL DEFAULT 0
                        CHECK (is_trust IN (0, 1)),
    is_reject           INTEGER NOT NULL DEFAULT 0
                        CHECK (is_reject IN (0, 1)),
    is_weak_method      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_weak_method IN (0, 1)),
    is_internet_exposed INTEGER NOT NULL DEFAULT 0
                        CHECK (is_internet_exposed IN (0, 1)),
    is_replication      INTEGER NOT NULL DEFAULT 0
                        CHECK (is_replication IN (0, 1)),
    is_wide_open        INTEGER NOT NULL DEFAULT 0
                        CHECK (is_wide_open IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_pg_hba_unique
    ON host_pg_hba(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_pg_hba_unsynced
    ON host_pg_hba(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me Postgres rows that accept unauthenticated
-- connections" (CWE-306).
CREATE INDEX IF NOT EXISTS idx_host_pg_hba_trust
    ON host_pg_hba(asset_id, file_path)
    WHERE is_trust = 1;

-- Fast path: "show me publicly-reachable databases with weak or no
-- authentication" (the alert query).
CREATE INDEX IF NOT EXISTS idx_host_pg_hba_internet_weak
    ON host_pg_hba(asset_id, address)
    WHERE is_internet_exposed = 1 AND (is_trust = 1 OR is_weak_method = 1);

-- Fast path: "show me replication grants".
CREATE INDEX IF NOT EXISTS idx_host_pg_hba_replication
    ON host_pg_hba(asset_id, db_role, address)
    WHERE is_replication = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_pg_hba_file_hash
    ON host_pg_hba(asset_id, file_path, file_hash);
