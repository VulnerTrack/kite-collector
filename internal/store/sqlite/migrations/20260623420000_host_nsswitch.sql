-- 20260623420000_host_nsswitch.sql: durable storage for per-host
-- /etc/nsswitch.conf inventory introduced by CDMS iter 31.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_nsswitch — one row per (asset_id, file_path, line_no). The
--                   collector parses /etc/nsswitch.conf. macOS uses a
--                   different mechanism (DirectoryService / OpenDirectory
--                   plist files — future iteration); Windows resolves
--                   identities through Windows-native APIs and has no
--                   nsswitch equivalent.
--
-- Audit value:
--   - MITRE T1556 (Modify Authentication Process) — adding `sss` or
--     `ldap` to the `passwd:`, `group:`, or `shadow:` chain lets an
--     attacker who controls those directories inject users without
--     touching /etc/passwd. `is_security_critical=1` +
--     `has_non_local_source=1` flag the combination.
--   - MITRE T1078 (Valid Accounts) — `hosts: dns files` (DNS first)
--     exposes the host to DNS-cache poisoning before /etc/hosts is
--     consulted. The audit pipeline correlates against
--     host_dns_resolvers to see whether the resolver is trustworthy.
--   - CWE-693 (Protection Mechanism Failure) — `is_files_missing=1`
--     flags databases (most importantly `passwd`/`shadow`/`group`)
--     where `files` does not appear at all. That breaks emergency
--     recovery: a network-source failure leaves no local fallback.
--   - Drift events — file_hash change on /etc/nsswitch.conf = the
--     identity-resolution policy was modified. Always worth alerting.

CREATE TABLE IF NOT EXISTS host_nsswitch (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    database                 TEXT NOT NULL
                             CHECK (database IN (
                                 'passwd', 'shadow', 'group', 'hosts',
                                 'services', 'networks', 'protocols',
                                 'rpc', 'ethers', 'netmasks', 'bootparams',
                                 'netgroup', 'automount', 'aliases',
                                 'publickey', 'gshadow', 'sudoers',
                                 'initgroups', 'unknown'
                             )),
    source_chain             TEXT NOT NULL,         -- "files [SUCCESS=return] sss"
    sources_json             TEXT NOT NULL DEFAULT '[]',  -- ["files","sss"]
    is_security_critical     INTEGER NOT NULL DEFAULT 0
                             CHECK (is_security_critical IN (0, 1)),
    has_non_local_source     INTEGER NOT NULL DEFAULT 0
                             CHECK (has_non_local_source IN (0, 1)),
    is_files_missing         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_files_missing IN (0, 1)),
    is_files_last            INTEGER NOT NULL DEFAULT 0
                             CHECK (is_files_last IN (0, 1)),
    file_path                TEXT,
    file_hash                TEXT,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_nsswitch_unique
    ON host_nsswitch(asset_id, file_path, database);

CREATE INDEX IF NOT EXISTS idx_host_nsswitch_unsynced
    ON host_nsswitch(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me identity databases sourced from remote backends".
CREATE INDEX IF NOT EXISTS idx_host_nsswitch_remote_identity
    ON host_nsswitch(asset_id, database)
    WHERE is_security_critical = 1 AND has_non_local_source = 1;

-- Fast path: "show me hosts where critical databases lack a files fallback".
CREATE INDEX IF NOT EXISTS idx_host_nsswitch_no_files
    ON host_nsswitch(asset_id, database)
    WHERE is_files_missing = 1;

-- Fast path: "show me hosts where files is consulted last (network first)".
CREATE INDEX IF NOT EXISTS idx_host_nsswitch_files_last
    ON host_nsswitch(asset_id, database)
    WHERE is_files_last = 1;

-- Drift detection on /etc/nsswitch.conf.
CREATE INDEX IF NOT EXISTS idx_host_nsswitch_file_hash
    ON host_nsswitch(asset_id, file_path, file_hash);
