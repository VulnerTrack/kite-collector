-- 20260623720000_host_hosts_entries.sql: durable storage for per-host
-- hosts-file entry inventory introduced by CDMS iter 65.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_hosts_entries — one row per non-comment, non-blank line in
--                        the platform-canonical hosts file:
--                          Windows: C:\Windows\System32\drivers\etc\hosts
--                          Linux:   /etc/hosts
--                          macOS:   /etc/hosts
--                        The file format is identical across all
--                        three: `<ip> <hostname> [<aliases>...]` per
--                        line, with `#` comments. We split each line
--                        into a row per hostname so the audit
--                        pipeline can join by hostname directly.
--
-- Audit value (MITRE T1565.001 — Stored Data Manipulation, plus
-- T1583 — Acquire Infrastructure adjacent):
--   - `is_dns_poisoning_candidate=1` — a non-loopback IP listed for
--     a hostname that doesn't end in one of the well-known local
--     suffixes. This is the canonical "redirect bank.example.com to
--     a phishing host" shape; legitimate uses (split-horizon DNS,
--     test fixtures) get cleared by the audit pipeline's allowlist.
--   - `is_blocklist_entry=1` — 0.0.0.0 or 127.0.0.1 binding for a
--     hostname; usually legit (ad/telemetry blockers, host-allowlist
--     enforcement) but worth counting for compliance.
--   - `is_wildcard_subdomain=1` — hostname begins with `*.` — an
--     unusual configuration that hosts(5) doesn't strictly support;
--     more common in PAC files but occasionally seen in homegrown
--     hosts patches and worth flagging.
--   - Drift events — file_hash change on the file = the DNS
--     override surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_hosts_entries (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    file_path                   TEXT NOT NULL,
    file_hash                   TEXT NOT NULL,
    line_no                     INTEGER NOT NULL DEFAULT 0,
    raw_line                    TEXT,
    ip_address                  TEXT NOT NULL,
    hostname                    TEXT NOT NULL,
    is_alias                    INTEGER NOT NULL DEFAULT 0
                                CHECK (is_alias IN (0, 1)),
    comment                     TEXT,
    ip_kind                     TEXT NOT NULL
                                CHECK (ip_kind IN (
                                    'loopback', 'rfc1918', 'public',
                                    'sinkhole', 'invalid'
                                )),
    is_loopback_target          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_loopback_target IN (0, 1)),
    is_blocklist_entry          INTEGER NOT NULL DEFAULT 0
                                CHECK (is_blocklist_entry IN (0, 1)),
    is_wildcard_subdomain       INTEGER NOT NULL DEFAULT 0
                                CHECK (is_wildcard_subdomain IN (0, 1)),
    is_system_managed_default   INTEGER NOT NULL DEFAULT 0
                                CHECK (is_system_managed_default IN (0, 1)),
    is_dns_poisoning_candidate  INTEGER NOT NULL DEFAULT 0
                                CHECK (is_dns_poisoning_candidate IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_hosts_entries_unique
    ON host_hosts_entries(asset_id, file_path, line_no, hostname);

CREATE INDEX IF NOT EXISTS idx_host_hosts_entries_unsynced
    ON host_hosts_entries(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me DNS-poisoning candidates" (T1565.001 headline).
CREATE INDEX IF NOT EXISTS idx_host_hosts_entries_poison
    ON host_hosts_entries(asset_id, hostname)
    WHERE is_dns_poisoning_candidate = 1;

-- Fast path: blocklist entries (telemetry / ad block).
CREATE INDEX IF NOT EXISTS idx_host_hosts_entries_block
    ON host_hosts_entries(asset_id, hostname)
    WHERE is_blocklist_entry = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_hosts_entries_file_hash
    ON host_hosts_entries(asset_id, file_path, file_hash);
