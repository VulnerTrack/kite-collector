-- 20260623400000_host_kerberos_config.sql: durable storage for per-host
-- Kerberos client configuration introduced by CDMS iter 29.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_kerberos_config — one row per (asset_id, file_path, line_no).
--                          The collector parses /etc/krb5.conf plus
--                          every drop-in under /etc/krb5.conf.d/.
--                          macOS uses the same file; Windows uses
--                          AD-native APIs (future iteration).
--
-- Audit value:
--   - MITRE T1558 (Steal or Forge Kerberos Tickets) — realm name +
--     KDC IPs are reconnaissance prerequisites. The audit pipeline
--     joins this table against host_listeners to detect "host knows
--     about a realm whose KDC isn't reachable" patterns (split-brain
--     domain join, lateral movement preparation).
--   - CWE-327 (Use of Broken Crypto) — `is_weak_crypto=1` flags
--     `allow_weak_crypto=true`, the legacy switch that re-enables
--     des-cbc-* ticket encryption (known-plaintext attacks).
--   - CWE-521 (Weak Auth) — `is_long_ticket_lifetime=1` flags
--     ticket_lifetime > 24h. Long-lived tickets remain valid after
--     a credential rotation, defeating the rotation control.
--   - T1568.002 (DNS-based attacks) — `dns_lookup_realm=true` lets
--     an attacker who controls DNS direct the host to a spoofed KDC.
--   - Drift events — file_hash change on /etc/krb5.conf or any
--     drop-in = the realm trust topology was modified.

CREATE TABLE IF NOT EXISTS host_kerberos_config (
    id                       TEXT PRIMARY KEY NOT NULL,
    asset_id                 TEXT NOT NULL,
    section                  TEXT NOT NULL
                             CHECK (section IN (
                                 'libdefaults', 'realms', 'domain_realm',
                                 'appdefaults', 'capaths', 'plugins',
                                 'logging', 'login', 'unknown'
                             )),
    realm                    TEXT,            -- "EXAMPLE.COM" when in [realms]/EXAMPLE.COM/ subsection
    key                      TEXT NOT NULL,
    value                    TEXT NOT NULL DEFAULT '',
    is_default_realm         INTEGER NOT NULL DEFAULT 0
                             CHECK (is_default_realm IN (0, 1)),
    is_weak_crypto           INTEGER NOT NULL DEFAULT 0
                             CHECK (is_weak_crypto IN (0, 1)),
    is_long_ticket_lifetime  INTEGER NOT NULL DEFAULT 0
                             CHECK (is_long_ticket_lifetime IN (0, 1)),
    is_dns_lookup_enabled    INTEGER NOT NULL DEFAULT 0
                             CHECK (is_dns_lookup_enabled IN (0, 1)),
    is_kdc_or_admin          INTEGER NOT NULL DEFAULT 0
                             CHECK (is_kdc_or_admin IN (0, 1)),
    file_path                TEXT,
    file_hash                TEXT,
    line_no                  INTEGER NOT NULL DEFAULT 0,
    raw_line                 TEXT,
    last_seen_at             TEXT NOT NULL,
    collected_at             TEXT NOT NULL,
    synced_at                INTEGER,
    created_at               INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_kerberos_config_unique
    ON host_kerberos_config(asset_id, file_path, line_no);

CREATE INDEX IF NOT EXISTS idx_host_kerberos_config_unsynced
    ON host_kerberos_config(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me KDCs + admin_server entries per realm".
CREATE INDEX IF NOT EXISTS idx_host_kerberos_config_kdcs
    ON host_kerberos_config(asset_id, realm, value)
    WHERE is_kdc_or_admin = 1;

-- Fast path: "show me hosts with weak crypto enabled".
CREATE INDEX IF NOT EXISTS idx_host_kerberos_config_weak
    ON host_kerberos_config(asset_id, realm)
    WHERE is_weak_crypto = 1;

-- Fast path: "show me hosts with excessive ticket lifetimes".
CREATE INDEX IF NOT EXISTS idx_host_kerberos_config_lifetime
    ON host_kerberos_config(asset_id, realm)
    WHERE is_long_ticket_lifetime = 1;

-- Drift detection on per-file content.
CREATE INDEX IF NOT EXISTS idx_host_kerberos_config_file_hash
    ON host_kerberos_config(asset_id, file_path, file_hash);
