-- 20260623190000_host_firewall_rules.sql: durable storage for per-host
-- firewall rule inventory introduced by CDMS iter 8.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_firewall_rules — one row per (asset_id, engine, rule_hash).
--                         rule_hash deduplicates re-discovery of the
--                         same logical rule across multiple scans and
--                         lets the DBOS bridge detect drift cheaply.
--
-- Audit value:
--   - CWE-732 (Incorrect Permission Assignment) — permissive rules like
--     `0.0.0.0/0 ACCEPT to dst_port=22` are findings.
--   - Pairs with host_listeners: a 'tcp 0.0.0.0:5432' listener + an
--     ACCEPT rule for src_cidr=0.0.0.0/0 → CWE-284 (Improper Access
--     Control), reported as a single finding rather than two.
--   - Drift detection: any rule_hash change → security-policy change
--     event in the audit log.

CREATE TABLE IF NOT EXISTS host_firewall_rules (
    id            TEXT PRIMARY KEY NOT NULL,
    asset_id      TEXT NOT NULL,
    engine        TEXT NOT NULL
                  CHECK (engine IN (
                      'iptables', 'nftables', 'pf',
                      'windows-firewall', 'ufw', 'firewalld',
                      'unknown'
                  )),
    chain         TEXT,
    direction     TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (direction IN ('in', 'out', 'forward', 'unknown')),
    action        TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (action IN (
                      'accept', 'drop', 'reject',
                      'log', 'jump', 'return', 'unknown'
                  )),
    proto         TEXT,            -- "tcp" | "udp" | "icmp" | "all" | ""
    src_cidr      TEXT,
    src_port      TEXT,            -- range as "1024-65535" or single
    dst_cidr      TEXT,
    dst_port      TEXT,
    iface_in      TEXT,
    iface_out     TEXT,
    extras        TEXT,            -- free-form trailing tokens (e.g. "-m state --state NEW")
    rule_hash     TEXT NOT NULL,   -- sha256 of the canonical rule string
    priority      INTEGER,         -- order within chain (lower = earlier)
    last_seen_at  TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    synced_at     INTEGER,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_firewall_rules_unique
    ON host_firewall_rules(asset_id, engine, rule_hash);

CREATE INDEX IF NOT EXISTS idx_host_firewall_rules_unsynced
    ON host_firewall_rules(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-732 finding: "show me permissive ACCEPT rules".
CREATE INDEX IF NOT EXISTS idx_host_firewall_rules_permissive
    ON host_firewall_rules(asset_id, action, src_cidr)
    WHERE action = 'accept' AND (src_cidr = '0.0.0.0/0' OR src_cidr = '::/0' OR src_cidr IS NULL);

-- For listener-correlation joins.
CREATE INDEX IF NOT EXISTS idx_host_firewall_rules_dst_port
    ON host_firewall_rules(asset_id, dst_port)
    WHERE dst_port IS NOT NULL;
