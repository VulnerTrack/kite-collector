-- 20260623690000_host_rsyslog_forwarders.sql: durable storage for
-- per-host rsyslog forwarder inventory introduced by CDMS iter 62.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_rsyslog_forwarders — one row per remote-forward directive
--                             discovered across the rsyslog config
--                             chain: /etc/rsyslog.conf, every
--                             /etc/rsyslog.d/*.conf drop-in, plus
--                             the Homebrew counterparts on macOS.
--                             Each `*.* @host` legacy directive,
--                             `action(type="omfwd" ...)` block, or
--                             `action(type="omhttp" ...)` block
--                             becomes a row.
--
-- Audit value (MITRE T1048 — Exfiltration Over Alternative Protocol,
-- T1567 — Exfiltration Over Web Service, defender side, plus
-- T1562.008 — Disable Cloud Logs):
--   - CWE-319 (Cleartext Transmission of Sensitive Information) —
--     `is_plaintext_transport=1` flags every `@host` (UDP) and
--     `@@host` (TCP) without TLS — logs carry user PII, IPs, and
--     occasionally credentials, and they leave the host in plain.
--   - `is_destination_external=1` flags forwards to non-RFC1918
--     IPs and to non-loopback hostnames the audit pipeline can't
--     resolve to a known internal range. The first signal of a
--     T1048 exfil channel pretending to be a SIEM uplink.
--   - `is_http_egress=1` flags `omhttp` outputs entirely — those
--     ride HTTPS to an arbitrary URL and are wildly easier to
--     deploy as a T1567 cover than a fresh process.
--   - `selector_includes_everything=1` flags `*.*`-scoped rules; a
--     scoped forward like `auth.*` is normal, but `*.*` is the
--     attacker's preferred selector when wiring up exfiltration.
--   - Drift events — file_hash change on any rsyslog file = the
--     log-egress surface was modified; alert verbatim.

CREATE TABLE IF NOT EXISTS host_rsyslog_forwarders (
    id                              TEXT PRIMARY KEY NOT NULL,
    asset_id                        TEXT NOT NULL,
    file_path                       TEXT NOT NULL,
    file_hash                       TEXT NOT NULL,
    line_no                         INTEGER NOT NULL DEFAULT 0,
    raw_directive                   TEXT,
    directive_kind                  TEXT NOT NULL
                                    CHECK (directive_kind IN (
                                        'legacy-udp', 'legacy-tcp',
                                        'action-omfwd', 'action-omhttp',
                                        'unknown'
                                    )),
    selector                        TEXT,                  -- "*.*" / "auth.*" / "kern.warn"
    destination                     TEXT NOT NULL,         -- hostname or IP
    destination_port                INTEGER,
    transport_protocol              TEXT,                  -- "udp" / "tcp" / "https"
    tls_driver                      TEXT,                  -- "gtls" / "ossl" / "" (none)
    queue_type                      TEXT,                  -- "LinkedList" / "FixedArray" / ""
    is_plaintext_transport          INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_plaintext_transport IN (0, 1)),
    is_destination_external         INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_destination_external IN (0, 1)),
    is_http_egress                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_http_egress IN (0, 1)),
    selector_includes_everything    INTEGER NOT NULL DEFAULT 0
                                    CHECK (selector_includes_everything IN (0, 1)),
    is_tls_enabled                  INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_tls_enabled IN (0, 1)),
    is_suspicious_egress            INTEGER NOT NULL DEFAULT 0
                                    CHECK (is_suspicious_egress IN (0, 1)),
    last_seen_at                    TEXT NOT NULL,
    collected_at                    TEXT NOT NULL,
    synced_at                       INTEGER,
    created_at                      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_unique
    ON host_rsyslog_forwarders(asset_id, file_path, line_no, destination);

CREATE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_unsynced
    ON host_rsyslog_forwarders(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me suspicious egress channels — plaintext to
-- external, or HTTP to anywhere" (T1048 + T1567).
CREATE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_suspicious
    ON host_rsyslog_forwarders(asset_id, file_path, destination)
    WHERE is_suspicious_egress = 1;

-- Fast path: "show me cleartext log shipping" (CWE-319).
CREATE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_plaintext
    ON host_rsyslog_forwarders(asset_id, file_path, destination)
    WHERE is_plaintext_transport = 1;

-- Fast path: omhttp egress to arbitrary URLs (T1567 cover).
CREATE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_http
    ON host_rsyslog_forwarders(asset_id, file_path, destination)
    WHERE is_http_egress = 1;

-- Drift detection.
CREATE INDEX IF NOT EXISTS idx_host_rsyslog_forwarders_file_hash
    ON host_rsyslog_forwarders(asset_id, file_path, file_hash);
