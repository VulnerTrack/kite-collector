-- 20260623320000_host_dns_resolvers.sql: durable storage for per-host
-- DNS resolver configuration introduced by CDMS iter 21.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_dns_resolvers — one row per (asset_id, source, server, port).
--                        Linux fills it from /etc/resolv.conf,
--                        /etc/systemd/resolved.conf, NetworkManager
--                        keyfiles, and /etc/dnsmasq.conf. macOS will
--                        cover scutil --dns; Windows will cover
--                        Get-DnsClientServerAddress. Drift between
--                        scans surfaces via the file_hash column.
--
-- Audit value:
--   - T1568.002 (Dynamic Resolution: DGA → broader DNS-hijack chain) —
--     a non-corporate resolver (`is_public_resolver=1`) on a host that
--     should be using internal DNS is the prime hijack signal.
--   - T1071.004 (Application Layer Protocol: DNS) — DoH/DoT (`protocol`
--     IN ('doh','dot')) defeats network-layer DNS inspection, which is
--     a feature for users but a problem for SOC teams.
--   - CWE-300 (Channel Accessible by Non-Endpoint) — `protocol='udp'`
--     resolvers with no DNSSEC validation (`is_dnssec=0`) are MitM-able
--     by any router on the path.
--   - Drift events — file_hash change on /etc/resolv.conf or any
--     NetworkManager keyfile = a DNS-routing modification event.

CREATE TABLE IF NOT EXISTS host_dns_resolvers (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'resolv-conf',
                            'systemd-resolved',
                            'network-manager',
                            'dnsmasq',
                            'unbound',
                            'macos-scutil',
                            'windows-dnsclient',
                            'unknown'
                        )),
    scope               TEXT NOT NULL
                        CHECK (scope IN (
                            'system', 'interface', 'process',
                            'per-domain', 'unknown'
                        )),
    interface_name      TEXT,                       -- "eth0", "wlan0", "tun0", NULL for system-wide
    server              TEXT NOT NULL,
    port                INTEGER NOT NULL DEFAULT 53,
    protocol            TEXT NOT NULL
                        CHECK (protocol IN (
                            'udp', 'tcp', 'tls', 'https',
                            'quic', 'unknown'
                        )),
    routed_domain       TEXT,                       -- "~corp.local", "~internal.example.com", NULL = global
    search_domains_json TEXT NOT NULL DEFAULT '[]',
    priority            INTEGER NOT NULL DEFAULT 0,
    is_dnssec           INTEGER NOT NULL DEFAULT 0
                        CHECK (is_dnssec IN (0, 1)),
    is_public_resolver  INTEGER NOT NULL DEFAULT 0
                        CHECK (is_public_resolver IN (0, 1)),
    is_loopback         INTEGER NOT NULL DEFAULT 0
                        CHECK (is_loopback IN (0, 1)),
    is_doh_or_dot       INTEGER NOT NULL DEFAULT 0
                        CHECK (is_doh_or_dot IN (0, 1)),
    file_path           TEXT,
    file_hash           TEXT,
    line_no             INTEGER NOT NULL DEFAULT 0,
    raw_line            TEXT,
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_dns_resolvers_unique
    ON host_dns_resolvers(asset_id, source, server, port, interface_name);

CREATE INDEX IF NOT EXISTS idx_host_dns_resolvers_unsynced
    ON host_dns_resolvers(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me public DNS resolvers configured on hosts that
-- should be using corp DNS" (T1568.002 hijack candidates).
CREATE INDEX IF NOT EXISTS idx_host_dns_resolvers_public
    ON host_dns_resolvers(asset_id, server)
    WHERE is_public_resolver = 1;

-- Fast path: "show me DoH/DoT resolvers" (SOC blindness).
CREATE INDEX IF NOT EXISTS idx_host_dns_resolvers_doh
    ON host_dns_resolvers(asset_id, server)
    WHERE is_doh_or_dot = 1;

-- Drift detection on /etc/resolv.conf + NM keyfiles.
CREATE INDEX IF NOT EXISTS idx_host_dns_resolvers_file_hash
    ON host_dns_resolvers(asset_id, file_path, file_hash);
