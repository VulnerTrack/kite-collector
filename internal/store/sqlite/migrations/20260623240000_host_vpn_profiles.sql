-- 20260623240000_host_vpn_profiles.sql: durable storage for per-host VPN
-- profile inventory introduced by CDMS iter 13.
--
-- One additive table. No existing rows or columns are touched.
--
--   host_vpn_profiles — one row per (asset_id, vpn_type, config_path).
--                       config_path is the natural disambiguator because
--                       the same host can carry multiple WireGuard peer
--                       configs (per-environment), and OpenVPN clients
--                       often have parallel files for dev/prod.
--
-- Audit value (completes Listeners + FirewallRules with egress-tunnel
-- visibility — "who can this host route traffic to/from"):
--   - CWE-200 (Information Exposure) — `is_full_tunnel=1` means
--     0.0.0.0/0 (or ::/0) is in the routed-subnets list, redirecting
--     ALL host traffic through the VPN. Combined with `endpoint` this
--     reveals which third party sees corporate traffic.
--   - CWE-321 (Hard-coded Cryptographic Key) — `private_key_present=1`
--     AND `auto_connect=1` means the host can reach the VPN without
--     human interaction, so the credential lives at rest on disk
--     unprotected.
--   - Drift / abandonment — `last_handshake_at < now - 30d` flags
--     stale tunnels that should be removed (attack surface that
--     nobody is watching).
--   - Multi-client enumeration — `COUNT(DISTINCT vpn_type) > 2 per
--     host` signals VPN-sprawl.

CREATE TABLE IF NOT EXISTS host_vpn_profiles (
    id                    TEXT PRIMARY KEY NOT NULL,
    asset_id              TEXT NOT NULL,
    vpn_type              TEXT NOT NULL
                          CHECK (vpn_type IN (
                              'wireguard', 'openvpn',
                              'ipsec', 'strongswan', 'libreswan',
                              'tailscale', 'zerotier', 'nebula', 'netbird',
                              'windows-builtin', 'macos-builtin',
                              'cisco-anyconnect', 'fortinet', 'pulse',
                              'unknown'
                          )),
    name                  TEXT NOT NULL,         -- interface name (wg0) or profile name
    config_path           TEXT NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 0
                          CHECK (enabled IN (0, 1)),
    auto_connect          INTEGER NOT NULL DEFAULT 0
                          CHECK (auto_connect IN (0, 1)),
    endpoint              TEXT,                  -- server "host:port" or "ip:port"
    protocol              TEXT,                  -- "udp" | "tcp" | ""
    port                  INTEGER,
    routed_subnets_json   TEXT NOT NULL DEFAULT '[]',  -- AllowedIPs / routes pushed
    dns_servers_json      TEXT NOT NULL DEFAULT '[]',
    mtu                   INTEGER,
    is_full_tunnel        INTEGER NOT NULL DEFAULT 0
                          CHECK (is_full_tunnel IN (0, 1)),
    private_key_present   INTEGER NOT NULL DEFAULT 0
                          CHECK (private_key_present IN (0, 1)),
    preshared_key_present INTEGER NOT NULL DEFAULT 0
                          CHECK (preshared_key_present IN (0, 1)),
    last_handshake_at     TEXT,
    last_seen_at          TEXT NOT NULL,
    collected_at          TEXT NOT NULL,
    synced_at             INTEGER,
    created_at            INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_vpn_profiles_unique
    ON host_vpn_profiles(asset_id, vpn_type, config_path);

CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_unsynced
    ON host_vpn_profiles(synced_at)
    WHERE synced_at IS NULL;

-- For the CWE-200 finding: "show me full-tunnel VPNs".
CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_full_tunnel
    ON host_vpn_profiles(asset_id, vpn_type)
    WHERE is_full_tunnel = 1;

-- For the CWE-321 finding: hands-off VPN with key on disk.
CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_unattended_creds
    ON host_vpn_profiles(asset_id, vpn_type)
    WHERE auto_connect = 1 AND private_key_present = 1;

-- For abandonment detection — index handshake timestamp for range scans.
CREATE INDEX IF NOT EXISTS idx_host_vpn_profiles_handshake
    ON host_vpn_profiles(asset_id, last_handshake_at);
