-- 20260623490000_host_windows_network.sql: per-host Windows network
-- inventory introduced by CDMS iter 38.
--
-- Two related tables in one migration:
--
--   host_windows_network_adapters — one row per NIC, with
--       Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration
--       joined via Index. Multi-IP adapters appear once with their
--       address list stored in ip_addresses_json.
--
--   host_windows_ip4_routes — one row per IPv4 routing-table entry
--       from Win32_IP4RouteTable.
--
-- Audit value (MITRE T1016 — System Network Configuration Discovery,
-- defender side):
--   - `is_default_route=1 AND next_hop NOT IN <expected-gw-set>` flags
--     hosts whose default gateway is unfamiliar — a classic
--     split-tunnel / pivot-VPN indicator.
--   - `is_dhcp_enabled=1 AND dhcp_server` join against the corporate
--     DHCP server set spots hosts using a rogue DHCP server.
--   - Cross-reference adapter `dns_servers_json` against the
--     dnsresolver collector's `host_dns_resolvers` table:
--     adapter-level DNS overrides that bypass system resolv config
--     are a T1568.002 signal.
--   - Inactive adapter (`net_connection_status=0`) with a valid IP
--     suggests a stale configuration; admins frequently leave old
--     VLAN entries that an attacker can resurrect.

CREATE TABLE IF NOT EXISTS host_windows_network_adapters (
    id                          TEXT PRIMARY KEY NOT NULL,
    asset_id                    TEXT NOT NULL,
    source                      TEXT NOT NULL
                                CHECK (source IN (
                                    'powershell-cim', 'powershell-wmi', 'unknown'
                                )),
    -- Win32_NetworkAdapter
    interface_index             INTEGER NOT NULL DEFAULT 0,
    device_id                   TEXT NOT NULL,        -- WMI key e.g. "0"
    name                        TEXT,                  -- "Intel(R) Wireless-AX 211"
    description                 TEXT,
    net_connection_id           TEXT,                  -- "Wi-Fi" / "Ethernet"
    manufacturer                TEXT,
    adapter_type                TEXT,                  -- "Ethernet 802.3"
    mac_address                 TEXT,                  -- canonical lower-case AA:BB:...
    speed_bps                   INTEGER NOT NULL DEFAULT 0,
    net_enabled                 INTEGER NOT NULL DEFAULT 0
                                CHECK (net_enabled IN (0, 1)),
    net_connection_status       INTEGER NOT NULL DEFAULT 0,
    physical_adapter            INTEGER NOT NULL DEFAULT 0
                                CHECK (physical_adapter IN (0, 1)),
    guid                        TEXT,
    pnp_device_id               TEXT,
    -- Win32_NetworkAdapterConfiguration
    dhcp_enabled                INTEGER NOT NULL DEFAULT 0
                                CHECK (dhcp_enabled IN (0, 1)),
    dhcp_server                 TEXT,
    dhcp_lease_obtained         TEXT,                  -- RFC3339
    ip_addresses_json           TEXT NOT NULL DEFAULT '[]',
    ip_subnets_json             TEXT NOT NULL DEFAULT '[]',
    gateways_json               TEXT NOT NULL DEFAULT '[]',
    dns_servers_json            TEXT NOT NULL DEFAULT '[]',
    dns_domain                  TEXT,
    dns_suffix_search_order_json TEXT NOT NULL DEFAULT '[]',
    wins_servers_json           TEXT NOT NULL DEFAULT '[]',
    -- Derived
    has_default_gateway         INTEGER NOT NULL DEFAULT 0
                                CHECK (has_default_gateway IN (0, 1)),
    last_seen_at                TEXT NOT NULL,
    collected_at                TEXT NOT NULL,
    synced_at                   INTEGER,
    created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_network_adapters_unique
    ON host_windows_network_adapters(asset_id, interface_index);

CREATE INDEX IF NOT EXISTS idx_host_windows_network_adapters_unsynced
    ON host_windows_network_adapters(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me adapters using DHCP".
CREATE INDEX IF NOT EXISTS idx_host_windows_network_adapters_dhcp
    ON host_windows_network_adapters(asset_id, dhcp_server)
    WHERE dhcp_enabled = 1;

-- Fast path: "show me physical adapters with active link" (for asset
-- triage when a host reports many virtual adapters).
CREATE INDEX IF NOT EXISTS idx_host_windows_network_adapters_active
    ON host_windows_network_adapters(asset_id, mac_address)
    WHERE physical_adapter = 1 AND net_enabled = 1;

CREATE TABLE IF NOT EXISTS host_windows_ip4_routes (
    id                  TEXT PRIMARY KEY NOT NULL,
    asset_id            TEXT NOT NULL,
    source              TEXT NOT NULL
                        CHECK (source IN (
                            'powershell-cim', 'powershell-wmi', 'unknown'
                        )),
    destination         TEXT NOT NULL,
    mask                TEXT NOT NULL,
    next_hop            TEXT NOT NULL,
    interface_index     INTEGER NOT NULL DEFAULT 0,
    metric1             INTEGER NOT NULL DEFAULT 0,
    protocol            INTEGER NOT NULL DEFAULT 0,
    type                INTEGER NOT NULL DEFAULT 0,
    age_seconds         INTEGER NOT NULL DEFAULT 0,
    is_default_route    INTEGER NOT NULL DEFAULT 0
                        CHECK (is_default_route IN (0, 1)),
    last_seen_at        TEXT NOT NULL,
    collected_at        TEXT NOT NULL,
    synced_at           INTEGER,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_host_windows_ip4_routes_unique
    ON host_windows_ip4_routes(asset_id, destination, mask, next_hop, interface_index);

CREATE INDEX IF NOT EXISTS idx_host_windows_ip4_routes_unsynced
    ON host_windows_ip4_routes(synced_at)
    WHERE synced_at IS NULL;

-- Fast path: "show me default routes per host" (split-tunnel checks).
CREATE INDEX IF NOT EXISTS idx_host_windows_ip4_routes_default
    ON host_windows_ip4_routes(asset_id, next_hop)
    WHERE is_default_route = 1;
