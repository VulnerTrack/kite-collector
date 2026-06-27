-- host_net_interfaces inventories physical and virtual network
-- interfaces on the host: Ethernet, Wi-Fi, cellular, loopback,
-- VLAN, bridge, bond, veth (container pair), TUN/TAP, dummy,
-- ip6tnl, sit, gretap, vxlan, geneve, wireguard, openvpn.
--
-- Linux source:   /sys/class/net/<iface>/{address,operstate,carrier,speed,duplex,...}
-- macOS source:   ioreg + ifconfig
-- Windows source: WMI Win32_NetworkAdapter / Get-NetAdapter
--
-- Read-only.

CREATE TABLE IF NOT EXISTS host_net_interfaces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    iface           TEXT    NOT NULL,
    iface_type      TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (iface_type IN (
            'unknown','ethernet','wifi','cellular','loopback',
            'vlan','bridge','bond','veth','tun','tap','dummy',
            'tunnel','sit','vxlan','geneve','wireguard','openvpn',
            'infiniband','can','ppp','tap-vpn','tap-virt','other'
        )),
    mac_address_hash TEXT   NOT NULL DEFAULT '',
    oui_hex         TEXT    NOT NULL DEFAULT '' CHECK (length(oui_hex) IN (0,6)),
    driver          TEXT    NOT NULL DEFAULT '',
    operstate       TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (operstate IN ('unknown','up','down','dormant','testing','lowerlayerdown','notpresent')),
    carrier         INTEGER NOT NULL DEFAULT 0 CHECK (carrier IN (0,1)),
    mtu             INTEGER NOT NULL DEFAULT 0,
    speed_mbps      INTEGER NOT NULL DEFAULT 0,
    duplex          TEXT    NOT NULL DEFAULT ''
        CHECK (duplex IN ('','half','full','unknown')),
    tx_queue_len    INTEGER NOT NULL DEFAULT 0,
    is_physical     INTEGER NOT NULL DEFAULT 0 CHECK (is_physical IN (0,1)),
    is_wireless     INTEGER NOT NULL DEFAULT 0 CHECK (is_wireless IN (0,1)),
    is_vpn          INTEGER NOT NULL DEFAULT 0 CHECK (is_vpn IN (0,1)),
    is_container    INTEGER NOT NULL DEFAULT 0 CHECK (is_container IN (0,1)),
    is_promiscuous  INTEGER NOT NULL DEFAULT 0 CHECK (is_promiscuous IN (0,1)),
    pci_bdf         TEXT    NOT NULL DEFAULT '',
    is_promiscuous_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_promiscuous_risk IN (0,1)),
    is_no_carrier_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_no_carrier_risk IN (0,1)),
    is_low_speed_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_low_speed_risk IN (0,1)),
    is_recent       INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    UNIQUE (iface)
);

CREATE INDEX IF NOT EXISTS idx_net_type   ON host_net_interfaces(iface_type);
CREATE INDEX IF NOT EXISTS idx_net_state  ON host_net_interfaces(operstate);
CREATE INDEX IF NOT EXISTS idx_net_oui    ON host_net_interfaces(oui_hex) WHERE oui_hex != '';
CREATE INDEX IF NOT EXISTS idx_net_pci    ON host_net_interfaces(pci_bdf) WHERE pci_bdf != '';
CREATE INDEX IF NOT EXISTS idx_net_promisc ON host_net_interfaces(iface) WHERE is_promiscuous = 1;
