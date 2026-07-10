// Package vpn enumerates installed VPN profiles across WireGuard,
// OpenVPN, IPSec/strongSwan, Tailscale, ZeroTier, Nebula, NetBird, and
// the OS-native VPN clients (Windows builtin, macOS Configuration
// Profiles). The collector closes the network-posture loop: Listeners
// describe inbound exposure, FirewallRules describe ingress filtering,
// VPN profiles describe **egress tunnelling** — who this host can route
// traffic to/from.
//
// Every collector is **read-only** — it parses config files and queries
// management daemons. It never edits any VPN config, brings a tunnel
// up/down, or rotates any key.
//
// Profile rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-200 (Information Exposure) — `is_full_tunnel=1` redirects
//     ALL host traffic through the VPN. Combined with `endpoint` this
//     reveals which third party sees the corporate traffic.
//   - CWE-321 (Hard-coded Cryptographic Key) — `private_key_present=1`
//     AND `auto_connect=1` means the unattended host has the
//     credential at rest on disk.
//   - Abandonment / drift — `last_handshake_at < now - 30d` flags
//     stale tunnels that nobody is watching.
package vpn

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// MaxProfiles bounds per-scan output. A typical host has 1-5 VPN
// profiles; a transit/jumpbox might have 30+. The 1024 ceiling protects
// the SQLite write path.
const MaxProfiles = 1024

// Type identifies the VPN technology. Strings pinned to the
// host_vpn_profiles.vpn_type CHECK enum.
type Type string

const (
	TypeWireGuard       Type = "wireguard"
	TypeOpenVPN         Type = "openvpn"
	TypeIPSec           Type = "ipsec"
	TypeStrongSwan      Type = "strongswan"
	TypeLibreSwan       Type = "libreswan"
	TypeTailscale       Type = "tailscale"
	TypeZeroTier        Type = "zerotier"
	TypeNebula          Type = "nebula"
	TypeNetBird         Type = "netbird"
	TypeWindowsBuiltin  Type = "windows-builtin"
	TypeMacOSBuiltin    Type = "macos-builtin"
	TypeCiscoAnyConnect Type = "cisco-anyconnect"
	TypeFortinet        Type = "fortinet"
	TypePulse           Type = "pulse"
	TypeGlobalProtect   Type = "globalprotect" // Palo Alto Networks
	TypeCheckPoint      Type = "checkpoint"    // Check Point Remote Secure Access
	TypeDirectAccess    Type = "directaccess"  // Microsoft DirectAccess
	TypeNordLayer       Type = "nordlayer"     // NordLayer (NordVPN Teams)
	TypeProtonVPN       Type = "protonvpn"     // Proton VPN / Proton VPN for Business
	TypeMullvad         Type = "mullvad"       // Mullvad VPN
	TypeUnknown         Type = "unknown"
)

// Profile is the cross-VPN record produced by every collector. Mirrors
// host_vpn_profiles' column shape.
//
// SharedPeers lists the DNS names of mesh peers that belong to a
// DIFFERENT identity than the one running this collector — i.e. nodes
// shared INTO this user's view from another tailnet user. Tailscale
// supports this via node sharing, and a non-empty list on an
// employee-owned device is a privilege-exposure smell: end-users
// rarely should hold cross-account routes into other people's hosts.
// Empty for non-mesh VPNs and for personal accounts where every peer
// is owned by the same user.
type Profile struct {
	LastHandshakeAt     string   `json:"last_handshake_at,omitempty"`
	Name                string   `json:"name"`
	ConfigPath          string   `json:"config_path"`
	Endpoint            string   `json:"endpoint,omitempty"`
	Protocol            string   `json:"protocol,omitempty"`
	Type                Type     `json:"type"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	RoutedSubnets       []string `json:"routed_subnets,omitempty"`
	SharedPeers         []string `json:"shared_peers,omitempty"`
	Port                int      `json:"port,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	Enabled             bool     `json:"enabled"`
	AutoConnect         bool     `json:"auto_connect"`
	IsFullTunnel        bool     `json:"is_full_tunnel"`
	PrivateKeyPresent   bool     `json:"private_key_present"`
	PresharedKeyPresent bool     `json:"preshared_key_present"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Profile, error)
}

// EncodeStringList returns a JSON array suitable for routed_subnets_json
// and dns_servers_json. Empty input always emits "[]".
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// IsDefaultRoute reports whether a CIDR represents the default route.
// Drives the CWE-200 full-tunnel detection. Handles both IPv4 (0.0.0.0/0)
// and IPv6 (::/0), plus the WireGuard shorthand without prefix length.
func IsDefaultRoute(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	switch cidr {
	case "0.0.0.0/0", "::/0", "*":
		return true
	}
	// Parse and check if it's literally the unspecified address.
	if ip, ipnet, err := net.ParseCIDR(cidr); err == nil {
		if ip.IsUnspecified() {
			ones, bits := ipnet.Mask.Size()
			if ones == 0 && bits > 0 {
				return true
			}
		}
	}
	return false
}

// HasFullTunnel reports whether any routed subnet captures the default
// route. The CWE-200 query goes through this so a single audit rule
// covers all per-VPN config quirks (AllowedIPs vs push-route vs split-DNS).
func HasFullTunnel(subnets []string) bool {
	for _, s := range subnets {
		if IsDefaultRoute(s) {
			return true
		}
	}
	return false
}

// SortProfiles returns a deterministic ordering: vpn_type, then
// config_path, then name. Useful for golden tests + stable diff output.
func SortProfiles(ps []Profile) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Type != ps[j].Type {
			return ps[i].Type < ps[j].Type
		}
		if ps[i].ConfigPath != ps[j].ConfigPath {
			return ps[i].ConfigPath < ps[j].ConfigPath
		}
		return ps[i].Name < ps[j].Name
	})
}
