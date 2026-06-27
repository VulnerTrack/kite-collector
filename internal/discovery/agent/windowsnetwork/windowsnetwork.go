// Package windowsnetwork inventories Windows network adapters +
// adapter configurations (joined via Index) + the IPv4 routing
// table via a PowerShell shim.
//
// Fourth table-set in the MID Server-aligned Windows track. Returns
// an Inventory bundle (Adapters + Routes) so the audit pipeline can
// join them via interface_index on a single Collect() call.
//
// MITRE T1016 (System Network Configuration Discovery — defender
// side): the audit pipeline correlates against host_dns_resolvers,
// host_listeners, and host_intranet_webs to surface:
//
//   - DHCP server outside the corporate set
//   - DNS servers overriding system config (T1568.002)
//   - Unfamiliar default gateways (split-tunnel / pivot VPN)
//   - Stale adapter rows with valid IPs but no link (rogue VLAN)
//
// Architecture: same PowerShell-shim + build-tag split as the rest
// of the windows* track. Parser in non-tagged file for cross-OS tests.
package windowsnetwork

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Source identifies which probe produced the rows. Pinned to the
// host_windows_network_adapters.source +
// host_windows_ip4_routes.source CHECK enums (shared enum set).
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// Adapter mirrors host_windows_network_adapters' column shape.
type Adapter struct {
	Manufacturer         string   `json:"manufacturer,omitempty"`
	DNSDomain            string   `json:"dns_domain,omitempty"`
	DeviceID             string   `json:"device_id"`
	Name                 string   `json:"name,omitempty"`
	Description          string   `json:"description,omitempty"`
	NetConnectionID      string   `json:"net_connection_id,omitempty"`
	GUID                 string   `json:"guid,omitempty"`
	AdapterType          string   `json:"adapter_type,omitempty"`
	MACAddress           string   `json:"mac_address,omitempty"`
	Source               Source   `json:"source"`
	DHCPLeaseObtained    string   `json:"dhcp_lease_obtained,omitempty"`
	DHCPServer           string   `json:"dhcp_server,omitempty"`
	PnpDeviceID          string   `json:"pnp_device_id,omitempty"`
	IPAddresses          []string `json:"ip_addresses,omitempty"`
	IPSubnets            []string `json:"ip_subnets,omitempty"`
	Gateways             []string `json:"gateways,omitempty"`
	DNSServers           []string `json:"dns_servers,omitempty"`
	DNSSuffixSearchOrder []string `json:"dns_suffix_search_order,omitempty"`
	WINSServers          []string `json:"wins_servers,omitempty"`
	NetConnectionStatus  int      `json:"net_connection_status"`
	SpeedBPS             int64    `json:"speed_bps,omitempty"`
	InterfaceIndex       int      `json:"interface_index"`
	PhysicalAdapter      bool     `json:"physical_adapter"`
	DHCPEnabled          bool     `json:"dhcp_enabled"`
	NetEnabled           bool     `json:"net_enabled"`
	HasDefaultGateway    bool     `json:"has_default_gateway"`
}

// Route mirrors host_windows_ip4_routes' column shape.
type Route struct {
	Source         Source `json:"source"`
	Destination    string `json:"destination"`
	Mask           string `json:"mask"`
	NextHop        string `json:"next_hop"`
	InterfaceIndex int    `json:"interface_index"`
	Metric1        int    `json:"metric1"`
	Protocol       int    `json:"protocol"`
	Type           int    `json:"type"`
	AgeSeconds     int    `json:"age_seconds,omitempty"`
	IsDefaultRoute bool   `json:"is_default_route"`
}

// Inventory bundles both entity slices. The store layer fans this
// out into two table writes via asset_id.
type Inventory struct {
	Adapters []Adapter `json:"adapters"`
	Routes   []Route   `json:"routes"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// EncodeStringList returns a JSON array suitable for the *_json columns.
// Empty input always emits "[]" so the column is never NULL.
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

// NormalizeMAC canonicalises a MAC address to uppercase colon-
// separated form ("AA:BB:CC:DD:EE:FF"). Empty input returns empty.
// Windows reports MACs in this shape natively but PowerShell can
// emit lower-case or dash-separated variants depending on host
// locale; the audit pipeline matches against MAC vendor prefixes
// in upper-case.
func NormalizeMAC(mac string) string {
	s := strings.TrimSpace(mac)
	if s == "" {
		return ""
	}
	// Replace dashes with colons.
	s = strings.ReplaceAll(s, "-", ":")
	// Validate: 6 groups of 2 hex chars.
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return strings.ToUpper(s)
	}
	for i, p := range parts {
		if len(p) != 2 {
			return strings.ToUpper(s)
		}
		parts[i] = strings.ToUpper(p)
	}
	return strings.Join(parts, ":")
}

// IsDefaultRouteDestination reports whether the (destination, mask)
// pair represents the default route. IPv4: 0.0.0.0/0.0.0.0.
func IsDefaultRouteDestination(destination, mask string) bool {
	return strings.TrimSpace(destination) == "0.0.0.0" &&
		strings.TrimSpace(mask) == "0.0.0.0"
}

// AnnotateAdapter sets the derived fields on an Adapter.
func AnnotateAdapter(a *Adapter) {
	a.MACAddress = NormalizeMAC(a.MACAddress)
	a.HasDefaultGateway = false
	for _, g := range a.Gateways {
		if strings.TrimSpace(g) != "" {
			a.HasDefaultGateway = true
			break
		}
	}
}

// AnnotateRoute sets the derived fields on a Route.
func AnnotateRoute(r *Route) {
	r.IsDefaultRoute = IsDefaultRouteDestination(r.Destination, r.Mask)
}

// SortAdapters returns a deterministic ordering: interface_index, mac.
func SortAdapters(as []Adapter) {
	sort.Slice(as, func(i, j int) bool {
		if as[i].InterfaceIndex != as[j].InterfaceIndex {
			return as[i].InterfaceIndex < as[j].InterfaceIndex
		}
		return as[i].MACAddress < as[j].MACAddress
	})
}

// SortRoutes returns a deterministic ordering: destination, mask, next_hop.
func SortRoutes(rs []Route) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Destination != rs[j].Destination {
			return rs[i].Destination < rs[j].Destination
		}
		if rs[i].Mask != rs[j].Mask {
			return rs[i].Mask < rs[j].Mask
		}
		return rs[i].NextHop < rs[j].NextHop
	})
}

// SortInventory normalises both slices in place.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortAdapters(inv.Adapters)
	SortRoutes(inv.Routes)
}
