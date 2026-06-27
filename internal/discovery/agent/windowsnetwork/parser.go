package windowsnetwork

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PowerShellScript captures both inventory types in one round-trip:
//   - All adapters joined with their configurations via Index
//   - The IPv4 routing table
//
// We index the configurations by Index so the adapter-side join is
// O(1). Hash-table lookup happens server-side so the Go decoder
// receives one flat row per adapter.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue)
$configs  = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue)
$routes   = @(Get-CimInstance -ClassName Win32_IP4RouteTable -ErrorAction SilentlyContinue)

$cfgByIndex = @{}
foreach ($c in $configs) {
    if ($null -ne $c.Index) { $cfgByIndex[[string]$c.Index] = $c }
}

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try { return (([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) } catch { return $null }
}

function Arr($v) {
    if ($null -eq $v) { return @() }
    return @($v | ForEach-Object { [string]$_ })
}

$adapterRows = @($adapters | ForEach-Object {
    $cfg = $cfgByIndex[[string]$_.Index]
    [pscustomobject]@{
        interface_index           = if ($_.Index -ne $null) { [int]$_.Index } else { 0 }
        device_id                 = [string]$_.DeviceID
        name                      = [string]$_.Name
        description               = [string]$_.Description
        net_connection_id         = [string]$_.NetConnectionID
        manufacturer              = [string]$_.Manufacturer
        adapter_type              = [string]$_.AdapterType
        mac_address               = [string]$_.MACAddress
        speed_bps                 = if ($_.Speed -ne $null) { [int64]$_.Speed } else { 0 }
        net_enabled               = [bool]$_.NetEnabled
        net_connection_status     = if ($_.NetConnectionStatus -ne $null) { [int]$_.NetConnectionStatus } else { 0 }
        physical_adapter          = [bool]$_.PhysicalAdapter
        guid                      = [string]$_.GUID
        pnp_device_id             = [string]$_.PNPDeviceID
        dhcp_enabled              = if ($cfg) { [bool]$cfg.DHCPEnabled } else { $false }
        dhcp_server               = if ($cfg) { [string]$cfg.DHCPServer } else { $null }
        dhcp_lease_obtained       = ToIso($(if ($cfg) { $cfg.DHCPLeaseObtained }))
        ip_addresses              = if ($cfg) { Arr($cfg.IPAddress) } else { @() }
        ip_subnets                = if ($cfg) { Arr($cfg.IPSubnet) } else { @() }
        gateways                  = if ($cfg) { Arr($cfg.DefaultIPGateway) } else { @() }
        dns_servers               = if ($cfg) { Arr($cfg.DNSServerSearchOrder) } else { @() }
        dns_domain                = if ($cfg) { [string]$cfg.DNSDomain } else { $null }
        dns_suffix_search_order   = if ($cfg) { Arr($cfg.DNSDomainSuffixSearchOrder) } else { @() }
        wins_servers              = if ($cfg) { Arr(@($cfg.WINSPrimaryServer, $cfg.WINSSecondaryServer) | Where-Object { $_ }) } else { @() }
    }
})

$routeRows = @($routes | ForEach-Object {
    [pscustomobject]@{
        destination     = [string]$_.Destination
        mask            = [string]$_.Mask
        next_hop        = [string]$_.NextHop
        interface_index = if ($_.InterfaceIndex -ne $null) { [int]$_.InterfaceIndex } else { 0 }
        metric1         = if ($_.Metric1 -ne $null) { [int]$_.Metric1 } else { 0 }
        protocol        = if ($_.Protocol -ne $null) { [int]$_.Protocol } else { 0 }
        type            = if ($_.Type -ne $null) { [int]$_.Type } else { 0 }
        age_seconds     = if ($_.Age -ne $null) { [int]$_.Age } else { 0 }
    }
})

[pscustomobject]@{
    adapters = $adapterRows
    routes   = $routeRows
} | ConvertTo-Json -Depth 5 -Compress
`

// rawPayload mirrors the JSON shape.
type rawPayload struct {
	Adapters []rawAdapter `json:"adapters"`
	Routes   []rawRoute   `json:"routes"`
}

type rawAdapter struct {
	DHCPServer           *string     `json:"dhcp_server"`
	DNSDomain            *string     `json:"dns_domain"`
	DHCPLeaseObtained    *string     `json:"dhcp_lease_obtained"`
	GUID                 string      `json:"guid"`
	InterfaceIndex       json.Number `json:"interface_index"`
	Manufacturer         string      `json:"manufacturer"`
	AdapterType          string      `json:"adapter_type"`
	MACAddress           string      `json:"mac_address"`
	SpeedBPS             json.Number `json:"speed_bps"`
	NetConnectionID      string      `json:"net_connection_id"`
	NetConnectionStatus  json.Number `json:"net_connection_status"`
	Name                 string      `json:"name"`
	DeviceID             string      `json:"device_id"`
	PnpDeviceID          string      `json:"pnp_device_id"`
	Description          string      `json:"description"`
	DNSSuffixSearchOrder []string    `json:"dns_suffix_search_order"`
	WINSServers          []string    `json:"wins_servers"`
	IPAddresses          []string    `json:"ip_addresses"`
	IPSubnets            []string    `json:"ip_subnets"`
	Gateways             []string    `json:"gateways"`
	DNSServers           []string    `json:"dns_servers"`
	NetEnabled           bool        `json:"net_enabled"`
	DHCPEnabled          bool        `json:"dhcp_enabled"`
	PhysicalAdapter      bool        `json:"physical_adapter"`
}

type rawRoute struct {
	Destination    string      `json:"destination"`
	Mask           string      `json:"mask"`
	NextHop        string      `json:"next_hop"`
	InterfaceIndex json.Number `json:"interface_index"`
	Metric1        json.Number `json:"metric1"`
	Protocol       json.Number `json:"protocol"`
	Type           json.Number `json:"type"`
	AgeSeconds     json.Number `json:"age_seconds"`
}

// ParsePowerShellOutput converts the JSON payload into an Inventory.
// Singleton-object unwrap mirrors the windowscpumem pattern: a host
// with exactly one adapter or one route can arrive as a singleton.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	normalised := unwrapSingletonArrays(trimmed)

	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-network json: %w", err)
	}

	inv := Inventory{
		Adapters: make([]Adapter, 0, len(raw.Adapters)),
		Routes:   make([]Route, 0, len(raw.Routes)),
	}
	for _, r := range raw.Adapters {
		a := Adapter{
			Source:               SourcePowerShellCIM,
			InterfaceIndex:       atoi(r.InterfaceIndex),
			DeviceID:             strings.TrimSpace(r.DeviceID),
			Name:                 strings.TrimSpace(r.Name),
			Description:          strings.TrimSpace(r.Description),
			NetConnectionID:      strings.TrimSpace(r.NetConnectionID),
			Manufacturer:         strings.TrimSpace(r.Manufacturer),
			AdapterType:          strings.TrimSpace(r.AdapterType),
			MACAddress:           strings.TrimSpace(r.MACAddress),
			SpeedBPS:             atoi64(r.SpeedBPS),
			NetEnabled:           r.NetEnabled,
			NetConnectionStatus:  atoi(r.NetConnectionStatus),
			PhysicalAdapter:      r.PhysicalAdapter,
			GUID:                 strings.TrimSpace(r.GUID),
			PnpDeviceID:          strings.TrimSpace(r.PnpDeviceID),
			DHCPEnabled:          r.DHCPEnabled,
			DHCPServer:           deref(r.DHCPServer),
			DHCPLeaseObtained:    normaliseTime(deref(r.DHCPLeaseObtained)),
			IPAddresses:          cleanList(r.IPAddresses),
			IPSubnets:            cleanList(r.IPSubnets),
			Gateways:             cleanList(r.Gateways),
			DNSServers:           cleanList(r.DNSServers),
			DNSDomain:            deref(r.DNSDomain),
			DNSSuffixSearchOrder: cleanList(r.DNSSuffixSearchOrder),
			WINSServers:          cleanList(r.WINSServers),
		}
		AnnotateAdapter(&a)
		inv.Adapters = append(inv.Adapters, a)
	}
	for _, r := range raw.Routes {
		ro := Route{
			Source:         SourcePowerShellCIM,
			Destination:    strings.TrimSpace(r.Destination),
			Mask:           strings.TrimSpace(r.Mask),
			NextHop:        strings.TrimSpace(r.NextHop),
			InterfaceIndex: atoi(r.InterfaceIndex),
			Metric1:        atoi(r.Metric1),
			Protocol:       atoi(r.Protocol),
			Type:           atoi(r.Type),
			AgeSeconds:     atoi(r.AgeSeconds),
		}
		AnnotateRoute(&ro)
		inv.Routes = append(inv.Routes, ro)
	}
	return inv, nil
}

// cleanList strips empty entries (PowerShell can emit empty strings
// when a field is null inside an array).
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unwrapSingletonArrays handles the PowerShell ConvertTo-Json quirk
// where a singleton becomes a bare object instead of a one-element
// array. Same shim as windowscpumem; specialised here for the
// "adapters" / "routes" keys.
func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"adapters":`, `"routes":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

func wrapSingletonValue(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '{' {
		return s
	}
	depth, inStr, escaped := 0, false, false
	end := -1
	for j := i; j < len(rest); j++ {
		c := rest[j]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case c == '{' && !inStr:
			depth++
		case c == '}' && !inStr:
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= i {
		return s
	}
	wrapped := "[" + rest[i:end] + "]" + rest[end:]
	return s[:idx+len(key)] + wrapped
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if f, err := n.Float64(); err == nil {
		return int(f)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func atoi64(n json.Number) int64 {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return v
	}
	if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
		if u > 1<<62 {
			return 1 << 62
		}
		return int64(u)
	}
	return 0
}

func normaliseTime(s string) string {
	if s == "" {
		return ""
	}
	candidates := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, layout := range candidates {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
