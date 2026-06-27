// Package dnsresolver inventories every DNS resolver configured on a
// host across Linux (/etc/resolv.conf, systemd-resolved.conf,
// NetworkManager keyfiles, dnsmasq.conf), macOS (scutil --dns), and
// Windows (Get-DnsClientServerAddress).
//
// DNS is the universal name-resolution layer; whoever controls it can
// redirect every connection a host attempts. MITRE ATT&CK groups this
// under T1568 (Dynamic Resolution) and T1071.004 (Application Layer
// Protocol: DNS). The collector inventories who the host is asking;
// the audit pipeline compares that list against the expected corporate
// resolver set and flags drift.
//
// Every collector is **read-only** — it parses config files, never
// invokes `resolvectl set-dns` or mutates anything. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Resolver rows feed the audit pipeline:
//
//   - T1568.002 — `is_public_resolver=1` on a host that should be
//     using internal DNS = candidate hijack / split-tunnel evasion.
//   - T1071.004 — `is_doh_or_dot=1` defeats network-layer DNS
//     inspection. Worth flagging on managed endpoints.
//   - CWE-300 — plain `protocol='udp'` with `is_dnssec=0` is MitM-able
//     by any router on the path.
//   - Drift — file_hash change on /etc/resolv.conf or any NetworkManager
//     keyfile = a DNS-routing modification event.
package dnsresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// MaxResolvers bounds per-scan output. A typical host has 2-4 system
// resolvers + per-interface entries on multi-homed hosts. The 256
// ceiling handles aggressive split-horizon configs without bloating
// the SQLite write path.
const MaxResolvers = 256

// Source identifies which file/subsystem produced the row. Pinned to
// the host_dns_resolvers.source CHECK enum.
type Source string

const (
	SourceResolvConf       Source = "resolv-conf"
	SourceSystemdResolved  Source = "systemd-resolved"
	SourceNetworkManager   Source = "network-manager"
	SourceDnsmasq          Source = "dnsmasq"
	SourceUnbound          Source = "unbound"
	SourceMacOSScutil      Source = "macos-scutil"
	SourceWindowsDNSClient Source = "windows-dnsclient"
	SourceUnknown          Source = "unknown"
)

// Scope is the application breadth of the resolver entry. Pinned to
// the host_dns_resolvers.scope CHECK enum.
type Scope string

const (
	ScopeSystem    Scope = "system"
	ScopeInterface Scope = "interface"
	ScopeProcess   Scope = "process"
	ScopePerDomain Scope = "per-domain"
	ScopeUnknown   Scope = "unknown"
)

// Protocol is the DNS transport. Pinned to host_dns_resolvers.protocol.
type Protocol string

const (
	ProtocolUDP     Protocol = "udp"
	ProtocolTCP     Protocol = "tcp"
	ProtocolDoT     Protocol = "tls"   // DNS-over-TLS, port 853
	ProtocolDoH     Protocol = "https" // DNS-over-HTTPS, port 443
	ProtocolQUIC    Protocol = "quic"  // DNS-over-QUIC
	ProtocolUnknown Protocol = "unknown"
)

// Resolver is the cross-source record. Mirrors host_dns_resolvers'
// column shape exactly.
type Resolver struct {
	FilePath         string   `json:"file_path,omitempty"`
	Scope            Scope    `json:"scope"`
	InterfaceName    string   `json:"interface_name,omitempty"`
	Server           string   `json:"server"`
	RawLine          string   `json:"raw_line,omitempty"`
	Protocol         Protocol `json:"protocol"`
	RoutedDomain     string   `json:"routed_domain,omitempty"`
	Source           Source   `json:"source"`
	FileHash         string   `json:"file_hash,omitempty"`
	SearchDomains    []string `json:"search_domains,omitempty"`
	Priority         int      `json:"priority"`
	LineNo           int      `json:"line_no"`
	Port             int      `json:"port"`
	IsLoopback       bool     `json:"is_loopback"`
	IsDoHOrDoT       bool     `json:"is_doh_or_dot"`
	IsPublicResolver bool     `json:"is_public_resolver"`
	IsDNSSEC         bool     `json:"is_dnssec"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Resolver, error)
}

// EncodeStringList returns a JSON array suitable for search_domains_json.
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

// HashContents returns the SHA-256 hex of a config file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PublicResolverIPs is the curated list of well-known public DNS
// services. Hits on this list from a managed corporate endpoint
// indicate either a deliberate user bypass or a hijack — the audit
// pipeline decides which.
//
// Sourced from operator-published IPs:
//   - Google Public DNS, Cloudflare, Quad9, OpenDNS, AdGuard,
//     Comodo Secure DNS, NextDNS anycast, Yandex DNS, CleanBrowsing.
func PublicResolverIPs() []string {
	return []string{
		// Google
		"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
		// Cloudflare
		"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
		// Quad9
		"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
		// OpenDNS / Cisco Umbrella
		"208.67.222.222", "208.67.220.220",
		// AdGuard DNS
		"94.140.14.14", "94.140.15.15",
		// Comodo Secure DNS
		"8.26.56.26", "8.20.247.20",
		// CleanBrowsing
		"185.228.168.168", "185.228.169.168",
		// Yandex DNS
		"77.88.8.8", "77.88.8.1",
	}
}

// IsPublicResolverIP reports whether the IP belongs to a well-known
// public DNS service. Comparison is case-insensitive on the v6 hex.
func IsPublicResolverIP(server string) bool {
	want := strings.ToLower(strings.TrimSpace(server))
	for _, p := range PublicResolverIPs() {
		if strings.EqualFold(p, want) {
			return true
		}
	}
	return false
}

// IsLoopbackResolver reports whether the resolver address points at
// the host's own loopback (the usual signal for a local stub resolver
// like dnsmasq, systemd-resolved's 127.0.0.53, or Pi-hole).
func IsLoopbackResolver(server string) bool {
	ip := net.ParseIP(strings.TrimSpace(server))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// IsDoHOrDoTProtocol reports whether the protocol bypasses on-network
// DNS inspection (DoH and DoT both tunnel over TLS/HTTPS).
func IsDoHOrDoTProtocol(p Protocol) bool {
	switch p {
	case ProtocolDoT, ProtocolDoH, ProtocolQUIC:
		return true
	case ProtocolUDP, ProtocolTCP, ProtocolUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on a resolver row from
// its already-populated server + protocol fields. Centralised so the
// flags don't drift between sources.
func AnnotateSecurity(r *Resolver) {
	r.IsPublicResolver = IsPublicResolverIP(r.Server)
	r.IsLoopback = IsLoopbackResolver(r.Server)
	r.IsDoHOrDoT = IsDoHOrDoTProtocol(r.Protocol)
}

// SortResolvers returns a deterministic ordering: source, then server,
// then port. Useful for golden-file tests and stable diff output.
func SortResolvers(rs []Resolver) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Source != rs[j].Source {
			return rs[i].Source < rs[j].Source
		}
		if rs[i].Server != rs[j].Server {
			return rs[i].Server < rs[j].Server
		}
		return rs[i].Port < rs[j].Port
	})
}
