// Package intranetweb inventories internal-facing HTTP/HTTPS endpoints.
//
// The collector takes a list of (ip, port, source) targets — usually
// fed from the existing LAN discovery output (mdns/ssdp/wsdiscovery/
// netbios/lldp) plus passive parses of /etc/hosts and the user's
// proxy PAC — and actively probes each one. For every reachable
// endpoint it records the HTTP status, server banner, page title,
// TLS subject/issuer/expiry, plus pre-computed security indicators.
//
// The probe is **read-only by intent**: GET / with a short timeout,
// follow zero redirects, never POST, never authenticate. The TLS
// dial uses InsecureSkipVerify because the whole point is to inspect
// the cert chain that browsers would warn on — but we never use the
// connection for anything beyond fingerprinting.
//
// Rows feed the audit pipeline:
//
//   - CWE-319 (Cleartext Transmission) — `is_cleartext=1` for any
//     intranet UI served plain-http.
//   - CWE-295 (Improper Cert Validation) — `tls_self_signed=1` and/or
//     `tls_expired=1` flag certs that train users to click through
//     browser warnings.
//   - CWE-200 (Information Exposure) — `is_directory_listing=1` for
//     Apache/nginx autoindex pages.
//   - MITRE T1133 / T1190 (internal variant) — every row is candidate
//     pivot surface for an already-internal actor.
package intranetweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// MaxEndpoints bounds per-scan output. A typical small office LAN has
// 10-30 web UIs (printers, NAS, switches, IPMI, internal apps). The
// 1024 ceiling protects the SQLite write path against a misconfigured
// scan that targets a large /16.
const MaxEndpoints = 1024

// DefaultPorts are the TCP ports the active prober tries on every
// target IP. The set is intentionally narrow — kite is a discovery
// agent, not nmap. The HTTP-vs-HTTPS classification is best-effort
// (port 80 is treated as cleartext, 443 as TLS, the others are probed
// twice on demand).
func DefaultPorts() []int {
	return []int{80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9000, 9090}
}

// Scheme is the wire protocol the endpoint speaks. Pinned to the
// host_intranet_webs.scheme CHECK enum.
type Scheme string

const (
	SchemeHTTP  Scheme = "http"
	SchemeHTTPS Scheme = "https"
)

// DiscoverySource records where this endpoint's (ip, port) candidate
// came from. Pinned to the host_intranet_webs.discovery_source CHECK
// enum so unknown values can't sneak through.
type DiscoverySource string

const (
	SourceMDNS        DiscoverySource = "mdns"
	SourceSSDP        DiscoverySource = "ssdp"
	SourceWSDiscovery DiscoverySource = "wsdiscovery"
	SourceNetBIOS     DiscoverySource = "netbios"
	SourceLLDP        DiscoverySource = "lldp"
	SourceHostsFile   DiscoverySource = "hosts-file"
	SourceProxyPAC    DiscoverySource = "proxy-pac"
	SourceManual      DiscoverySource = "manual"
	SourceSubnetSweep DiscoverySource = "subnet-sweep"
	SourceUnknown     DiscoverySource = "unknown"
)

// Target identifies one (ip, port) candidate to probe, plus where it
// came from. Callers build a list of these from LAN discovery output.
type Target struct {
	IP     string
	Host   string
	Source DiscoverySource
	Port   int
}

// Endpoint is the projected record produced per reachable target.
// Mirrors host_intranet_webs' column shape exactly.
type Endpoint struct {
	ServerHeader         string          `json:"server_header,omitempty"`
	TLSIssuer            string          `json:"tls_issuer,omitempty"`
	IP                   string          `json:"ip"`
	PageHash             string          `json:"page_hash,omitempty"`
	DiscoverySource      DiscoverySource `json:"discovery_source"`
	Scheme               Scheme          `json:"scheme"`
	ContentType          string          `json:"content_type,omitempty"`
	TLSFingerprintSHA256 string          `json:"tls_fingerprint_sha256,omitempty"`
	Host                 string          `json:"host"`
	PoweredBy            string          `json:"powered_by,omitempty"`
	AuthScheme           string          `json:"auth_scheme,omitempty"`
	TLSSubject           string          `json:"tls_subject,omitempty"`
	Title                string          `json:"title,omitempty"`
	TLSNotAfter          string          `json:"tls_not_after,omitempty"`
	StatusCode           int             `json:"status_code,omitempty"`
	Port                 int             `json:"port"`
	IsCleartext          bool            `json:"is_cleartext"`
	TLSSelfSigned        bool            `json:"tls_self_signed"`
	TLSExpired           bool            `json:"tls_expired"`
	IsDirectoryListing   bool            `json:"is_directory_listing"`
	IsDefaultPage        bool            `json:"is_default_page"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Endpoint, error)
}

// TargetResolver supplies the candidate (ip, port) list to probe.
// Implementations stitch together the LAN discovery output, /etc/hosts
// entries, and the user's proxy PAC.
type TargetResolver interface {
	Resolve(ctx context.Context) ([]Target, error)
}

// HashPage returns a stable sha256 of the bytes that make up the
// "page identity" — status code, server banner, content-type, title.
// Used for drift detection between scans.
func HashPage(statusCode int, serverHeader, contentType, title string) string {
	var sb strings.Builder
	sb.WriteString(strings.TrimSpace(serverHeader))
	sb.WriteByte('|')
	sb.WriteString(strings.TrimSpace(contentType))
	sb.WriteByte('|')
	sb.WriteString(strings.TrimSpace(title))
	sb.WriteByte('|')
	// status as 3-digit decimal so 200 vs 2000 doesn't collide.
	sb.WriteString(formatStatus(statusCode))
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func formatStatus(code int) string {
	if code <= 0 {
		return "000"
	}
	if code >= 1000 {
		// Should never happen with HTTP, but cap defensively.
		return "999"
	}
	digits := []byte{
		byte('0' + code/100),
		byte('0' + (code/10)%10),
		byte('0' + code%10),
	}
	return string(digits)
}

// IsCleartextPort reports whether the port is conventionally plain-HTTP.
// Used by the prober to pre-set Endpoint.IsCleartext before the probe
// (the probe itself confirms by which dial succeeded).
func IsCleartextPort(port int) bool {
	switch port {
	case 80, 81, 8000, 8008, 8080, 8888, 9000, 9090, 3000, 5000:
		return true
	}
	return false
}

// IsTLSPort reports whether the port is conventionally HTTPS. We don't
// assume one-or-the-other for ambiguous ports — the prober tries both.
func IsTLSPort(port int) bool {
	switch port {
	case 443, 8443:
		return true
	}
	return false
}

// DefaultPageTitles is a curated set of strings that identify a
// post-install / never-customised admin landing page. Hitting one of
// these on a LAN endpoint is high-signal: the device was deployed and
// never further configured.
func DefaultPageTitles() []string {
	return []string{
		"Welcome to nginx!",
		"Apache2 Ubuntu Default Page: It works",
		"Apache2 Debian Default Page",
		"Test Page for the Apache HTTP Server",
		"IIS Windows Server",
		"Welcome to CentOS",
		"It works!",
		"Welcome to your Tomcat",
	}
}

// IsDefaultLandingTitle reports whether the page title matches a
// known post-install template.
func IsDefaultLandingTitle(title string) bool {
	t := strings.TrimSpace(title)
	if t == "" {
		return false
	}
	for _, want := range DefaultPageTitles() {
		if strings.Contains(t, want) {
			return true
		}
	}
	return false
}

// IsDirectoryListingBody reports whether the response body looks like
// an Apache/nginx autoindex page. We sniff the first ~4KB only.
func IsDirectoryListingBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	probe := body
	if len(probe) > 4096 {
		probe = probe[:4096]
	}
	s := strings.ToLower(string(probe))
	// nginx autoindex starts with "<h1>Index of /...</h1>".
	// Apache autoindex starts with "<title>Index of /...".
	if strings.Contains(s, "<title>index of /") ||
		strings.Contains(s, "<h1>index of /") {
		return true
	}
	return false
}

// SortEndpoints returns a deterministic ordering: ip, then port.
func SortEndpoints(es []Endpoint) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].IP != es[j].IP {
			return es[i].IP < es[j].IP
		}
		return es[i].Port < es[j].Port
	})
}

// DedupeTargets removes (ip, port) duplicates, preferring the first
// occurrence's DiscoverySource. Sources are merged-keep-first because
// the resolver typically queries the highest-quality source (mDNS/SSDP)
// before the noisier fallbacks (subnet sweep).
func DedupeTargets(ts []Target) []Target {
	seen := make(map[string]bool, len(ts))
	out := make([]Target, 0, len(ts))
	for _, t := range ts {
		key := t.IP + ":" + strconv.Itoa(t.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}
