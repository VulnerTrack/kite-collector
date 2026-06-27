// Package rsyslog inventories remote-forwarding directives in the
// rsyslog configuration chain — /etc/rsyslog.conf plus every
// /etc/rsyslog.d/*.conf drop-in. Each forwarder is a potential
// egress channel; defender-side audit pipelines need to know:
//
//   - Where the logs go (which host, port, transport).
//   - Whether the link is encrypted.
//   - Whether the destination is inside the customer's address
//     space or out on the public internet.
//
// rsyslog has two distinct grammars for the same operation:
//
//   - Legacy single-line:
//     *.*  @logserver.example.com:514       # UDP forward
//     auth.*  @@logserver.example.com:6514  # TCP forward
//   - Modern action() block:
//     action(type="omfwd" target="logserver" port="6514"
//     protocol="tcp" StreamDriver="gtls")
//     action(type="omhttp" server="https://collect.example.com")
//
// We parse both, normalise the destination, and surface the same
// derived booleans regardless of source style.
//
// MITRE T1048 (Exfiltration Over Alternative Protocol) and T1567
// (Exfiltration Over Web Service). A forwarder added that points at
// a server *not* listed in the SIEM inventory is a high-confidence
// exfil signal.
//
// Read-only by intent — we parse the .conf chain only, never invoke
// rsyslogd. (Project guideline 4.2.)
package rsyslog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. Most hosts ship 0-3 forwarders;
// the 256 ceiling covers heavy-tier log-aggregation hubs without
// bloating SQLite writes.
const MaxRows = 256

// DirectiveKind classifies one forwarder by its source grammar.
// Pinned to the host_rsyslog_forwarders.directive_kind CHECK enum.
type DirectiveKind string

const (
	KindLegacyUDP    DirectiveKind = "legacy-udp"
	KindLegacyTCP    DirectiveKind = "legacy-tcp"
	KindActionOmfwd  DirectiveKind = "action-omfwd"
	KindActionOmhttp DirectiveKind = "action-omhttp"
	KindUnknown      DirectiveKind = "unknown"
)

// Forwarder mirrors host_rsyslog_forwarders' column shape exactly.
type Forwarder struct {
	TransportProtocol          string        `json:"transport_protocol,omitempty"`
	TLSDriver                  string        `json:"tls_driver,omitempty"`
	FilePath                   string        `json:"file_path"`
	RawDirective               string        `json:"raw_directive,omitempty"`
	DirectiveKind              DirectiveKind `json:"directive_kind"`
	Selector                   string        `json:"selector,omitempty"`
	Destination                string        `json:"destination"`
	QueueType                  string        `json:"queue_type,omitempty"`
	FileHash                   string        `json:"file_hash"`
	DestinationPort            int           `json:"destination_port,omitempty"`
	LineNo                     int           `json:"line_no"`
	IsPlaintextTransport       bool          `json:"is_plaintext_transport"`
	IsDestinationExternal      bool          `json:"is_destination_external"`
	IsHTTPEgress               bool          `json:"is_http_egress"`
	SelectorIncludesEverything bool          `json:"selector_includes_everything"`
	IsTLSEnabled               bool          `json:"is_tls_enabled"`
	IsSuspiciousEgress         bool          `json:"is_suspicious_egress"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Forwarder, error)
}

// HashContents returns the SHA-256 hex of a config-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsRFC1918Address reports whether an IPv4 address belongs to one of
// the private ranges (10/8, 172.16/12, 192.168/16) or is loopback /
// link-local. Returns false for non-IPv4 (incl. IPv6 ULA which we
// treat conservatively as external — the audit pipeline can override).
func IsRFC1918Address(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return ip.IsPrivate()
	}
	return ip.IsPrivate()
}

// IsExternalDestination reports whether a host string resolves to a
// non-private address. Hostnames return true unless they're literal
// loopback names — we deliberately err on the side of "investigate"
// for unresolved DNS names. The audit pipeline can fold against the
// allowlist of internal hostnames.
func IsExternalDestination(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	// Strip URL scheme + path if present (omhttp targets).
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	// Strip :port if present.
	if hostPart, _, err := net.SplitHostPort(h); err == nil {
		h = hostPart
	}
	if h == "" {
		return false
	}
	lower := strings.ToLower(h)
	if lower == "localhost" || lower == "localhost.localdomain" {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return !IsRFC1918Address(h)
	}
	return true
}

// AnnotateSecurity sets the derived booleans on a Forwarder.
func AnnotateSecurity(f *Forwarder) {
	f.IsTLSEnabled = strings.TrimSpace(f.TLSDriver) != "" ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Destination)), "https://")
	f.IsHTTPEgress = f.DirectiveKind == KindActionOmhttp
	switch f.DirectiveKind {
	case KindLegacyUDP, KindLegacyTCP:
		f.IsPlaintextTransport = true
	case KindActionOmfwd:
		f.IsPlaintextTransport = !f.IsTLSEnabled
	case KindActionOmhttp:
		// omhttp without TLS is plaintext — though uncommon, an
		// `http://` target is exfil-friendly.
		lower := strings.ToLower(strings.TrimSpace(f.Destination))
		f.IsPlaintextTransport = strings.HasPrefix(lower, "http://")
	case KindUnknown:
		// Unknown directive shape — leave booleans cleared; the
		// audit pipeline can decide what to do with the raw row.
	}
	f.IsDestinationExternal = IsExternalDestination(f.Destination)
	f.SelectorIncludesEverything = isWildcardSelector(f.Selector)
	// Headline rollup: external destination AND (plaintext OR http).
	// A TLS-tunnelled forward to an internal SIEM is fine; everything
	// else deserves a closer look.
	f.IsSuspiciousEgress = f.IsDestinationExternal &&
		(f.IsPlaintextTransport || f.IsHTTPEgress)
}

// isWildcardSelector reports whether the selector matches "every
// facility, every priority". rsyslog accepts a handful of shorthand
// forms; the bare "*.*" and "*.* @host" are the most common, but
// "*.info;auth.none" with effective coverage also surface in audits.
func isWildcardSelector(s string) bool {
	t := strings.TrimSpace(s)
	return t == "*.*" || t == "*"
}

// SortForwarders returns a deterministic ordering by file path, line
// number.
func SortForwarders(fs []Forwarder) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].FilePath != fs[j].FilePath {
			return fs[i].FilePath < fs[j].FilePath
		}
		return fs[i].LineNo < fs[j].LineNo
	})
}
