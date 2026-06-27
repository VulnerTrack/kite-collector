// Package winhosts inventories entries in the hosts(5) file. The
// canonical path on Windows is
// C:\Windows\System32\drivers\etc\hosts; Linux and macOS use the
// shorter /etc/hosts. The file grammar is identical across all
// three OSes — IP + whitespace + hostname + optional aliases +
// optional `#` comment.
//
// File-based discovery is the deliberate design choice: every host
// has the file, every parser reads it the same way, and the audit
// pipeline can hash it for drift detection without going through
// the DNS resolver stack.
//
// Headline finding shapes (MITRE T1565.001 — Stored Data
// Manipulation, plus T1583 — Acquire Infrastructure adjacent):
//
//   - `is_dns_poisoning_candidate=1` — a non-loopback IP for a
//     hostname that doesn't end in a well-known local suffix
//     (.local / .localhost / .internal / .test / .example /
//     .invalid). The canonical "redirect a public domain to a
//     phishing host" shape; the audit pipeline allowlists
//     legitimate split-horizon DNS uses by name.
//   - `is_blocklist_entry=1` — 0.0.0.0 or 127.0.0.1 binding for a
//     hostname. Usually legit (ad blockers, telemetry suppression)
//     but worth counting for compliance.
//   - `is_wildcard_subdomain=1` — hostname begins with `*.`; the
//     hosts(5) format doesn't strictly support wildcards, but
//     homegrown patches occasionally write them. Always investigate.
//
// Read-only by intent — we parse the file only, never invoke
// `ipconfig /flushdns` or anything else. (Project guideline 4.2.)
package winhosts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

// MaxEntries bounds per-scan output. A typical hosts file has 5-20
// lines; ad-block hosts files (StevenBlack et al) ship 100k+ lines.
// The 200k ceiling covers them without bloating SQLite writes too
// aggressively.
const MaxEntries = 200000

// IPKind classifies the destination IP for an entry. Pinned to the
// host_hosts_entries.ip_kind CHECK enum.
type IPKind string

const (
	IPLoopback IPKind = "loopback" // 127.0.0.0/8 or ::1
	IPRFC1918  IPKind = "rfc1918"  // 10/8, 172.16/12, 192.168/16
	IPPublic   IPKind = "public"   // anything else routable
	IPSinkhole IPKind = "sinkhole" // 0.0.0.0 or ::
	IPInvalid  IPKind = "invalid"  // unparseable
)

// LocalDomainSuffixes is the curated set of TLD suffixes the audit
// pipeline considers "local" (split-horizon DNS, test fixtures,
// internal-only resolution). Hostnames ending in these never flag
// the DNS-poisoning candidate finding.
//
// `.localhost`, `.local`, `.example`, `.test`, `.invalid` are the
// RFC 6761 reserved names; the others are common enterprise picks.
func LocalDomainSuffixes() []string {
	return []string{
		".local", ".localhost", ".internal", ".intranet",
		".example", ".test", ".invalid", ".lan", ".corp", ".home",
	}
}

// Entry mirrors host_hosts_entries' column shape exactly.
type Entry struct {
	IPKind                  IPKind `json:"ip_kind"`
	FileHash                string `json:"file_hash"`
	RawLine                 string `json:"raw_line,omitempty"`
	IPAddress               string `json:"ip_address"`
	Hostname                string `json:"hostname"`
	FilePath                string `json:"file_path"`
	Comment                 string `json:"comment,omitempty"`
	LineNo                  int    `json:"line_no"`
	IsAlias                 bool   `json:"is_alias"`
	IsLoopbackTarget        bool   `json:"is_loopback_target"`
	IsBlocklistEntry        bool   `json:"is_blocklist_entry"`
	IsWildcardSubdomain     bool   `json:"is_wildcard_subdomain"`
	IsSystemManagedDefault  bool   `json:"is_system_managed_default"`
	IsDNSPoisoningCandidate bool   `json:"is_dns_poisoning_candidate"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// HashContents returns the SHA-256 hex of a hosts-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ClassifyIP maps an IP literal to its IPKind. Unparseable input
// returns IPInvalid. `0.0.0.0` and `::` map to IPSinkhole — they
// don't actually route traffic anywhere; they're the canonical
// "drop on the floor" shape adopted by every host-based ad blocker.
func ClassifyIP(addr string) IPKind {
	a := strings.TrimSpace(addr)
	if a == "" {
		return IPInvalid
	}
	if a == "0.0.0.0" || a == "::" {
		return IPSinkhole
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return IPInvalid
	}
	if ip.IsLoopback() {
		return IPLoopback
	}
	if ip.IsPrivate() {
		return IPRFC1918
	}
	return IPPublic
}

// IsLocalHostname reports whether a hostname ends in one of the
// curated local-domain suffixes. The bare `localhost` literal also
// flags.
func IsLocalHostname(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if h == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	for _, suf := range LocalDomainSuffixes() {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// SystemManagedDefaultHostnames is the curated set of hostnames the
// OS installer typically writes into the file — every Windows /
// Linux / macOS install ships a few stock entries that should never
// flag findings.
func SystemManagedDefaultHostnames() []string {
	return []string{
		"localhost",
		"localhost.localdomain",
		"ip6-localhost", "ip6-loopback",
		"ip6-allnodes", "ip6-allrouters",
		"ip6-mcastprefix",
		"broadcasthost",
	}
}

// IsSystemManagedDefault reports whether a hostname is in the stock
// installer set.
func IsSystemManagedDefault(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	for _, d := range SystemManagedDefaultHostnames() {
		if h == d {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on an Entry that has
// its raw fields populated.
func AnnotateSecurity(e *Entry) {
	e.IPKind = ClassifyIP(e.IPAddress)
	e.IsLoopbackTarget = e.IPKind == IPLoopback
	e.IsBlocklistEntry = e.IPKind == IPSinkhole ||
		(e.IPKind == IPLoopback && !IsSystemManagedDefault(e.Hostname))
	e.IsWildcardSubdomain = strings.HasPrefix(strings.TrimSpace(e.Hostname), "*.")
	e.IsSystemManagedDefault = IsSystemManagedDefault(e.Hostname)
	// DNS-poisoning candidate: non-loopback, non-sinkhole IP for a
	// hostname that isn't (a) a local-domain suffix and (b) a stock
	// installer default.
	e.IsDNSPoisoningCandidate = (e.IPKind == IPPublic || e.IPKind == IPRFC1918) &&
		!IsLocalHostname(e.Hostname) &&
		!e.IsSystemManagedDefault
}

// SortEntries returns a deterministic ordering by file path, line
// number, hostname.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		if es[i].LineNo != es[j].LineNo {
			return es[i].LineNo < es[j].LineNo
		}
		return es[i].Hostname < es[j].Hostname
	})
}
