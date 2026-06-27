// Package timesync inventories every time-synchronization source
// configured on a host across Linux (chrony, ntpd, systemd-timesyncd,
// openntpd), macOS (sntp via /etc/ntp.conf), and Windows (w32time).
//
// Time is the root of authentication: Kerberos tickets, TLS cert
// expiry, TOTP codes, and DNSSEC signatures all hinge on the host's
// notion of UTC. An attacker who pins the clock can replay expired
// credentials, defeat signed-payload expiry, and bypass cert checks.
// MITRE ATT&CK covers this under T1124 (System Time Discovery /
// Manipulation) and T1098 (the Kerberos branch of Account
// Manipulation — Golden Ticket forgery requires clock control).
//
// Every collector is **read-only by intent** — it parses config files,
// never invokes `chronyc add server` or `w32tm /config`. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Peer rows feed the audit pipeline:
//
//   - T1124 — `is_public_server=1` flags peers in well-known pool/
//     public networks. Acceptable for personal devices, suspicious
//     for domain-joined endpoints that should sync to the corp NTP.
//   - CWE-345 — `is_authenticated=0` flags peers without NTS /
//     autokey / shared-key auth. Plain NTP is trivially MitM-able.
//   - T1098 — file_hash drift on chrony.conf / ntp.conf =
//     attacker may have swapped the source. Always worth alerting.
package timesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxPeers bounds per-scan output. A typical chrony.conf has 4-8 pool
// entries; the 256 ceiling covers aggressive split-poll configs.
const MaxPeers = 256

// Source identifies which subsystem produced the row. Pinned to the
// host_time_sync.source CHECK enum.
type Source string

const (
	SourceChrony           Source = "chrony"
	SourceNTPd             Source = "ntpd"
	SourceSystemdTimesyncd Source = "systemd-timesyncd"
	SourceOpenNTPd         Source = "openntpd"
	SourceW32Time          Source = "w32time"
	SourceSNTP             Source = "sntp"
	SourceUnknown          Source = "unknown"
)

// Directive classifies how the host treats the peer. Pinned to the
// host_time_sync.directive CHECK enum.
type Directive string

const (
	DirectiveServer       Directive = "server"
	DirectivePeer         Directive = "peer"
	DirectivePool         Directive = "pool"
	DirectiveFallback     Directive = "fallback"
	DirectiveSNTPFallback Directive = "sntp-fallback"
	DirectiveUnknown      Directive = "unknown"
)

// Protocol is the wire protocol. Pinned to host_time_sync.protocol.
type Protocol string

const (
	ProtocolNTP     Protocol = "ntp"
	ProtocolNTS     Protocol = "nts"     // NTS-secured NTP (chrony nts option)
	ProtocolSNTP    Protocol = "sntp"    // Simple NTP (systemd-timesyncd, sntp(1))
	ProtocolAutokey Protocol = "autokey" // legacy ntpd autokey
	ProtocolUnknown Protocol = "unknown"
)

// Peer is the cross-source record. Mirrors host_time_sync's column
// shape exactly.
type Peer struct {
	Source          Source    `json:"source"`
	Directive       Directive `json:"directive"`
	Server          string    `json:"server"`
	RawLine         string    `json:"raw_line,omitempty"`
	Protocol        Protocol  `json:"protocol"`
	FileHash        string    `json:"file_hash,omitempty"`
	FilePath        string    `json:"file_path,omitempty"`
	MaxPoll         int       `json:"maxpoll,omitempty"`
	KeyID           int       `json:"key_id,omitempty"`
	MinPoll         int       `json:"minpoll,omitempty"`
	LineNo          int       `json:"line_no"`
	Port            int       `json:"port"`
	IsPublicServer  bool      `json:"is_public_server"`
	IsPoolMember    bool      `json:"is_pool_member"`
	IsAuthenticated bool      `json:"is_authenticated"`
	PreferFlag      bool      `json:"prefer_flag"`
	Iburst          bool      `json:"iburst"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Peer, error)
}

// HashContents returns the SHA-256 hex of a config file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PublicNTPDomainSuffixes is the curated list of well-known public
// NTP pool / appliance suffixes. Peers matching any of these flag
// `is_public_server=1`. Maintained in lower-case for case-insensitive
// comparison.
func PublicNTPDomainSuffixes() []string {
	return []string{
		"pool.ntp.org",
		"ntp.ubuntu.com",
		"time.nist.gov",
		"time.google.com",
		"time.cloudflare.com",
		"time.windows.com",
		"time.apple.com",
		"time.facebook.com",
		"time.aws.com",
		"time.fb.com",
		"nts.ntp.se",
		"ptbtime1.ptb.de",
		"ptbtime2.ptb.de",
	}
}

// IsPublicNTPServer reports whether the server name matches any of
// the well-known public pools/appliances. Substring suffix match so
// that "0.pool.ntp.org" + "2.ubuntu.pool.ntp.org" both flag.
func IsPublicNTPServer(server string) bool {
	s := strings.ToLower(strings.TrimSpace(server))
	if s == "" {
		return false
	}
	for _, suffix := range PublicNTPDomainSuffixes() {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// IsPoolDirective returns the canonical Directive for a chrony/ntp
// keyword. Pool/server/peer overlap across the implementations.
func IsPoolDirective(d Directive) bool {
	return d == DirectivePool
}

// AnnotateSecurity sets the indexed booleans on a peer row from its
// already-populated fields. Centralised so the flags don't drift
// between sources.
func AnnotateSecurity(p *Peer) {
	p.IsPublicServer = IsPublicNTPServer(p.Server)
	p.IsPoolMember = p.Directive == DirectivePool
	// is_authenticated is set by the per-source parsers when they see
	// `nts`, `key <N>`, or `autokey`. The default zero here means the
	// peer is plain NTP — which is the conservative finding.
}

// SortPeers returns a deterministic ordering: source, server, port.
func SortPeers(ps []Peer) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Source != ps[j].Source {
			return ps[i].Source < ps[j].Source
		}
		if ps[i].Server != ps[j].Server {
			return ps[i].Server < ps[j].Server
		}
		return ps[i].Port < ps[j].Port
	})
}
