// Package listeners enumerates LISTEN-state TCP/UDP sockets across Linux,
// macOS, Windows, and the BSDs, binding each socket to its owning process.
// A single cross-platform collector is possible via gopsutil/v4/net
// (Linux /proc/net, macOS sysctl, Windows GetExtendedTcpTable/UdpTable).
//
// Every collector is **read-only** — it queries socket tables, never
// opens, closes, or sends on any socket. Read-only is enforced by
// guideline 4.2 of the kite-collector project.
//
// Listener rows are the single highest-value asset class for security
// audits because they describe a host's *attack surface*:
//
//   - CWE-200 (Information Exposure) — anything bound to 0.0.0.0 / :: is
//     reachable from every network the host is on.
//   - CWE-319 (Cleartext Transmission) — telnet:23, ftp:21, rsh:514,
//     unencrypted-mongo:27017 listening on non-loopback.
//   - CWE-284 (Improper Access Control) — database ports (5432, 3306,
//     27017, 6379) bound to 0.0.0.0 + no firewall.
//   - CWE-693 (Protection Mechanism Failure) — SSH listening on the
//     internet exposure path with PasswordAuthentication enabled
//     (cross-referenced with the config-audit findings).
package listeners

import (
	"context"
	"net"
	"sort"
)

// MaxListeners bounds per-scan output. A typical host has 5-30 listeners;
// a busy server might have 100+. The 4096 ceiling protects the SQLite
// write path from socket-exhaustion attacks or misconfigured spawn-on-
// demand systemd units.
const MaxListeners = 4096

// Protocol normalises gopsutil's "tcp"/"tcp6"/"udp"/"udp6" strings. Values
// are pinned to the host_listeners.protocol CHECK enum.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoTCP6 Protocol = "tcp6"
	ProtoUDP  Protocol = "udp"
	ProtoUDP6 Protocol = "udp6"
)

// Exposure is the derived reachability classification. Strings are pinned
// to the host_listeners.exposure CHECK enum. Pre-computing this at write
// time keeps CWE audit queries as equality lookups (vs CIDR matches at
// query time).
type Exposure string

const (
	ExposureInternet Exposure = "internet"
	ExposureLAN      Exposure = "lan"
	ExposureLoopback Exposure = "loopback"
	ExposureUnknown  Exposure = "unknown"
)

// Listener is the cross-platform record produced by every collector. It
// mirrors the column shape of host_listeners so the store layer can
// persist rows without a translation step.
type Listener struct {
	Protocol    Protocol `json:"protocol"`
	BindAddress string   `json:"bind_address"`
	Exposure    Exposure `json:"exposure"`
	ProcessName string   `json:"process_name,omitempty"`
	Exe         string   `json:"exe,omitempty"`
	Username    string   `json:"username,omitempty"`
	PID         int32    `json:"pid,omitempty"`
	Port        uint16   `json:"port"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry.
	Name() string
	// Collect enumerates LISTEN sockets. Read-only.
	Collect(ctx context.Context) ([]Listener, error)
}

// ClassifyExposure maps a bind address to a reachability class.
//
//   - 0.0.0.0 / :: → internet (reachable from every routable network)
//   - 127.0.0.0/8 / ::1 → loopback
//   - RFC 1918 (10/8, 172.16/12, 192.168/16) / link-local → lan
//   - public IPs → internet
//   - unparseable → unknown
//
// This is intentionally pessimistic about 0.0.0.0: even if the host is
// behind a NAT, a misconfigured port-forward or VPN tunnel makes a
// 0.0.0.0 listener internet-exposed *somehow*. False-positive on this
// axis is preferable to false-negative.
func ClassifyExposure(addr string) Exposure {
	if addr == "" || addr == "*" {
		return ExposureInternet
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ExposureUnknown
	}
	if ip.IsUnspecified() {
		// 0.0.0.0 or ::
		return ExposureInternet
	}
	if ip.IsLoopback() {
		return ExposureLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return ExposureLAN
	}
	// Public unicast IP — assume internet-reachable.
	return ExposureInternet
}

// SortListeners returns a deterministic ordering: by protocol, then bind
// address, then port. Useful for golden-file tests and stable diffs.
func SortListeners(ls []Listener) {
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].Protocol != ls[j].Protocol {
			return ls[i].Protocol < ls[j].Protocol
		}
		if ls[i].BindAddress != ls[j].BindAddress {
			return ls[i].BindAddress < ls[j].BindAddress
		}
		return ls[i].Port < ls[j].Port
	})
}
