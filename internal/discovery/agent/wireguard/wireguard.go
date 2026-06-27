// Package wireguard inventories WireGuard tunnel definitions from
// /etc/wireguard/*.conf and the Homebrew counterparts on macOS. Each
// file describes one tunnel: an [Interface] section for the local
// endpoint plus one or more [Peer] sections for remote nodes.
//
// WireGuard's failure modes are narrower than typical VPN tools, but
// the few that exist are catastrophic:
//
//   - PrivateKey stored in a world- or group-readable .conf =
//     anyone who can `cat` the file can resurrect the tunnel from
//     any other host (CWE-312 + CWE-732). `wg-quick`'s installer
//     leaves files at 0600 by design — drift to 0644 is always
//     worth alerting.
//   - A [Peer] with `AllowedIPs = 0.0.0.0/0, ::/0` is the "full
//     tunnel" shape: depending on which side of the link you're on,
//     either that peer routes all of your traffic OR you accept all
//     of theirs. Often the wrong default for site-to-site (T1572).
//   - `PostUp` / `PostDown` / `PreUp` / `PreDown` lines invoke a
//     shell command as root on tunnel bring-up. Anyone who can
//     write the .conf gets arbitrary code (CWE-78 + T1059).
//   - Missing `PresharedKey` on a [Peer] drops the third (PSK)
//     factor — legitimate for personal tunnels, regression for
//     site-to-site between high-value endpoints (CWE-308).
//
// Read-only by intent — we parse the .conf only, never invoke
// wg / wg-quick. (Project guideline 4.2.)
package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical mesh host has 1-3
// tunnels with 2-30 peers each; the 512 ceiling covers heavyweight
// site-to-site hubs without bloating SQLite writes.
const MaxRows = 512

// SectionKind classifies a tunnel-file section. Pinned to the
// host_wireguard_tunnels.section_kind CHECK enum.
type SectionKind string

const (
	SectionInterface SectionKind = "interface"
	SectionPeer      SectionKind = "peer"
	SectionUnknown   SectionKind = "unknown"
)

// Tunnel mirrors host_wireguard_tunnels' column shape exactly. One
// of these is produced per [Interface] or [Peer] section.
type Tunnel struct {
	Endpoint                   string      `json:"endpoint,omitempty"`
	FileHash                   string      `json:"file_hash"`
	SectionKind                SectionKind `json:"section_kind"`
	TunnelName                 string      `json:"tunnel_name"`
	Address                    string      `json:"address,omitempty"`
	FilePath                   string      `json:"file_path"`
	DNS                        string      `json:"dns,omitempty"`
	AllowedIPs                 string      `json:"allowed_ips,omitempty"`
	TableRouting               string      `json:"table_routing,omitempty"`
	PublicKeyFingerprint       string      `json:"public_key_fingerprint,omitempty"`
	PeerPublicKeyFingerprint   string      `json:"peer_public_key_fingerprint,omitempty"`
	ShellHooks                 []string    `json:"shell_hooks,omitempty"`
	ListenPort                 int         `json:"listen_port,omitempty"`
	MTU                        int         `json:"mtu,omitempty"`
	PersistentKeepaliveSeconds int         `json:"persistent_keepalive_seconds,omitempty"`
	SectionIndex               int         `json:"section_index"`
	FileMode                   int         `json:"file_mode,omitempty"`
	FileOwnerUID               int         `json:"file_owner_uid,omitempty"`
	HasPresharedKey            bool        `json:"has_preshared_key"`
	HasPrivateKey              bool        `json:"has_private_key"`
	IsMissingPresharedKey      bool        `json:"is_missing_preshared_key"`
	IsFullTrafficRoute         bool        `json:"is_full_traffic_route"`
	HasShellHook               bool        `json:"has_shell_hook"`
	HasPersistentKeepalive     bool        `json:"has_persistent_keepalive"`
	IsFileWorldReadable        bool        `json:"is_file_world_readable"`
	IsFileGroupReadable        bool        `json:"is_file_group_readable"`
	HasPrivateKeyExposed       bool        `json:"has_private_key_exposed"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Tunnel, error)
}

// HashContents returns the SHA-256 hex of a .conf body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PublicKeyFingerprint returns a short, non-secret identifier for a
// WireGuard public key — the first 12 hex chars of sha256(key). Used
// so the audit pipeline can join [Interface] ↔ [Peer] rows without
// persisting the raw 32-byte key.
func PublicKeyFingerprint(b64Key string) string {
	k := strings.TrimSpace(b64Key)
	if k == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:6])
}

// IsFullTrafficRoute reports whether an AllowedIPs string covers
// every IPv4 OR every IPv6 destination. WireGuard treats the union
// of all peer AllowedIPs as the routing table; a 0.0.0.0/0 or ::/0
// is the canonical "send everything through this peer" shape.
func IsFullTrafficRoute(allowed string) bool {
	for _, tok := range splitCommaList(allowed) {
		t := strings.TrimSpace(tok)
		if t == "0.0.0.0/0" || t == "::/0" {
			return true
		}
	}
	return false
}

// ShellHookCommands is the curated set of WireGuard hook directives
// that execute arbitrary shell commands during tunnel bring-up or
// teardown.
func ShellHookCommands() []string {
	return []string{"preup", "postup", "predown", "postdown"}
}

// AnnotateSecurity sets the derived booleans on a Tunnel that has
// its raw fields populated.
func AnnotateSecurity(t *Tunnel) {
	t.IsFullTrafficRoute = IsFullTrafficRoute(t.AllowedIPs)
	t.HasShellHook = len(t.ShellHooks) > 0
	t.HasPersistentKeepalive = t.PersistentKeepaliveSeconds > 0
	if t.SectionKind == SectionPeer {
		t.IsMissingPresharedKey = !t.HasPresharedKey
	}
	if t.FileMode != 0 {
		t.IsFileWorldReadable = t.FileMode&0o004 != 0
		t.IsFileGroupReadable = t.FileMode&0o040 != 0
	}
	t.HasPrivateKeyExposed = t.HasPrivateKey &&
		(t.IsFileWorldReadable || t.IsFileGroupReadable)
}

// SortTunnels returns a deterministic ordering by file path, then
// section index (so [Interface] always sits ahead of its peers).
func SortTunnels(ts []Tunnel) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].FilePath != ts[j].FilePath {
			return ts[i].FilePath < ts[j].FilePath
		}
		return ts[i].SectionIndex < ts[j].SectionIndex
	})
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
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

// splitCommaList tokenises a comma-separated value with whitespace
// tolerance. Used for AllowedIPs and DNS.
func splitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
