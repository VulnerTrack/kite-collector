// Package mongodconf inventories the local MongoDB server's
// configuration — /etc/mongod.conf and its Homebrew counterpart. The
// file's grammar is YAML 1.2 (mongod also accepts the legacy
// `key=value` style but every modern install ships YAML).
//
// The 2017 MongoCrypt ransom waves drained ~28k unauthenticated
// MongoDB instances in a week by exploiting the legacy default:
// pre-3.6 mongod bound 0.0.0.0 with `security.authorization=disabled`.
// Even today, those defaults appear in stock Docker images that
// pre-date the bind-localhost change.
//
// Headline finding shapes:
//
//   - `security.authorization: disabled` (or unset) + `net.bindIp`
//     not loopback = unauthenticated public Mongo. Anyone can drop
//     every db, leave a ransom note, or exfiltrate (CWE-306 + T1190
//   - T1486).
//   - `security.javascriptEnabled: true` lets `$where` / `mapReduce`
//     run server-side JS. Combined with auth disabled = unauth RCE
//     (CWE-94).
//   - `setParameter.enableLocalhostAuthBypass: true` permits the
//     first localhost connection to create users without auth —
//     dangerous on multi-tenant hosts (CWE-287).
//   - `net.tls.mode: disabled` + non-loopback bind = plaintext on
//     the wire (CWE-319).
//
// Read-only by intent — we parse mongod.conf only, never invoke
// mongo / mongosh. (Project guideline 4.2.)
package mongodconf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// Source identifies the probe path that produced the row. Pinned to
// the host_mongod_config.source CHECK enum.
type Source string

const (
	SourceConfigYAML Source = "config-yaml"
	SourceNoConfig   Source = "no-config"
	SourceNoProbe    Source = "no-probe"
	SourceUnknown    Source = "unknown"
)

// State mirrors host_mongod_config's column shape exactly.
type State struct {
	TLSCAFile                     string   `json:"tls_ca_file,omitempty"`
	TLSMode                       string   `json:"tls_mode,omitempty"`
	FileHash                      string   `json:"file_hash,omitempty"`
	Source                        Source   `json:"source"`
	ReplicaSetName                string   `json:"replica_set_name,omitempty"`
	DBPath                        string   `json:"db_path,omitempty"`
	LogPath                       string   `json:"log_path,omitempty"`
	LogDestination                string   `json:"log_destination,omitempty"`
	AuthorizationMode             string   `json:"authorization_mode,omitempty"`
	ClusterAuthMode               string   `json:"cluster_auth_mode,omitempty"`
	KeyfilePath                   string   `json:"keyfile_path,omitempty"`
	TLSCertKeyFile                string   `json:"tls_cert_key_file,omitempty"`
	ConfigPath                    string   `json:"config_path,omitempty"`
	BindIPs                       []string `json:"bind_ips,omitempty"`
	Port                          int      `json:"port,omitempty"`
	IsTLSEnabled                  bool     `json:"is_tls_enabled"`
	IsBoundToLoopbackOnly         bool     `json:"is_bound_to_loopback_only"`
	IsAuthorizationDisabled       bool     `json:"is_authorization_disabled"`
	IsLocalhostAuthBypassEnabled  bool     `json:"is_localhost_auth_bypass_enabled"`
	IsScriptingEnabled            bool     `json:"is_scripting_enabled"`
	IsHTTPInterfaceEnabled        bool     `json:"is_http_interface_enabled"`
	IsExternallyBound             bool     `json:"is_externally_bound"`
	IsTLSDisabledWithExternalBind bool     `json:"is_tls_disabled_with_external_bind"`
	IsUnauthenticatedWorldExposed bool     `json:"is_unauthenticated_world_exposed"`
	IsHardened                    bool     `json:"is_hardened"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// HashContents returns the SHA-256 hex of a mongod.conf body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsLoopbackAddress reports whether a bindIp entry resolves to a
// loopback interface. Empty / "0.0.0.0" / "::" all flag as NOT
// loopback — mongod listens on every interface in those cases.
func IsLoopbackAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	if addr == "localhost" {
		return true
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// IsExternalBindList reports whether any bindIp entry is non-loopback.
// Empty input flags external by default — mongod with no `bindIp`
// listens on all interfaces.
func IsExternalBindList(addrs []string) bool {
	if len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		if !IsLoopbackAddress(a) {
			return true
		}
	}
	return false
}

// IsLoopbackOnlyList reports whether every bindIp entry is loopback.
// Empty input is NOT loopback-only (no bindIp = listen everywhere).
func IsLoopbackOnlyList(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !IsLoopbackAddress(a) {
			return false
		}
	}
	return true
}

// TLSModeIsEnabled reports whether `net.tls.mode` enables wire-level
// encryption — anything other than `disabled` / "" counts as on.
func TLSModeIsEnabled(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	return m != "" && m != "disabled"
}

// IsHardened returns whether every required protection knob is set —
// rolls up the per-flag booleans into the single signal the audit
// pipeline alerts on.
func IsHardened(s State) bool {
	return !s.IsAuthorizationDisabled &&
		!s.IsScriptingEnabled &&
		!s.IsLocalhostAuthBypassEnabled &&
		!s.IsTLSDisabledWithExternalBind
}

// AnnotateSecurity sets the derived booleans on a State that has its
// raw fields populated.
func AnnotateSecurity(s *State) {
	s.IsBoundToLoopbackOnly = IsLoopbackOnlyList(s.BindIPs)
	s.IsExternallyBound = IsExternalBindList(s.BindIPs)
	s.IsTLSEnabled = TLSModeIsEnabled(s.TLSMode)
	s.IsTLSDisabledWithExternalBind = s.IsExternallyBound && !s.IsTLSEnabled
	// The headline finding: external-bound AND auth-disabled. Each
	// alone is reduced-impact; the union is the 2017-ransom shape.
	s.IsUnauthenticatedWorldExposed = s.IsExternallyBound && s.IsAuthorizationDisabled
	s.IsHardened = IsHardened(*s)
}

// SortBindIPs returns a deterministic ordering so the audit pipeline
// gets stable diffs between scans.
func SortBindIPs(s *State) {
	sort.Strings(s.BindIPs)
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
