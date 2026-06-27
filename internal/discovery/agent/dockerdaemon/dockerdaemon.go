// Package dockerdaemon inventories the local Docker daemon's
// configuration — primarily /etc/docker/daemon.json. The Docker
// daemon is the most privileged service on a container host (it
// effectively runs as init for every workload), so its configuration
// posture is a CDMS asset on its own.
//
// The shape of the file is the union of every flag documented by
// `dockerd --help` — most fields are optional with engine defaults
// that the collector has to recreate to derive findings correctly.
//
// Headline findings:
//
//   - "hosts": ["tcp://0.0.0.0:2375"] + no TLS = anyone with network
//     reach gets root on the host (CWE-306 + T1610).
//   - "insecure-registries": [...] = TLS bypass for image pulls,
//     opening MITM image substitution (CWE-295 + T1525).
//   - "no-new-privileges": false (default) = container processes can
//     re-acquire privileges via setuid (CWE-269).
//   - "userns-remap": "" = container UID 0 == host UID 0 (CWE-269).
//   - "iptables": false = the daemon won't manage firewall rules,
//     usually leaving published ports exposed network-wide.
//
// Read-only by intent — this collector parses daemon.json and never
// invokes dockerd / docker-cli. (Project guideline 4.2.)
package dockerdaemon

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
// the host_docker_daemon.source CHECK enum.
type Source string

const (
	SourceDaemonJSON Source = "daemon-json"
	SourceNoConfig   Source = "no-config"
	SourceNoProbe    Source = "no-probe"
	SourceUnknown    Source = "unknown"
)

// State mirrors host_docker_daemon's column shape exactly.
type State struct {
	LogDriver                string   `json:"log_driver,omitempty"`
	ConfigPath               string   `json:"config_path,omitempty"`
	FileHash                 string   `json:"file_hash,omitempty"`
	RawConfig                string   `json:"raw_config,omitempty"`
	SeccompProfile           string   `json:"seccomp_profile,omitempty"`
	UsernsRemap              string   `json:"userns_remap,omitempty"`
	Source                   Source   `json:"source"`
	DefaultRuntime           string   `json:"default_runtime,omitempty"`
	CgroupParent             string   `json:"cgroup_parent,omitempty"`
	StorageDriver            string   `json:"storage_driver,omitempty"`
	RegistryMirrors          []string `json:"registry_mirrors,omitempty"`
	InsecureRegistries       []string `json:"insecure_registries,omitempty"`
	Hosts                    []string `json:"hosts,omitempty"`
	HasInsecureRegistries    bool     `json:"has_insecure_registries"`
	IsTCPSocketWorldExposed  bool     `json:"is_tcp_socket_world_exposed"`
	IsTLSEnabled             bool     `json:"is_tls_enabled"`
	IsTLSVerifyEnabled       bool     `json:"is_tls_verify_enabled"`
	IsTCPSocketExposed       bool     `json:"is_tcp_socket_exposed"`
	IsUsernsRemapped         bool     `json:"is_userns_remapped"`
	IsNoNewPrivilegesDefault bool     `json:"is_no_new_privileges_default"`
	IsIptablesManaged        bool     `json:"is_iptables_managed"`
	IsLiveRestoreEnabled     bool     `json:"is_live_restore_enabled"`
	IsSELinuxEnabled         bool     `json:"is_selinux_enabled"`
	IsExperimentalEnabled    bool     `json:"is_experimental_enabled"`
	IsHardened               bool     `json:"is_hardened"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// HashContents returns the SHA-256 hex of a daemon.json body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsTCPHost reports whether a hosts[] entry exposes a TCP socket
// (`tcp://0.0.0.0:2375` etc) as opposed to the unix:// or fd://
// transports that dockerd uses by default.
func IsTCPHost(h string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "tcp://")
}

// IsWorldBoundHost reports whether a TCP host string binds to a
// world-reachable interface — either 0.0.0.0 / [::]/ explicit IP that
// isn't loopback. Empty host (`tcp://:2375`) means "all interfaces"
// per dockerd convention and also flags.
func IsWorldBoundHost(h string) bool {
	if !IsTCPHost(h) {
		return false
	}
	rest := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(h)), "tcp://")
	if rest == "" {
		return true
	}
	host, _, err := net.SplitHostPort(rest)
	if err != nil {
		host = rest
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	// Bare hostname → assume non-loopback. The audit pipeline can
	// fold by reachability with the listeners table.
	return host != "localhost"
}

// HasTCPSocket reports whether any hosts[] entry exposes TCP.
func HasTCPSocket(hosts []string) bool {
	for _, h := range hosts {
		if IsTCPHost(h) {
			return true
		}
	}
	return false
}

// HasWorldExposedTCPSocket reports whether any hosts[] entry binds
// TCP to a non-loopback address.
func HasWorldExposedTCPSocket(hosts []string) bool {
	for _, h := range hosts {
		if IsWorldBoundHost(h) {
			return true
		}
	}
	return false
}

// IsHardened returns whether every required protection knob is set —
// rolls up the per-flag booleans into the single signal the audit
// pipeline alerts on.
func IsHardened(s State) bool {
	return !s.HasInsecureRegistries &&
		!s.IsTCPSocketWorldExposed &&
		s.IsNoNewPrivilegesDefault &&
		s.IsUsernsRemapped &&
		s.IsIptablesManaged
}

// AnnotateSecurity sets the derived booleans on a State that has its
// raw fields populated.
func AnnotateSecurity(s *State) {
	s.IsTCPSocketExposed = HasTCPSocket(s.Hosts)
	s.IsTCPSocketWorldExposed = HasWorldExposedTCPSocket(s.Hosts)
	s.HasInsecureRegistries = len(s.InsecureRegistries) > 0
	s.IsUsernsRemapped = strings.TrimSpace(s.UsernsRemap) != ""
	s.IsHardened = IsHardened(*s)
}

// SortLists normalises the string slices in place so the audit
// pipeline gets stable diffs between scans.
func SortLists(s *State) {
	sort.Strings(s.Hosts)
	sort.Strings(s.InsecureRegistries)
	sort.Strings(s.RegistryMirrors)
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
