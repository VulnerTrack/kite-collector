// Package redisconf inventories Redis server configuration —
// typically /etc/redis/redis.conf plus any files reached via `include`
// directives. Redis's config grammar is the simplest one in this
// project: comments start with `#`, every directive is `key value(s)`
// on one line, and `include /path/to/other.conf` chains config files.
//
// The exploitable failure modes are well-trodden:
//
//   - `bind 0.0.0.0` (or no `bind`) + missing `requirepass` +
//     `protected-mode no` = pre-auth Redis. From there, an attacker
//     can `CONFIG SET dir /var/www`, `SLAVEOF` replicate, or
//     `MODULE LOAD` arbitrary code — full RCE without credentials
//     (CWE-306 + T1190).
//   - `requirepass foobared` (or any short / stock value) = brute
//     force is trivial (CWE-326).
//   - Default-named CONFIG / EVAL / MODULE / FLUSHALL = lateral
//     movement and destructive intent (CWE-862).
//
// Read-only by intent — we parse the .conf, never invoke
// redis-cli or load the running config. (Project guideline 4.2.)
package redisconf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// MaxConfigs bounds per-scan output (one row per discovered
// redis*.conf). Most hosts have 1-3 (server + sentinel + cluster).
const MaxConfigs = 64

// MinPasswordLength is the floor we consider safe for `requirepass`.
// Redis docs recommend 64; we flag anything below 16 — that's the
// CWE-326 threshold the audit pipeline alerts on.
const MinPasswordLength = 16

// ConfigRole identifies which Redis role a config file belongs to.
// Pinned to the host_redis_config.config_role CHECK enum.
type ConfigRole string

const (
	RoleServer   ConfigRole = "server"
	RoleSentinel ConfigRole = "sentinel"
	RoleCluster  ConfigRole = "cluster"
	RoleUnknown  ConfigRole = "unknown"
)

// RenamedCommand captures one `rename-command FROM TO` directive.
// Empty `To` means the command is disabled entirely (`rename-command
// FLUSHALL ""`).
type RenamedCommand struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Config mirrors host_redis_config's column shape exactly.
type Config struct {
	AppendFilename                string           `json:"appendfilename,omitempty"`
	FileHash                      string           `json:"file_hash"`
	ConfigRole                    ConfigRole       `json:"config_role"`
	FilePath                      string           `json:"file_path"`
	Requirepass                   string           `json:"-"`
	ACLFile                       string           `json:"aclfile,omitempty"`
	Dir                           string           `json:"dir,omitempty"`
	DBFilename                    string           `json:"dbfilename,omitempty"`
	AppendOnly                    string           `json:"appendonly,omitempty"`
	RenamedCommands               []RenamedCommand `json:"renamed_commands,omitempty"`
	BindAddresses                 []string         `json:"bind_addresses,omitempty"`
	Includes                      []string         `json:"includes,omitempty"`
	TLSPort                       int              `json:"tls_port,omitempty"`
	Port                          int              `json:"port,omitempty"`
	IsProtectedModeEnabled        bool             `json:"is_protected_mode_enabled"`
	MasterauthPresent             bool             `json:"masterauth_present"`
	RequirepassPresent            bool             `json:"requirepass_present"`
	IsBoundToLoopbackOnly         bool             `json:"is_bound_to_loopback_only"`
	IsExternallyBound             bool             `json:"is_externally_bound"`
	IsPasswordWeak                bool             `json:"is_password_weak"`
	IsACLEnabled                  bool             `json:"is_acl_enabled"`
	HasDangerousUnrenamedCommands bool             `json:"has_dangerous_unrenamed_commands"`
	IsTLSEnabled                  bool             `json:"is_tls_enabled"`
	IsTLSDisabledWithExternalBind bool             `json:"is_tls_disabled_with_external_bind"`
	IsUnauthenticatedWorldExposed bool             `json:"is_unauthenticated_world_exposed"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Config, error)
}

// HashContents returns the SHA-256 hex of a redis.conf body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DangerousCommands is the curated set of Redis commands that must
// be disabled or renamed in any production deployment. Each grants
// lateral movement (CONFIG/SLAVEOF/MODULE) or destructive action
// (FLUSHALL/SHUTDOWN/DEBUG).
func DangerousCommands() []string {
	return []string{"CONFIG", "EVAL", "MODULE", "DEBUG", "FLUSHALL", "FLUSHDB", "SHUTDOWN", "SLAVEOF", "REPLICAOF"}
}

// StockPasswords is the curated set of low-effort passwords that any
// attacker will try first. `foobared` is the legacy Redis default
// that ships in many tutorials and stock images.
func StockPasswords() []string {
	return []string{"foobared", "redis", "password", "admin", "root", "default", "secret"}
}

// IsLoopbackAddress reports whether a bind value names only the
// loopback interface(s). The empty string means "no bind" — Redis
// listens on every interface, which is the *opposite* of loopback.
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

// IsExternalBind reports whether at least one bind address is
// non-loopback. A bind value of `0.0.0.0` or `::` is the canonical
// "all interfaces" shape; we treat anything that isn't loopback as
// externally-reachable.
func IsExternalBind(binds []string) bool {
	for _, b := range binds {
		if !IsLoopbackAddress(b) {
			return true
		}
	}
	return false
}

// IsLoopbackOnly reports whether every bind address resolves to the
// loopback interface. An empty list means "no bind", which Redis
// treats as "listen everywhere" — NOT loopback-only.
func IsLoopbackOnly(binds []string) bool {
	if len(binds) == 0 {
		return false
	}
	for _, b := range binds {
		if !IsLoopbackAddress(b) {
			return false
		}
	}
	return true
}

// IsWeakPassword reports whether a `requirepass` value is too short
// to brute-force-resist OR matches one of the stock defaults.
func IsWeakPassword(pass string) bool {
	p := strings.TrimSpace(pass)
	if p == "" {
		return false
	}
	if len(p) < MinPasswordLength {
		return true
	}
	lp := strings.ToLower(p)
	for _, stock := range StockPasswords() {
		if lp == stock {
			return true
		}
	}
	return false
}

// HasDangerousUnrenamed reports whether the dangerous-command set is
// not blanket-disabled or renamed. ACL-gated deployments may keep
// commands at default names safely; the audit pipeline treats this
// flag as "investigate" rather than "block".
func HasDangerousUnrenamed(renamed []RenamedCommand, aclEnabled bool) bool {
	if aclEnabled {
		return false
	}
	disabled := make(map[string]struct{}, len(renamed))
	for _, r := range renamed {
		if r.To == "" {
			disabled[strings.ToUpper(r.From)] = struct{}{}
		}
	}
	for _, cmd := range DangerousCommands() {
		if _, off := disabled[cmd]; !off {
			return true
		}
	}
	return false
}

// NormalizeRole maps a redis*.conf file path's leaf name to a
// ConfigRole. Sentinel and cluster-bus files have stable names.
func NormalizeRole(filePath string) ConfigRole {
	lower := strings.ToLower(filePath)
	switch {
	case strings.Contains(lower, "sentinel"):
		return RoleSentinel
	case strings.Contains(lower, "cluster"):
		return RoleCluster
	case strings.HasSuffix(lower, "redis.conf") ||
		strings.HasSuffix(lower, "/redis-server.conf"):
		return RoleServer
	}
	return RoleUnknown
}

// AnnotateSecurity sets the derived booleans on a Config that has
// its raw fields populated.
func AnnotateSecurity(c *Config) {
	c.RequirepassPresent = strings.TrimSpace(c.Requirepass) != ""
	c.IsBoundToLoopbackOnly = IsLoopbackOnly(c.BindAddresses)
	c.IsExternallyBound = IsExternalBind(c.BindAddresses) || len(c.BindAddresses) == 0
	c.IsACLEnabled = strings.TrimSpace(c.ACLFile) != ""
	c.IsPasswordWeak = IsWeakPassword(c.Requirepass)
	c.HasDangerousUnrenamedCommands = HasDangerousUnrenamed(c.RenamedCommands, c.IsACLEnabled)
	c.IsTLSEnabled = c.TLSPort > 0
	c.IsTLSDisabledWithExternalBind = c.IsExternallyBound && !c.IsTLSEnabled
	// The headline finding: bound non-loopback AND not protected AND
	// no password. Each component alone is reduced-impact; the union
	// is the pre-auth RCE shape.
	c.IsUnauthenticatedWorldExposed = c.IsExternallyBound &&
		!c.IsProtectedModeEnabled &&
		!c.RequirepassPresent
}

// SortConfigs returns a deterministic ordering by file path.
func SortConfigs(cs []Config) {
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].FilePath < cs[j].FilePath
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

// EncodeRenamedCommands returns the canonical JSON shape for the
// renamed_commands_json column.
func EncodeRenamedCommands(rs []RenamedCommand) string {
	if len(rs) == 0 {
		return "[]"
	}
	b, err := json.Marshal(rs)
	if err != nil {
		return "[]"
	}
	return string(b)
}
