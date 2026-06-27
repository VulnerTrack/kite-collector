// Package nsswitch inventories the GNU Name Service Switch
// configuration at /etc/nsswitch.conf — the file that tells every
// libc lookup (getpwnam, getgrnam, getaddrinfo) which backend to ask
// for `passwd`, `group`, `shadow`, `hosts`, and friends.
//
// nsswitch is the universal identity-resolution control point on
// Linux. Adding `sss` or `ldap` to the `passwd:` chain joins the host
// to a directory; flipping `hosts:` to consult DNS before `files`
// inverts the trust order between the local hosts file and the
// network. Both are well-known persistence + lateral-movement
// primitives:
//
//   - MITRE T1556 (Modify Authentication Process) — adding a remote
//     identity source to passwd/group/shadow lets an attacker who
//     controls the directory inject users without touching
//     /etc/passwd.
//   - MITRE T1078 (Valid Accounts) — the audit pipeline joins this
//     table against host_dns_resolvers + host_kerberos_config to map
//     the full credential surface a host trusts.
//
// Every collector is **read-only by intent** — it parses
// /etc/nsswitch.conf, never modifies it. Read-only is enforced by
// guideline 4.2 of the kite-collector project.
//
// Entry rows feed the audit pipeline:
//
//   - `is_security_critical=1 AND has_non_local_source=1` flags the
//     T1556 finding shape: a password/group/shadow database backed by
//     a remote source.
//   - `is_files_missing=1` flags databases that have no local
//     fallback — emergency-recovery hazard.
//   - `is_files_last=1` flags hosts that consult network sources
//     before files (DNS-spoofing exposure for the hosts: chain).
//   - File hash drift on /etc/nsswitch.conf = identity-resolution
//     policy was modified.
package nsswitch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxEntries bounds per-scan output. /etc/nsswitch.conf typically has
// 12-18 active databases; the 64 ceiling covers any plausible setup.
const MaxEntries = 64

// Database identifies which lookup type the entry configures. Pinned
// to the host_nsswitch.database CHECK enum. Unknown databases are
// inventoried under DatabaseUnknown.
type Database string

const (
	DatabasePasswd     Database = "passwd"
	DatabaseShadow     Database = "shadow"
	DatabaseGroup      Database = "group"
	DatabaseHosts      Database = "hosts"
	DatabaseServices   Database = "services"
	DatabaseNetworks   Database = "networks"
	DatabaseProtocols  Database = "protocols"
	DatabaseRPC        Database = "rpc"
	DatabaseEthers     Database = "ethers"
	DatabaseNetmasks   Database = "netmasks"
	DatabaseBootparams Database = "bootparams"
	DatabaseNetgroup   Database = "netgroup"
	DatabaseAutomount  Database = "automount"
	DatabaseAliases    Database = "aliases"
	DatabasePublickey  Database = "publickey"
	DatabaseGshadow    Database = "gshadow"
	DatabaseSudoers    Database = "sudoers"
	DatabaseInitgroups Database = "initgroups"
	DatabaseUnknown    Database = "unknown"
)

// Entry is the parsed record produced per non-comment line. Mirrors
// host_nsswitch's column shape exactly.
type Entry struct {
	Database           Database `json:"database"`
	SourceChain        string   `json:"source_chain"`
	FilePath           string   `json:"file_path,omitempty"`
	FileHash           string   `json:"file_hash,omitempty"`
	RawLine            string   `json:"raw_line,omitempty"`
	Sources            []string `json:"sources,omitempty"`
	LineNo             int      `json:"line_no"`
	IsSecurityCritical bool     `json:"is_security_critical"`
	HasNonLocalSource  bool     `json:"has_non_local_source"`
	IsFilesMissing     bool     `json:"is_files_missing"`
	IsFilesLast        bool     `json:"is_files_last"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// EncodeStringList returns a JSON array suitable for sources_json.
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

// HashContents returns the SHA-256 hex of /etc/nsswitch.conf. Drives
// drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SecurityCriticalDatabases is the set whose remote-sourcing flips a
// host into directory-trust territory. Drawn from PAM module behaviour:
// these are the databases the auth stack actually consults.
func SecurityCriticalDatabases() []Database {
	return []Database{
		DatabasePasswd,
		DatabaseShadow,
		DatabaseGroup,
		DatabaseGshadow,
		DatabaseInitgroups,
		DatabaseSudoers,
	}
}

// IsSecurityCriticalDatabase reports whether the database is in the
// curated identity-authoritative set.
func IsSecurityCriticalDatabase(d Database) bool {
	for _, c := range SecurityCriticalDatabases() {
		if c == d {
			return true
		}
	}
	return false
}

// NormalizeDatabase maps a raw database token to our enum. Unknown
// names collapse to DatabaseUnknown.
func NormalizeDatabase(s string) Database {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passwd":
		return DatabasePasswd
	case "shadow":
		return DatabaseShadow
	case "group":
		return DatabaseGroup
	case "hosts":
		return DatabaseHosts
	case "services":
		return DatabaseServices
	case "networks":
		return DatabaseNetworks
	case "protocols":
		return DatabaseProtocols
	case "rpc":
		return DatabaseRPC
	case "ethers":
		return DatabaseEthers
	case "netmasks":
		return DatabaseNetmasks
	case "bootparams":
		return DatabaseBootparams
	case "netgroup":
		return DatabaseNetgroup
	case "automount":
		return DatabaseAutomount
	case "aliases":
		return DatabaseAliases
	case "publickey":
		return DatabasePublickey
	case "gshadow":
		return DatabaseGshadow
	case "sudoers":
		return DatabaseSudoers
	case "initgroups":
		return DatabaseInitgroups
	}
	return DatabaseUnknown
}

// LocalSources is the set of NSS sources that resolve from on-disk
// state without traversing the network. Anything else flips
// HasNonLocalSource=true.
func LocalSources() []string {
	return []string{
		"files",
		"compat",
		"db",
		"cache",
		"myhostname",
		"myhostnames",
		"resolve",
	}
}

// IsLocalSource reports whether the source name resolves locally.
func IsLocalSource(name string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, l := range LocalSources() {
		if l == want {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on an entry row from
// its parsed sources slice.
func AnnotateSecurity(e *Entry) {
	e.IsSecurityCritical = IsSecurityCriticalDatabase(e.Database)
	e.HasNonLocalSource = false
	e.IsFilesMissing = true
	e.IsFilesLast = false
	if len(e.Sources) == 0 {
		return
	}
	for i, src := range e.Sources {
		if !IsLocalSource(src) {
			e.HasNonLocalSource = true
		}
		if strings.EqualFold(src, "files") || strings.EqualFold(src, "compat") {
			e.IsFilesMissing = false
			// `files` last means at least one non-local source consults
			// the network before the local fallback.
			if i == len(e.Sources)-1 && len(e.Sources) > 1 {
				e.IsFilesLast = true
			}
		}
	}
}

// SortEntries returns a deterministic ordering: file path, then line.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		return es[i].LineNo < es[j].LineNo
	})
}
