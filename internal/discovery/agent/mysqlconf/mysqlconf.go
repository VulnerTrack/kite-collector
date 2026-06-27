// Package mysqlconf inventories MySQL / MariaDB server configuration
// from the canonical my.cnf chain — /etc/mysql/my.cnf, /etc/my.cnf,
// drop-in directories, and the per-user ~/.my.cnf. Every [section]
// becomes its own row so the audit pipeline can attribute a finding
// to the right physical file.
//
// The shape of the file is INI-with-extras (per the mysql/mariadb
// manuals):
//
//	# comment    or    ; comment
//	[section-name]
//	    key = value
//	    boolean-shortcut          # equivalent to `boolean-shortcut = 1`
//	    !include /etc/mysql/conf.d/local.cnf
//	    !includedir /etc/mysql/conf.d/
//
// Headline finding shapes (per MySQL Server reference manual and
// CIS-MySQL-Benchmark v8):
//
//   - `skip-grant-tables` in any [mysqld] section = the privilege
//     subsystem is off. Any TCP/socket connect lands as root
//     (CWE-306 + T1190 + T1078.003).
//   - `local_infile = ON` + a malicious client = arbitrary file
//     disclosure of anything mysqld can read (CWE-552 / CVE-2017-3306
//     family). MySQL 8 defaults to OFF; MariaDB 10.x ON.
//   - `secure_file_priv` empty / unset / "" = LOAD DATA, SELECT INTO
//     OUTFILE and UDF-write-then-load all unconstrained (CWE-732).
//   - `require_secure_transport = OFF` + non-loopback bind =
//     plaintext SQL on the wire (CWE-319).
//   - `[client] password = …` in a world- or group-readable file =
//     credentials-in-file (CWE-256 / T1552.001).
//
// Read-only by intent — we parse my.cnf files only, never invoke
// mysql / mysqladmin. (Project guideline 4.2.)
package mysqlconf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical install has 3-8 sections
// across 1-4 files; the 512 ceiling covers heavyweight per-vhost
// MariaDB deployments without bloating SQLite writes.
const MaxRows = 512

// SectionKind classifies a [section] header. Pinned to the
// host_mysql_config.section_kind CHECK enum.
type SectionKind string

const (
	SectionServer  SectionKind = "server"
	SectionClient  SectionKind = "client"
	SectionCommon  SectionKind = "common"
	SectionUnknown SectionKind = "unknown"
)

// Row mirrors host_mysql_config's column shape exactly.
type Row struct {
	GeneralLog                    string      `json:"general_log,omitempty"`
	SocketPath                    string      `json:"socket_path,omitempty"`
	SectionName                   string      `json:"section_name"`
	SectionKind                   SectionKind `json:"section_kind"`
	BindAddress                   string      `json:"bind_address,omitempty"`
	FilePath                      string      `json:"file_path"`
	LogErrorPath                  string      `json:"log_error_path,omitempty"`
	Datadir                       string      `json:"datadir,omitempty"`
	UserName                      string      `json:"user_name,omitempty"`
	SecureFilePriv                string      `json:"secure_file_priv,omitempty"`
	FileHash                      string      `json:"file_hash"`
	TLSVersion                    string      `json:"tls_version,omitempty"`
	PluginLoad                    string      `json:"plugin_load,omitempty"`
	Port                          int         `json:"port,omitempty"`
	IsNameResolveSkipped          bool        `json:"is_name_resolve_skipped"`
	IsGrantTablesSkipped          bool        `json:"is_grant_tables_skipped"`
	IsNetworkingSkipped           bool        `json:"is_networking_skipped"`
	IsLocalInfileEnabled          bool        `json:"is_local_infile_enabled"`
	HasUnrestrictedSecureFilePriv bool        `json:"has_unrestricted_secure_file_priv"`
	IsSecureTransportRequired     bool        `json:"is_secure_transport_required"`
	IsExternallyBound             bool        `json:"is_externally_bound"`
	IsBoundToLoopbackOnly         bool        `json:"is_bound_to_loopback_only"`
	HasCleartextClientPassword    bool        `json:"has_cleartext_client_password"`
	IsUnauthenticatedWorldExposed bool        `json:"is_unauthenticated_world_exposed"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of a my.cnf body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeSectionKind maps a [section] header to our enum. MySQL
// recognises a few server-side names alongside per-version variants:
//
//	[mysqld]            - the canonical server
//	[mariadb], [mariadbd], [mariadb-10.6] - MariaDB equivalents
//	[mysqld-5.7], [mysqld-8.0] - per-version overrides
//	[client], [mysql], [mysqldump] - client-side
//	[client-server], [client-mariadb] - shared keys
func NormalizeSectionKind(s string) SectionKind {
	name := strings.ToLower(strings.TrimSpace(s))
	if name == "" {
		return SectionUnknown
	}
	switch name {
	case "mysqld", "mariadb", "mariadbd", "server":
		return SectionServer
	case "client", "mysql", "mysqldump", "mysqlhotcopy", "mysqladmin",
		"mysqlcheck", "mysqlimport", "mysqlshow":
		return SectionClient
	case "client-server", "client-mariadb":
		return SectionCommon
	}
	switch {
	case strings.HasPrefix(name, "mysqld-") || strings.HasPrefix(name, "mariadb-") ||
		strings.HasPrefix(name, "mariadbd-"):
		return SectionServer
	}
	return SectionUnknown
}

// IsLoopbackAddress reports whether a bind-address value resolves to
// the loopback interface. Empty / "*" / "0.0.0.0" all flag as NOT
// loopback — MySQL listens on every interface in those cases.
func IsLoopbackAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "*" {
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

// IsExternalBind reports whether bind-address resolves to a non-
// loopback (or unset, which means listen on every interface).
func IsExternalBind(addr string) bool {
	return !IsLoopbackAddress(addr)
}

// IsLoopbackOnly reports whether bind-address resolves to ONLY the
// loopback interface — i.e. set, non-empty, and loopback.
func IsLoopbackOnly(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	return IsLoopbackAddress(addr)
}

// IsUnrestrictedSecureFilePriv reports whether secure_file_priv is
// configured to allow unconstrained file IO. Both "" (the empty
// string) and an unset value (caller passes "" too) leave LOAD DATA
// and SELECT INTO OUTFILE wide open. "NULL" / "null" mean the
// feature is fully disabled — the safest setting.
//
// The function takes BOTH the parsed value AND a "was-set" boolean,
// because the security implication of an unset directive depends on
// the MySQL/MariaDB default (MySQL 8: /var/lib/mysql-files/, MariaDB:
// unset = empty = unrestricted).
func IsUnrestrictedSecureFilePriv(val string, wasSet bool) bool {
	v := strings.ToLower(strings.TrimSpace(val))
	if !wasSet {
		return true
	}
	if v == "" {
		return true
	}
	if v == "null" {
		return false
	}
	return false
}

// IsBoolTrue maps the MySQL grammar's boolean accent — ON / OFF /
// TRUE / FALSE / YES / NO / 1 / 0 — to Go bool.
func IsBoolTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Row that has its
// raw fields populated.
func AnnotateSecurity(r *Row) {
	if r.SectionKind == SectionServer {
		r.IsBoundToLoopbackOnly = IsLoopbackOnly(r.BindAddress)
		r.IsExternallyBound = IsExternalBind(r.BindAddress)
		r.IsUnauthenticatedWorldExposed = r.IsExternallyBound &&
			r.IsGrantTablesSkipped
	}
}

// SortRows returns a deterministic ordering by file path, then
// section name.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		return rs[i].SectionName < rs[j].SectionName
	})
}
