// Package pghba inventories PostgreSQL pg_hba.conf — the file that
// controls who can connect to a Postgres instance from where, with
// what authentication method.
//
// pg_hba.conf is one of the highest-leverage security configs on
// any Postgres host: a single line of `host all all 0.0.0.0/0 trust`
// turns the database into a public, unauthenticated read/write data
// source. Inventorying it row-by-row lets the audit pipeline answer:
//
//   - Are there `trust` lines outside the local Unix socket? (CWE-306)
//   - Are non-SCRAM auth methods (`md5`, `password`, `peer`, `ident`)
//     still in use? (CWE-326 with SCRAM-SHA-256 as the baseline)
//   - Is any rule open to the public internet (0.0.0.0/0 or ::/0)?
//     Combined with weak auth that's a CWE-285 finding.
//   - Are there replication grants (`database='replication'`) that
//     would let an attacker stream the primary off-host?
//
// Every collector is **read-only by intent** — it parses pg_hba.conf
// files, never reloads PostgreSQL or `ALTER ROLE`s anything. Read-only
// is enforced by guideline 4.2 of the kite-collector project.
package pghba

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A heavyweight production
// pg_hba.conf has 40-120 entries; the 1024 ceiling covers
// multi-tenant clusters with per-tenant role grants.
const MaxRows = 1024

// ConnectionType identifies the transport. Pinned to the
// host_pg_hba.connection_type CHECK enum.
type ConnectionType string

const (
	ConnectionLocal        ConnectionType = "local"
	ConnectionHost         ConnectionType = "host"
	ConnectionHostSSL      ConnectionType = "hostssl"
	ConnectionHostNoSSL    ConnectionType = "hostnossl"
	ConnectionHostGSSEnc   ConnectionType = "hostgssenc"
	ConnectionHostNoGSSEnc ConnectionType = "hostnogssenc"
	ConnectionUnknown      ConnectionType = "unknown"
)

// Method identifies the authentication method. Pinned to the
// host_pg_hba.method CHECK enum.
type Method string

const (
	MethodTrust       Method = "trust"
	MethodReject      Method = "reject"
	MethodMD5         Method = "md5"
	MethodSCRAMSHA256 Method = "scram-sha-256"
	MethodPassword    Method = "password"
	MethodGSS         Method = "gss"
	MethodSSPI        Method = "sspi"
	MethodIdent       Method = "ident"
	MethodPeer        Method = "peer"
	MethodLDAP        Method = "ldap"
	MethodRadius      Method = "radius"
	MethodCert        Method = "cert"
	MethodPAM         Method = "pam"
	MethodBSD         Method = "bsd"
	MethodUnknown     Method = "unknown"
)

// Row mirrors host_pg_hba's column shape exactly.
type Row struct {
	Method            Method         `json:"method"`
	Options           string         `json:"options,omitempty"`
	Address           string         `json:"address,omitempty"`
	RawLine           string         `json:"raw_line,omitempty"`
	ConnectionType    ConnectionType `json:"connection_type"`
	Database          string         `json:"database,omitempty"`
	FileHash          string         `json:"file_hash"`
	DBRole            string         `json:"db_role,omitempty"`
	FilePath          string         `json:"file_path"`
	LineNo            int            `json:"line_no"`
	IsTrust           bool           `json:"is_trust"`
	IsReject          bool           `json:"is_reject"`
	IsWeakMethod      bool           `json:"is_weak_method"`
	IsInternetExposed bool           `json:"is_internet_exposed"`
	IsReplication     bool           `json:"is_replication"`
	IsWideOpen        bool           `json:"is_wide_open"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of a pg_hba.conf body.
// Drives drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeConnectionType maps a token to our enum. Unknown values
// collapse to ConnectionUnknown.
func NormalizeConnectionType(s string) ConnectionType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "local":
		return ConnectionLocal
	case "host":
		return ConnectionHost
	case "hostssl":
		return ConnectionHostSSL
	case "hostnossl":
		return ConnectionHostNoSSL
	case "hostgssenc":
		return ConnectionHostGSSEnc
	case "hostnogssenc":
		return ConnectionHostNoGSSEnc
	}
	return ConnectionUnknown
}

// NormalizeMethod maps the auth-method token to our enum.
func NormalizeMethod(s string) Method {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trust":
		return MethodTrust
	case "reject":
		return MethodReject
	case "md5":
		return MethodMD5
	case "scram-sha-256":
		return MethodSCRAMSHA256
	case "password":
		return MethodPassword
	case "gss":
		return MethodGSS
	case "sspi":
		return MethodSSPI
	case "ident":
		return MethodIdent
	case "peer":
		return MethodPeer
	case "ldap":
		return MethodLDAP
	case "radius":
		return MethodRadius
	case "cert":
		return MethodCert
	case "pam":
		return MethodPAM
	case "bsd":
		return MethodBSD
	}
	return MethodUnknown
}

// WeakMethods is the curated set of auth methods considered weak
// under modern threat models. SCRAM-SHA-256 / cert / GSS / LDAP /
// PAM / RADIUS are the modern baseline; `trust` is its own category
// (no-auth — even worse than weak).
func WeakMethods() []Method {
	return []Method{MethodMD5, MethodPassword, MethodIdent, MethodPeer}
}

// IsWeakMethod reports whether the method is in the curated weak set.
func IsWeakMethod(m Method) bool {
	for _, w := range WeakMethods() {
		if w == m {
			return true
		}
	}
	return false
}

// IsInternetExposedAddress reports whether the address field opens
// the rule to the public internet. We handle:
//   - "0.0.0.0/0" or "::/0" — explicit any-host CIDR
//   - "all" — pg_hba's wildcard token
//   - A CIDR whose mask is /0 (whatever family)
//
// We do NOT flag bare hostnames or RFC1918 CIDRs.
func IsInternetExposedAddress(address string) bool {
	v := strings.ToLower(strings.TrimSpace(address))
	switch v {
	case "0.0.0.0/0", "::/0", "all":
		return true
	}
	if _, ipnet, err := net.ParseCIDR(v); err == nil && ipnet != nil {
		ones, _ := ipnet.Mask.Size()
		if ones == 0 {
			return true
		}
	}
	return false
}

// IsReplicationDB reports whether the database token claims the
// virtual "replication" pseudo-DB, which grants streaming-replication
// rights.
func IsReplicationDB(db string) bool {
	for _, item := range strings.Split(db, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "replication") {
			return true
		}
	}
	return false
}

// IsAll reports whether the comma-separated list contains the
// `all` wildcard token.
func IsAll(s string) bool {
	for _, item := range strings.Split(s, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "all") {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on a row from its
// already-populated fields. Centralised so the flags don't drift
// between sources.
func AnnotateSecurity(r *Row) {
	r.IsTrust = r.Method == MethodTrust
	r.IsReject = r.Method == MethodReject
	r.IsWeakMethod = IsWeakMethod(r.Method)
	r.IsInternetExposed = r.ConnectionType != ConnectionLocal &&
		IsInternetExposedAddress(r.Address)
	r.IsReplication = IsReplicationDB(r.Database)
	// "Wide open" = the rule covers all databases AND all users AND
	// is reachable from the internet — the worst single-line shape.
	r.IsWideOpen = r.IsInternetExposed && IsAll(r.Database) && IsAll(r.DBRole)
}

// SortRows returns a deterministic ordering: file path, then line.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		return rs[i].LineNo < rs[j].LineNo
	})
}
