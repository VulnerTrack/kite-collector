// Package pam parses /etc/pam.d/* + /etc/pam.conf into a per-host,
// row-per-directive inventory. The grammar is documented in pam.conf(5)
// — we implement enough of it to extract the high-signal security
// fields without trying to evaluate the actual stack (that would require
// importing PAM's runtime semantics including [list-of-key=val] control
// flow).
//
// MITRE ATT&CK T1556.003 (Modify Authentication Process: Pluggable
// Authentication Modules) is the headline technique this collector
// inventories. A single line modification in /etc/pam.d/sshd —
// `auth sufficient pam_permit.so` — bypasses every SSH password check.
// The file change is invisible to EDR; this collector turns it into a
// per-scan row whose hash drives drift detection.
//
// Every collector is **read-only** — it parses PAM files, never invokes
// pam-auth-update or modifies anything.
//
// Rows feed the audit pipeline:
//
//   - T1556.003 — `is_unconditional_pass=1` flags `pam_permit.so` in
//     the auth stack. Always a critical finding outside Live-CD environments.
//   - CWE-521 (Weak Password Requirements) — `is_nullok=1` on pam_unix
//     allows empty passwords.
//   - CWE-829 (Untrusted Functionality) — `is_nonstandard_path=1`
//     flags PAM modules loaded from outside /usr/lib + /lib.
//   - Drift events — every `file_hash` change on /etc/pam.d/* is an
//     auth-policy modification event.
package pam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxDirectives bounds per-scan output. A typical /etc/pam.d tree has
// 20-50 files × 5-15 lines each → 100-750 directives. The 4096 ceiling
// protects the SQLite write path.
const MaxDirectives = 4096

// Type classifies the PAM stack the directive participates in. Pinned
// to the host_pam_configs.type CHECK enum.
type Type string

const (
	TypeAuth     Type = "auth"     // credential collection + verification
	TypeAccount  Type = "account"  // account/policy checks (locked, expired)
	TypeSession  Type = "session"  // pre/post session work (mount homedirs)
	TypePassword Type = "password" // password-change checks
	TypeInclude  Type = "include"  // `@include otherfile`
	TypeSubstack Type = "substack" // `substack otherfile`
	TypeUnknown  Type = "unknown"
)

// Directive is the parsed record produced per non-comment PAM line.
// Mirrors host_pam_configs' column shape exactly.
type Directive struct {
	Module              string   `json:"module"`
	ModulePath          string   `json:"module_path,omitempty"`
	Service             string   `json:"service"`
	Type                Type     `json:"type"`
	Control             string   `json:"control"`
	FilePath            string   `json:"file_path"`
	FileHash            string   `json:"file_hash"`
	RawLine             string   `json:"raw_line,omitempty"`
	Arguments           []string `json:"arguments,omitempty"`
	LineNo              int      `json:"line_no"`
	ShortCircuitsStack  bool     `json:"short_circuits_stack"`
	IsNonstandardPath   bool     `json:"is_nonstandard_path"`
	IsNullok            bool     `json:"is_nullok"`
	IsUnconditionalPass bool     `json:"is_unconditional_pass"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Directive, error)
}

// EncodeStringList returns a JSON array suitable for arguments_json.
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

// HashContents returns the SHA-256 hex of a file's contents. Stable
// across rescans; the natural key for drift detection.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// UnconditionalPassModules is the curated list of PAM modules that
// always succeed regardless of input. Their presence in an `auth` or
// `account` stack is a T1556.003 finding.
//
//   - pam_permit.so:    always returns PAM_SUCCESS — bypass primitive.
//   - pam_succeed_if.so without conditions is also dangerous, but it
//     requires argument analysis; we don't flag it via this helper.
func UnconditionalPassModules() []string {
	return []string{"pam_permit.so"}
}

// IsUnconditionalPassModule reports whether the module name always
// succeeds. Used to set the indexed `is_unconditional_pass` column.
func IsUnconditionalPassModule(module string) bool {
	for _, m := range UnconditionalPassModules() {
		if m == module {
			return true
		}
	}
	return false
}

// IsStandardModulePath reports whether the absolute path points into
// the OS-distributed PAM module directories. PAM modules outside these
// trees are CWE-829 candidates.
func IsStandardModulePath(path string) bool {
	if path == "" {
		// Empty path means the module was referenced by bare name
		// (e.g. `pam_unix.so`), which PAM resolves from the system
		// search path — considered safe.
		return true
	}
	switch {
	case strings.HasPrefix(path, "/usr/lib/"),
		strings.HasPrefix(path, "/lib/"),
		strings.HasPrefix(path, "/usr/local/lib/security/"),
		strings.HasPrefix(path, "/usr/lib64/"):
		return true
	}
	return false
}

// SortDirectives returns a deterministic ordering: file path, then line.
func SortDirectives(ds []Directive) {
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].FilePath != ds[j].FilePath {
			return ds[i].FilePath < ds[j].FilePath
		}
		return ds[i].LineNo < ds[j].LineNo
	})
}
