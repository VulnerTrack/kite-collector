// Package sudoers parses /etc/sudoers + /etc/sudoers.d/* into a
// per-host row-per-grant inventory. The grammar is documented in
// sudoers(5); we implement enough of it to extract the high-signal
// security fields (NOPASSWD, ALL=(ALL) ALL, env_keep, timestamp_timeout)
// without trying to mimic sudo's own visudo parser.
//
// MITRE ATT&CK T1548.003 (Abuse Elevation Control Mechanism: Sudo and
// Sudo Caching) is the headline technique this collector inventories.
// A single `alice ALL=(ALL) NOPASSWD: ALL` line is invisible to EDR
// until alice (or anyone who steals alice's session) actually runs sudo
// — by then it's too late.
//
// Every collector is **read-only** — it parses sudoers files, never
// invokes `visudo` or modifies anything. Read-only is enforced by
// guideline 4.2.
//
// Rows feed the CWE/CAPEC + ATT&CK audit pipeline:
//
//   - T1548.003 — `is_passwordless=1` is a persistence + privilege
//     escalation primitive. Combined with `is_total_privilege=1` it's
//     unrestricted root with no auth.
//   - CWE-269 (Improper Privilege Management) — `ALL=(ALL:ALL) ALL`
//     grants without command restriction.
//   - CWE-526 (Exposure Through Environmental Variables) —
//     `env_keep += "..."` Defaults widen the env-var passthrough.
//   - Drift events — `file_hash` change between scans on any sudoers
//     file is a security-policy modification event.
package sudoers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// MaxEntries bounds per-scan output. A real /etc/sudoers + drop-ins
// typically yields 5-50 entries; misconfigured generators have produced
// hundreds. The 4096 ceiling protects the SQLite write path.
const MaxEntries = 4096

// EntryType classifies the sudoers line. Pinned to the
// host_sudoers.entry_type CHECK enum.
type EntryType string

const (
	EntryUserSpec   EntryType = "user-spec"   // "alice ALL=(ALL) NOPASSWD: ALL"
	EntryDefaults   EntryType = "defaults"    // "Defaults timestamp_timeout=30"
	EntryUserAlias  EntryType = "user-alias"  // "User_Alias DEVS = alice, bob"
	EntryRunasAlias EntryType = "runas-alias" // "Runas_Alias OP = root, operator"
	EntryHostAlias  EntryType = "host-alias"  // "Host_Alias WEB = web1, web2"
	EntryCmndAlias  EntryType = "cmnd-alias"  // "Cmnd_Alias SOFTWARE = /usr/bin/apt"
	EntryInclude    EntryType = "include"     // "@includedir /etc/sudoers.d"
	EntryUnknown    EntryType = "unknown"
)

// Entry is the cross-form record produced by the parser. Mirrors
// host_sudoers' column shape.
type Entry struct {
	DefaultsKey        string    `json:"defaults_key,omitempty"`
	FileHash           string    `json:"file_hash"`
	RawLine            string    `json:"raw_line,omitempty"`
	EntryType          EntryType `json:"entry_type"`
	Principal          string    `json:"principal,omitempty"`
	RunasUser          string    `json:"runas_user,omitempty"`
	RunasGroup         string    `json:"runas_group,omitempty"`
	Hosts              string    `json:"hosts,omitempty"`
	FilePath           string    `json:"file_path"`
	IncludesPath       string    `json:"includes_path,omitempty"`
	AliasName          string    `json:"alias_name,omitempty"`
	DefaultsValue      string    `json:"defaults_value,omitempty"`
	Commands           []string  `json:"commands,omitempty"`
	AliasMembers       []string  `json:"alias_members,omitempty"`
	Tags               []string  `json:"tags,omitempty"`
	LineNo             int       `json:"line_no"`
	IsDangerousDefault bool      `json:"is_dangerous_default"`
	IsTotalPrivilege   bool      `json:"is_total_privilege"`
	IsPasswordless     bool      `json:"is_passwordless"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// EncodeStringList returns a JSON array suitable for *_json columns.
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

// HashContents returns the SHA-256 hex of file contents. Stable across
// rescans; the natural key for drift detection.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DangerousDefaults is the curated list of Defaults keys whose presence
// (or modification) is a security finding. The audit pipeline does the
// full lookup against its policy catalogue; this is the on-host
// pre-filter for fast-path indexing.
//
//   - env_keep:   widens the env-var passthrough across sudo (CWE-526)
//   - env_reset:  when disabled (env_reset=0), all env vars pass through
//   - secure_path: when missing, sudo respects the user's $PATH (CWE-426)
//   - !requiretty: removes the TTY requirement (eases automated abuse)
//   - !lecture:   disables the warning banner (small UX flag)
//   - timestamp_timeout: ≥ 30 minutes is the ticket-reuse window
//   - tty_tickets: when disabled, sudo tickets cross TTY boundaries
func DangerousDefaults() []string {
	return []string{
		"env_keep", "env_reset", "secure_path",
		"requiretty", "timestamp_timeout", "tty_tickets",
		"passwd_timeout", "use_pty",
	}
}

// IsDangerousDefault reports whether a Defaults key is in the curated
// security-relevant list. Used to set the partial-index column.
func IsDangerousDefault(key string) bool {
	for _, k := range DangerousDefaults() {
		if k == key {
			return true
		}
	}
	return false
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
