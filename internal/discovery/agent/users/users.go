// Package users enumerates local user accounts across Linux, macOS,
// Windows, and the BSDs. Source attribution distinguishes purely local
// accounts (/etc/passwd, Windows SAM) from directory-synced ones
// (AD via SSSD, OpenLDAP, Entra Cloud Sync).
//
// Every collector is **read-only** — it queries user databases, never
// useradd / userdel / passwd / chage / net user / dscl -create. Read-only
// is enforced by guideline 4.2 of the kite-collector project.
//
// HostUser rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-1004 (Sensitive Default Account) — `is_admin=1` accounts other
//     than the OS-provided root/Administrator deserve scrutiny.
//   - CWE-862 (Missing Authorization) — service account with an
//     interactive shell (`is_interactive=1`) when it should be /sbin/nologin.
//   - CWE-521 (Weak Password Requirements) — `password_status='active'`
//     with stale `password_age_days` against the configured policy.
//
// Pairs with the Processes collector: process.username → host_users.username
// answers "what processes is each user running right now".
package users

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// MaxUsers bounds per-scan output. A laptop has 20-50 local users (many
// system accounts); a directory-joined host with cached AD users can
// exceed 1000. The 4096 ceiling protects the SQLite write path.
const MaxUsers = 4096

// Source classifies where the user's authoritative record lives.
// Strings are pinned to the host_users.source CHECK enum.
type Source string

const (
	SourceLocal         Source = "local"
	SourceAD            Source = "ad"
	SourceLDAP          Source = "ldap"
	SourceAzureAD       Source = "azure-ad"
	SourceSSSD          Source = "sssd"
	SourceOpenDirectory Source = "open-directory"
	SourceUnknown       Source = "unknown"
)

// PasswordStatus is the credential state. Pinned to the
// host_users.password_status CHECK enum.
type PasswordStatus string

const (
	PasswordActive     PasswordStatus = "active"
	PasswordLocked     PasswordStatus = "locked"
	PasswordExpired    PasswordStatus = "expired"
	PasswordDisabled   PasswordStatus = "disabled"
	PasswordNoPassword PasswordStatus = "no-password"
	PasswordUnknown    PasswordStatus = "unknown"
)

// User is the cross-platform record produced by every collector. Mirrors
// the host_users column shape.
type User struct {
	Username        string         `json:"username"`
	UID             string         `json:"uid"` // numeric on Unix, SID on Windows
	PrimaryGID      string         `json:"primary_gid,omitempty"`
	FullName        string         `json:"full_name,omitempty"`
	Home            string         `json:"home,omitempty"`
	Shell           string         `json:"shell,omitempty"`
	Source          Source         `json:"source"`
	PasswordStatus  PasswordStatus `json:"password_status"`
	LastLoginAt     string         `json:"last_login_at,omitempty"`
	Groups          []string       `json:"groups,omitempty"`
	PasswordAgeDays int            `json:"password_age_days,omitempty"`
	IsAdmin         bool           `json:"is_admin"`
	IsInteractive   bool           `json:"is_interactive"`
	IsLocked        bool           `json:"is_locked"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry.
	Name() string
	// Collect enumerates users. Read-only. Returns empty slice when no
	// source is available (restricted container, missing /etc/passwd).
	Collect(ctx context.Context) ([]User, error)
}

// EncodeGroups returns a JSON array suitable for the groups_json column.
// Empty input emits "[]" so the column is never NULL.
func EncodeGroups(gs []string) string {
	if len(gs) == 0 {
		return "[]"
	}
	b, err := json.Marshal(gs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// IsInteractiveShell reports whether a shell path indicates an interactive
// login is possible. The /sbin/nologin and /bin/false conventions are
// universal across Unix; everything else is treated as interactive.
//
// macOS uses /usr/bin/false for system accounts; we cover both.
func IsInteractiveShell(shell string) bool {
	switch {
	case shell == "",
		strings.HasSuffix(shell, "/nologin"),
		strings.HasSuffix(shell, "/false"),
		shell == "/dev/null":
		return false
	}
	return true
}

// IsAdminUID reports whether a numeric uid is the root account (uid 0).
// Conservative — only true for the literal "0" string. Higher-uid
// privilege comes from group membership (sudo / wheel / admin).
func IsAdminUID(uid string) bool {
	return uid == "0"
}

// AdminGroups returns the set of group names that grant admin privileges
// on Unix-like systems. wheel = BSD/macOS convention, sudo = Debian/
// Ubuntu, admin = legacy macOS, root = some hardened distros.
func AdminGroups() []string {
	return []string{"wheel", "sudo", "admin", "root"}
}

// IsAdminGroup reports whether a group name grants admin privileges.
func IsAdminGroup(group string) bool {
	for _, g := range AdminGroups() {
		if g == group {
			return true
		}
	}
	return false
}

// SortUsers returns a deterministic ordering: by source then UID.
func SortUsers(us []User) {
	sort.Slice(us, func(i, j int) bool {
		if us[i].Source != us[j].Source {
			return us[i].Source < us[j].Source
		}
		// Numeric UID compare when both are numeric; lexical otherwise.
		ai, aok := atoi(us[i].UID)
		bi, bok := atoi(us[j].UID)
		if aok && bok {
			return ai < bi
		}
		return us[i].UID < us[j].UID
	})
}

// atoi is a tiny dep-free parser — returns (value, true) on success.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
