// Package launchd inventories macOS launchd service definitions
// (LaunchDaemons and LaunchAgents). Every plist that lives under one
// of these directories represents code launchd will start on the
// system's behalf:
//
//	/Library/LaunchDaemons         — root, system-wide, runs at boot
//	/Library/LaunchAgents          — user session, runs at login
//	/System/Library/LaunchDaemons  — Apple-shipped daemons
//	/System/Library/LaunchAgents   — Apple-shipped agents
//	~/Library/LaunchAgents         — per-user agents
//
// The canonical persistence finding shapes (MITRE T1543.004 / T1547.011):
//
//   - Plist owned by non-root *or writable by other* in
//     /Library/LaunchDaemons → any local user can rewrite the file
//     and inject code at next boot (CWE-732).
//   - Program path under /tmp, /Users/Shared, /private/var/folders →
//     world-writable execution target (CWE-426).
//   - Non-Apple label running as root with RunAtLoad=true → unsigned
//     third-party persistence; alert verbatim (CWE-269).
//
// Read-only by intent — we parse the plist XML, never run
// launchctl. (Project guideline 4.2.)
package launchd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// MaxServices bounds per-scan output. A loaded macOS host carries
// roughly 200-400 active launchd services across the three scopes;
// the 4096 ceiling covers heavily-customised dev workstations.
const MaxServices = 4096

// PlistScope tags where the plist lives. Pinned to the
// host_launch_services.plist_scope CHECK enum.
type PlistScope string

const (
	ScopeSystemDaemon PlistScope = "system-daemon"
	ScopeSystemAgent  PlistScope = "system-agent"
	ScopeUserAgent    PlistScope = "user-agent"
	ScopeUnknown      PlistScope = "unknown"
)

// Service mirrors host_launch_services' column shape exactly.
type Service struct {
	GroupName                   string     `json:"group_name,omitempty"`
	FileHash                    string     `json:"file_hash"`
	PlistScope                  PlistScope `json:"plist_scope"`
	Label                       string     `json:"label"`
	LabelDomain                 string     `json:"label_domain,omitempty"`
	Program                     string     `json:"program,omitempty"`
	UserName                    string     `json:"user_name,omitempty"`
	FilePath                    string     `json:"file_path"`
	WorkingDirectory            string     `json:"working_directory,omitempty"`
	StandardOutPath             string     `json:"standard_out_path,omitempty"`
	StandardErrorPath           string     `json:"standard_error_path,omitempty"`
	ProgramArguments            []string   `json:"program_arguments,omitempty"`
	WatchPaths                  []string   `json:"watch_paths,omitempty"`
	FileMode                    int        `json:"file_mode,omitempty"`
	StartIntervalSeconds        int        `json:"start_interval_seconds,omitempty"`
	FileOwnerUID                int        `json:"file_owner_uid,omitempty"`
	FileOwnerGID                int        `json:"file_owner_gid,omitempty"`
	HasStartCalendarInterval    bool       `json:"has_start_calendar_interval"`
	IsRunAtLoad                 bool       `json:"is_run_at_load"`
	IsKeepAlive                 bool       `json:"is_keep_alive"`
	IsDisabled                  bool       `json:"is_disabled"`
	HasWatchPaths               bool       `json:"has_watch_paths"`
	RunsAsRoot                  bool       `json:"runs_as_root"`
	IsAppleSignedDomain         bool       `json:"is_apple_signed_domain"`
	IsPlistOwnedByRoot          bool       `json:"is_plist_owned_by_root"`
	IsPlistWritableByGroup      bool       `json:"is_plist_writable_by_group"`
	IsPlistWritableByOther      bool       `json:"is_plist_writable_by_other"`
	IsProgramInWorldWritableDir bool       `json:"is_program_in_world_writable_dir"`
	IsPersistentThirdPartyRoot  bool       `json:"is_persistent_third_party_root"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Service, error)
}

// HashContents returns the SHA-256 hex of a plist body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LabelDomain returns the dotted-reverse-domain prefix of a service
// label. `com.apple.Spotlight` → `com.apple`. Labels without at least
// two segments return the full label.
func LabelDomain(label string) string {
	label = strings.TrimSpace(label)
	parts := strings.Split(label, ".")
	if len(parts) < 2 {
		return label
	}
	return parts[0] + "." + parts[1]
}

// IsAppleSignedDomain reports whether a label belongs to one of
// Apple's reserved persistence domains. Used to filter out the noise
// of OS-shipped LaunchDaemons from third-party persistence.
func IsAppleSignedDomain(label string) bool {
	dom := strings.ToLower(LabelDomain(label))
	switch dom {
	case "com.apple", "com.openssh", "org.cups":
		return true
	}
	return false
}

// WorldWritableDirRoots is the curated set of directory prefixes
// that any local user can write into. Program paths under these
// trigger the world-writable finding.
func WorldWritableDirRoots() []string {
	return []string{
		"/tmp/",
		"/var/tmp/",
		"/private/tmp/",
		"/private/var/tmp/",
		"/Users/Shared/",
		"/private/var/folders/",
	}
}

// IsProgramInWorldWritableDir reports whether a Program path roots
// under one of the curated world-writable directories. Empty path
// returns false.
func IsProgramInWorldWritableDir(program string) bool {
	p := strings.TrimSpace(program)
	if p == "" {
		return false
	}
	clean := filepath.Clean(p)
	for _, root := range WorldWritableDirRoots() {
		if strings.HasPrefix(clean, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// IsRootUser reports whether a UserName value resolves to root —
// either the literal `root` or uid 0 written as a string.
func IsRootUser(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	return v == "root" || v == "0"
}

// PlistScopeFromPath maps a plist's directory to the appropriate
// PlistScope value. Anything under `~/Library/LaunchAgents` is a
// user-agent, anything under `/Library/LaunchDaemons` (or System
// counterpart) is a system-daemon, etc.
func PlistScopeFromPath(path string) PlistScope {
	p := filepath.Clean(path)
	dir := filepath.Dir(p)
	switch {
	case strings.HasSuffix(dir, "/LaunchDaemons") &&
		(strings.HasPrefix(dir, "/Library/") ||
			strings.HasPrefix(dir, "/System/Library/")):
		return ScopeSystemDaemon
	case strings.HasSuffix(dir, "/LaunchAgents") &&
		(strings.HasPrefix(dir, "/Library/") ||
			strings.HasPrefix(dir, "/System/Library/")):
		return ScopeSystemAgent
	case strings.Contains(dir, "/Library/LaunchAgents"):
		return ScopeUserAgent
	}
	return ScopeUnknown
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

// AnnotateSecurity sets the derived booleans on a Service that has
// its raw fields populated.
func AnnotateSecurity(s *Service) {
	s.LabelDomain = LabelDomain(s.Label)
	s.IsAppleSignedDomain = IsAppleSignedDomain(s.Label)
	// Default for a launchd plist with no explicit UserName: root for
	// daemons, the session user for agents. We can't know the session
	// user here, so we only flag the daemon case.
	if s.UserName == "" && s.PlistScope == ScopeSystemDaemon {
		s.RunsAsRoot = true
	} else {
		s.RunsAsRoot = IsRootUser(s.UserName)
	}
	s.IsProgramInWorldWritableDir = IsProgramInWorldWritableDir(s.Program)
	if len(s.ProgramArguments) > 0 && !s.IsProgramInWorldWritableDir {
		s.IsProgramInWorldWritableDir = IsProgramInWorldWritableDir(s.ProgramArguments[0])
	}
	s.HasWatchPaths = len(s.WatchPaths) > 0
	if s.FileMode != 0 {
		s.IsPlistWritableByGroup = s.FileMode&0o020 != 0
		s.IsPlistWritableByOther = s.FileMode&0o002 != 0
	}
	s.IsPlistOwnedByRoot = s.FileOwnerUID == 0
	s.IsPersistentThirdPartyRoot = s.PlistScope == ScopeSystemDaemon &&
		!s.IsAppleSignedDomain && s.RunsAsRoot && s.IsRunAtLoad
}

// SortServices returns a deterministic ordering: file path, then label.
func SortServices(ss []Service) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].FilePath != ss[j].FilePath {
			return ss[i].FilePath < ss[j].FilePath
		}
		return ss[i].Label < ss[j].Label
	})
}
