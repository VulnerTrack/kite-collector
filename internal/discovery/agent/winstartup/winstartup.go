// Package winstartup inventories files in the Windows Startup
// directories — both the All-Users tree under ProgramData and the
// per-user tree under each profile's AppData\Roaming. Anything
// that lands here runs at the next login (per-user) or at every
// user's login (All-Users); it's one of the oldest and still most
// common persistence primitives on Windows.
//
// File-based discovery is the deliberate design choice: there is
// no API to "list everything that will run at logon" — the system
// just walks these directories. The collector mirrors that path
// and also does a best-effort Shell-Link parse to expose the
// target each .lnk resolves to.
//
// Headline finding shapes (MITRE T1547.001 — Registry Run Keys /
// Startup Folder, defender side):
//
//   - `is_all_users_scope=1` — the row lives under ProgramData;
//     it runs for every account that logs in. Attackers prefer
//     this scope when they have admin.
//   - `is_executable_extension=1` — file is `.exe` / `.bat` /
//     `.cmd` / `.vbs` / `.ps1` dropped directly in the Startup
//     folder, bypassing the usual `.lnk` indirection. Vendor
//     installers always ship `.lnk`; direct executables are a
//     strong implant signal.
//   - `is_target_in_world_writable_dir=1` — the .lnk resolves to
//     a target under `C:\Users\Public`, `%TEMP%`, etc. The audit
//     pipeline alerts even when the .lnk itself is signed,
//     because the target binary isn't (CWE-426 + T1547.001).
//
// Read-only by intent — we walk the directories only, never
// invoke `wscript` / `shortcut` resolvers. (Project guideline 4.2.)
package winstartup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxItems bounds per-scan output. A typical workstation has 2-8
// startup items per scope; the 1024 ceiling covers vendor-heavy
// build farms without bloating SQLite writes.
const MaxItems = 1024

// Scope classifies which Startup tree the file sits under. Pinned
// to the host_startup_items.scope CHECK enum.
type Scope string

const (
	ScopeAllUsers Scope = "all-users"
	ScopePerUser  Scope = "per-user"
	ScopeUnknown  Scope = "unknown"
)

// Item mirrors host_startup_items' column shape exactly.
type Item struct {
	UserProfile                string `json:"user_profile,omitempty"`
	FileHash                   string `json:"file_hash"`
	FileName                   string `json:"file_name"`
	FileExtension              string `json:"file_extension"`
	FilePath                   string `json:"file_path"`
	Scope                      Scope  `json:"scope"`
	TargetPath                 string `json:"target_path,omitempty"`
	FileSizeBytes              int64  `json:"file_size_bytes"`
	FileMtime                  int64  `json:"file_mtime,omitempty"`
	IsAllUsersScope            bool   `json:"is_all_users_scope"`
	IsExecutableExtension      bool   `json:"is_executable_extension"`
	IsShortcut                 bool   `json:"is_shortcut"`
	IsTargetInWorldWritableDir bool   `json:"is_target_in_world_writable_dir"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Item, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ExecutableExtensions is the curated set of directly-executable
// extensions. Anything in this set sitting in a Startup folder
// skipped the `.lnk` indirection — implant-shaped.
func ExecutableExtensions() []string {
	return []string{
		".exe", ".bat", ".cmd", ".vbs", ".vbe",
		".js", ".jse", ".wsf", ".wsh", ".ps1", ".scr",
	}
}

// IsExecutableExtension reports whether `ext` is in the curated
// executable set. Case-insensitive.
func IsExecutableExtension(ext string) bool {
	e := strings.ToLower(strings.TrimSpace(ext))
	for _, k := range ExecutableExtensions() {
		if e == k {
			return true
		}
	}
	return false
}

// WorldWritableDirRoots is the curated set of directory prefixes
// any local user can write into. .lnk targets resolving under
// these surface the world-writable finding.
func WorldWritableDirRoots() []string {
	return []string{
		`c:\users\public\`,
		`c:\windows\temp\`,
		`c:\temp\`,
		`c:\programdata\temp\`,
		`%temp%\`,
		`%tmp%\`,
		`%public%\`,
		`%userprofile%\appdata\local\temp\`,
	}
}

// IsTargetInWorldWritableDir reports whether a resolved .lnk
// target sits under one of the curated world-writable roots.
// Empty target returns false.
func IsTargetInWorldWritableDir(target string) bool {
	v := strings.ToLower(strings.TrimSpace(target))
	if v == "" {
		return false
	}
	v = strings.Trim(v, `"`)
	cleaned := filepath.ToSlash(v)
	for _, root := range WorldWritableDirRoots() {
		r := strings.ToLower(filepath.ToSlash(root))
		if strings.HasPrefix(cleaned, r) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on an Item that has
// its raw fields populated.
func AnnotateSecurity(i *Item) {
	i.IsAllUsersScope = i.Scope == ScopeAllUsers
	i.IsShortcut = strings.EqualFold(i.FileExtension, ".lnk")
	i.IsExecutableExtension = IsExecutableExtension(i.FileExtension)
	i.IsTargetInWorldWritableDir = IsTargetInWorldWritableDir(i.TargetPath)
}

// SortItems returns a deterministic ordering by scope, then file path.
func SortItems(is []Item) {
	sort.Slice(is, func(i, j int) bool {
		if is[i].Scope != is[j].Scope {
			return is[i].Scope < is[j].Scope
		}
		return is[i].FilePath < is[j].FilePath
	})
}
