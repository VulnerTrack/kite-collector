// Package winofficeaddins inventories files in the Office
// application-startup and add-in directories on Windows. Every
// Office host walks these directories at launch; anything that
// lands here runs the next time the user opens Word / Excel /
// PowerPoint / Outlook. It's the canonical T1137 (Office
// Application Startup) on-disk persistence surface.
//
// File-based discovery is the deliberate design choice: there is
// no API that lists "everything Office will auto-load". The audit
// pipeline cross-references (file_name, file_hash) against vendor
// whitelists for known-good add-ins (Bloomberg, ThinkOrSwim, etc.)
// and known-bad hashes for off-the-shelf VBA droppers.
//
// Headline finding shapes:
//
//   - `is_persistence_candidate=1` — file extension matches one of
//     the macro-enabled / native-add-in / Outlook-VBA shapes that
//     auto-load on app launch. The audit pipeline alerts verbatim;
//     legit add-ins are dismissed by signed-vendor allowlist.
//   - `is_machine_wide=1` — file lives under a Program Files
//     Office STARTUP directory. Runs for every user that opens
//     Office, not just the file's owner.
//   - `is_outlook_vba_project=1` — `VbaProject.OTM` per user.
//     Outlook loads this every profile open; one of the few
//     T1137.003 file-based primitives.
//
// Read-only by intent — we walk directories only, never invoke
// `winword`/`excel` or Office automation. (Project guideline 4.2.)
package winofficeaddins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxItems bounds per-scan output. A typical workstation has 0-5
// add-ins per user; the 1024 ceiling covers enterprise admins
// with vendor-heavy templates.
const MaxItems = 1024

// OfficeHost tags which Office product loads the file. Pinned to
// the host_office_addins.office_host CHECK enum.
type OfficeHost string

const (
	HostWord         OfficeHost = "word"
	HostExcel        OfficeHost = "excel"
	HostPowerPoint   OfficeHost = "powerpoint"
	HostOutlook      OfficeHost = "outlook"
	HostOfficeShared OfficeHost = "office-shared"
	HostUnknown      OfficeHost = "unknown"
)

// Scope tags per-user vs. machine-wide. Pinned to the
// host_office_addins.scope CHECK enum.
type Scope string

const (
	ScopePerUser     Scope = "per-user"
	ScopeMachineWide Scope = "machine-wide"
	ScopeUnknown     Scope = "unknown"
)

// Item mirrors host_office_addins' column shape exactly.
type Item struct {
	UserProfile             string     `json:"user_profile,omitempty"`
	OfficeHost              OfficeHost `json:"office_host"`
	FileName                string     `json:"file_name"`
	FileExtension           string     `json:"file_extension"`
	Scope                   Scope      `json:"scope"`
	FilePath                string     `json:"file_path"`
	FileHash                string     `json:"file_hash"`
	FileSizeBytes           int64      `json:"file_size_bytes"`
	FileMtime               int64      `json:"file_mtime,omitempty"`
	IsOutlookVBAProject     bool       `json:"is_outlook_vba_project"`
	IsNativeAddinDLL        bool       `json:"is_native_addin_dll"`
	IsMachineWide           bool       `json:"is_machine_wide"`
	IsMacroEnabledExtension bool       `json:"is_macro_enabled_extension"`
	IsPersistenceCandidate  bool       `json:"is_persistence_candidate"`
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

// MacroEnabledExtensions is the curated set of Office macro-
// enabled file extensions. Files in STARTUP / XLSTART / AddIns
// folders with these extensions auto-load on app launch.
func MacroEnabledExtensions() []string {
	return []string{
		".dotm", ".docm", // Word
		".xlsm", ".xltm", ".xlam", // Excel
		".pptm", ".potm", ".ppam", // PowerPoint
		".xla", ".xlt", ".dot", ".pot", ".ppa", // legacy Office 97-2003 macro-capable
	}
}

// NativeAddinExtensions is the curated set of native (DLL-based)
// Office add-in extensions. `.wll` = Word, `.xll` = Excel.
func NativeAddinExtensions() []string {
	return []string{".wll", ".xll"}
}

// IsMacroEnabledExtension reports whether `ext` is in the curated
// macro-enabled set. Case-insensitive.
func IsMacroEnabledExtension(ext string) bool {
	e := strings.ToLower(strings.TrimSpace(ext))
	for _, k := range MacroEnabledExtensions() {
		if e == k {
			return true
		}
	}
	return false
}

// IsNativeAddinDLL reports whether `ext` is in the curated native
// add-in set. Case-insensitive.
func IsNativeAddinDLL(ext string) bool {
	e := strings.ToLower(strings.TrimSpace(ext))
	for _, k := range NativeAddinExtensions() {
		if e == k {
			return true
		}
	}
	return false
}

// IsOutlookVBAFile reports whether `fileName` is the Outlook VBA
// project file. Outlook auto-loads exactly this name from each
// user's profile.
func IsOutlookVBAFile(fileName string) bool {
	return strings.EqualFold(strings.TrimSpace(fileName), "VbaProject.OTM")
}

// AnnotateSecurity sets the derived booleans on an Item that has
// its raw fields populated.
func AnnotateSecurity(i *Item) {
	i.IsMacroEnabledExtension = IsMacroEnabledExtension(i.FileExtension)
	i.IsNativeAddinDLL = IsNativeAddinDLL(i.FileExtension)
	i.IsMachineWide = i.Scope == ScopeMachineWide
	i.IsOutlookVBAProject = IsOutlookVBAFile(i.FileName)
	i.IsPersistenceCandidate = i.IsMacroEnabledExtension ||
		i.IsNativeAddinDLL ||
		i.IsOutlookVBAProject
}

// SortItems returns a deterministic ordering by office_host, then
// scope, then file path.
func SortItems(is []Item) {
	sort.Slice(is, func(i, j int) bool {
		if is[i].OfficeHost != is[j].OfficeHost {
			return is[i].OfficeHost < is[j].OfficeHost
		}
		if is[i].Scope != is[j].Scope {
			return is[i].Scope < is[j].Scope
		}
		return is[i].FilePath < is[j].FilePath
	})
}

// HostFromDirName maps a directory-name segment to an OfficeHost.
// Used by the collector to label each row based on which subdir
// produced it (`Word\STARTUP\foo.dotm` → HostWord).
func HostFromDirName(name string) OfficeHost {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "word":
		return HostWord
	case "excel":
		return HostExcel
	case "powerpoint":
		return HostPowerPoint
	case "outlook":
		return HostOutlook
	case "addins":
		return HostOfficeShared
	}
	return HostUnknown
}

// PathBaseLower returns filepath.Base(p) lowercased. Used so we
// don't pull in additional imports inside the collector.
func PathBaseLower(p string) string {
	return strings.ToLower(filepath.Base(p))
}
