// Package macoshomebrew audits macOS Homebrew package manager
// artifacts cached on macOS workstations (Apple Silicon
// /opt/homebrew + Intel /usr/local paths).
//
// Per installed formula, Homebrew writes INSTALL_RECEIPT.json
// inside the Cellar; per cask (GUI app) it writes a cask
// JSON inside the Caskroom metadata directory. Together these
// carry the canonical software-licence inventory fields:
// title, manufacturer (homepage publisher), install date,
// purpose (description), URL, plus DP/DS classification via
// the catalogue shared with iters 121-129.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget
// exports), iter 127 macosinfoplist (macOS Info.plist),
// iter 128 linuxdpkginventory (Debian dpkg), and iter 129
// linuxrpminventory (RHEL/Fedora rpm).
//
// Headline finding shapes:
//
//   - `is_cask=1` — file describes a GUI cask (vs CLI
//     formula).
//   - `has_homepage=1` — formula/cask ships a homepage URL.
//   - `has_recent_install=1` — install_time within 30d.
//   - `installed_on_request=1` — user explicitly installed
//     (vs pulled in as dep).
//   - `is_pii_handling=1` — matches PII / financial / PHI
//     catalogue.
//   - `is_credential_exposure_risk=1` — readable file +
//     formula/cask token + PII-handling.
//
// Read-only by intent. (Project guideline 4.2.)
package macoshomebrew

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 32768

// MaxFileBytes bounds per-file read (4 MiB — install receipts
// and cask metadata files are KiB-scale, but `.brew/*.rb`
// formula sources can grow).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install_time within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_macos_homebrew.artifact_kind.
type ArtifactKind string

const (
	KindBrewInstallReceipt ArtifactKind = "brew-install-receipt"
	KindBrewFormulaRB      ArtifactKind = "brew-formula-rb"
	KindCaskMetadataJSON   ArtifactKind = "cask-metadata-json"
	KindBrewfile           ArtifactKind = "brewfile"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// DPDSClass pinned to host_macos_homebrew.dp_ds_class.
type DPDSClass string

const (
	DPDSHandlesPII       DPDSClass = "handles-pii"
	DPDSHandlesFinancial DPDSClass = "handles-financial"
	DPDSHandlesPHI       DPDSClass = "handles-phi"
	DPDSHandlesPCI       DPDSClass = "handles-pci"
	DPDSHandlesBiometric DPDSClass = "handles-biometric"
	DPDSSystemUtility    DPDSClass = "system-utility"
	DPDSDevTool          DPDSClass = "dev-tool"
	DPDSMediaTool        DPDSClass = "media-tool"
	DPDSOSSNoPII         DPDSClass = "oss-no-pii"
	DPDSOther            DPDSClass = "other"
	DPDSUnknown          DPDSClass = "unknown"
)

// Row mirrors host_macos_homebrew' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	FormulaOrToken           string       `json:"formula_or_token,omitempty"`
	DisplayName              string       `json:"display_name,omitempty"`
	Description              string       `json:"description,omitempty"`
	Homepage                 string       `json:"homepage,omitempty"`
	Version                  string       `json:"version,omitempty"`
	HomebrewVersion          string       `json:"homebrew_version,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	InstallTimeUnix          int64        `json:"install_time_unix,omitempty"`
	RuntimeDepsCount         int64        `json:"runtime_deps_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	IsCask                   bool         `json:"is_cask"`
	HasHomepage              bool         `json:"has_homepage"`
	HasRecentInstall         bool         `json:"has_recent_install"`
	InstalledOnRequest       bool         `json:"installed_on_request"`
	IsPIIHandling            bool         `json:"is_pii_handling"`
	IsRecent                 bool         `json:"is_recent"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set.
// Apple Silicon (M-series) uses /opt/homebrew; Intel uses
// /usr/local. Both are walked.
func DefaultInstallRoots() []string {
	return []string{
		"/opt/homebrew/Cellar",
		"/opt/homebrew/Caskroom",
		"/usr/local/Cellar",
		"/usr/local/Caskroom",
		// Bonus: cross-OS Homebrew (Linux Homebrew aka linuxbrew).
		"/home/linuxbrew/.linuxbrew/Cellar",
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		"/Users",
		"/home",
		`C:\Users`,
	}
}

// UserBrewDirs is the curated per-user relative path set
// (admins / developers often keep Brewfiles under Documents).
func UserBrewDirs() [][]string {
	return [][]string{
		{"Documents", "Brewfiles"},
		{"Documents", "homebrew"},
		{".brew"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Homebrew artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".rb", "":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Homebrew catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	switch n {
	case "install_receipt.json", "brewfile":
		return true
	}
	if strings.HasSuffix(n, ".rb") {
		return true
	}
	if strings.HasSuffix(n, ".json") {
		// Cask metadata files take the form `<token>.json` under
		// Caskroom/<token>/.metadata/<ver>/<ts>/Casks/<token>.json
		// — we accept any .json and let ArtifactKindFromPath
		// disambiguate.
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a file by its full path.
// Normalises both `\` and `/` separators so Windows-style
// paths resolve correctly when this code runs on Linux CI.
func ArtifactKindFromPath(path string) ArtifactKind {
	if strings.TrimSpace(path) == "" {
		return KindUnknown
	}
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	lower := strings.ToLower(normalised)
	var base string
	if idx := strings.LastIndex(lower, "/"); idx >= 0 {
		base = lower[idx+1:]
	} else {
		base = lower
	}
	switch {
	case base == "install_receipt.json":
		return KindBrewInstallReceipt
	case base == "brewfile":
		return KindBrewfile
	case strings.HasSuffix(base, ".rb") &&
		strings.Contains(lower, "/.brew/"):
		return KindBrewFormulaRB
	case strings.HasSuffix(base, ".json") &&
		strings.Contains(lower, "/caskroom/"):
		return KindCaskMetadataJSON
	}
	return KindOther
}

// FormulaOrTokenFromPath extracts the formula name (for
// Cellar paths) or cask token (for Caskroom paths) from the
// install-path breadcrumb.
//
//	/opt/homebrew/Cellar/<formula>/<ver>/INSTALL_RECEIPT.json
//	/opt/homebrew/Caskroom/<cask>/<ver>/.metadata/.../<cask>.json
func FormulaOrTokenFromPath(path string) string {
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	parts := strings.Split(normalised, "/")
	for i, p := range parts {
		lp := strings.ToLower(p)
		if (lp == "cellar" || lp == "caskroom") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// IsCaskPath reports whether the given path lives under a
// Caskroom directory.
func IsCaskPath(path string) bool {
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	return strings.Contains(strings.ToLower(normalised), "/caskroom/")
}

// PIIHandlingMarkers — lowercased formula / cask tokens that
// flag PII / financial / PHI / PCI handling. Shared concept
// with iters 121-129; Homebrew tokens use kebab-case and
// don't include a publisher prefix.
func PIIHandlingMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// Browsers (Casks)
		"firefox":        DPDSHandlesPII,
		"google-chrome":  DPDSHandlesPII,
		"microsoft-edge": DPDSHandlesPII,
		"brave-browser":  DPDSHandlesPII,
		"safari-tp":      DPDSHandlesPII,
		// Email + collaboration (Casks)
		"thunderbird":     DPDSHandlesPII,
		"microsoft-teams": DPDSHandlesPII,
		"slack":           DPDSHandlesPII,
		"zoom":            DPDSHandlesPII,
		"webex":           DPDSHandlesPII,
		"signal":          DPDSHandlesPII,
		"telegram":        DPDSHandlesPII,
		// Office productivity (Casks)
		"microsoft-office":  DPDSHandlesPII,
		"microsoft-outlook": DPDSHandlesPII,
		"libreoffice":       DPDSHandlesPII,
		"onedrive":          DPDSHandlesPII,
		// Databases (formulas)
		"postgresql":        DPDSHandlesPII,
		"mariadb":           DPDSHandlesPII,
		"mysql":             DPDSHandlesPII,
		"redis":             DPDSHandlesPII,
		"mongodb-community": DPDSHandlesPII,
		// Credential / SSH (formulas + casks)
		"openssh":   DPDSHandlesPII,
		"vault":     DPDSHandlesPII,
		"keepassxc": DPDSHandlesPII,
		"1password": DPDSHandlesPII,
		"bitwarden": DPDSHandlesPII,
		// Financial / accounting (Casks)
		"quickbooks": DPDSHandlesFinancial,
		"gnucash":    DPDSHandlesFinancial,
		// EHR / PHI
		"openemr": DPDSHandlesPHI,
		// Dev tools (formulas)
		"git":       DPDSDevTool,
		"gh":        DPDSDevTool,
		"awscli":    DPDSDevTool,
		"terraform": DPDSDevTool,
		"kubectl":   DPDSDevTool,
		"docker":    DPDSDevTool,
		"node":      DPDSDevTool,
		"python":    DPDSDevTool,
		"go":        DPDSDevTool,
		// Media (Casks)
		"adobe-acrobat-reader": DPDSMediaTool,
		"vlc":                  DPDSMediaTool,
		"spotify":              DPDSMediaTool,
	}
}

// ClassifyDPDS returns the DP/DS class for a Homebrew row
// based on the formula/cask token.
func ClassifyDPDS(token string) DPDSClass {
	t := strings.ToLower(strings.TrimSpace(token))
	if t == "" {
		return DPDSUnknown
	}
	if cls, ok := PIIHandlingMarkers()[t]; ok {
		return cls
	}
	return DPDSUnknown
}

// IsPIIHandlingClass reports membership in the PII set.
func IsPIIHandlingClass(c DPDSClass) bool {
	switch c {
	case DPDSHandlesPII, DPDSHandlesFinancial,
		DPDSHandlesPHI, DPDSHandlesPCI, DPDSHandlesBiometric:
		return true
	case DPDSSystemUtility, DPDSDevTool, DPDSMediaTool,
		DPDSOSSNoPII, DPDSOther, DPDSUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// AnnotateSecurityWithClock is the time-injectable variant.
func AnnotateSecurityWithClock(r *Row, now func() time.Time) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.Homepage != "" {
		r.HasHomepage = true
	}
	if IsPIIHandlingClass(r.DPDSClass) {
		r.IsPIIHandling = true
	}
	if r.InstallTimeUnix > 0 {
		t := time.Unix(r.InstallTimeUnix, 0).UTC()
		r.InstallDateYYYYMMDD = t.Format("20060102")
		if now().Sub(t) <= RecentInstallWindow {
			r.HasRecentInstall = true
		}
	} else if r.InstallDateYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.InstallDateYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.FormulaOrToken != "" && r.IsPIIHandling {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ArtifactKind != rs[j].ArtifactKind {
			return rs[i].ArtifactKind < rs[j].ArtifactKind
		}
		return rs[i].FormulaOrToken < rs[j].FormulaOrToken
	})
}
