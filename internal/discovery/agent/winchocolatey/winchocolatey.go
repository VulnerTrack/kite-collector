// Package winchocolatey audits Chocolatey package manager
// artifacts cached on Windows workstations (with portability
// to Linux + macOS for cross-platform Chocolatey-CLI
// deployments).
//
// Per nuspec the inventory captures title, manufacturer
// (authors+copyright), version, vendor URL, licence URL,
// purpose (description), tags, install date proxy (file
// mtime), and DP/DS classification via the shared
// PII/PHI/PCI catalogue.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM-tool aggregate), iter 123
// winregistryuninstall (host-native Uninstall), and
// iter 124 winsbom (SBOM artifacts).
//
// Headline finding shapes:
//
//   - `has_license_url=1` — nuspec ships licenseUrl.
//   - `has_project_url=1` — nuspec ships projectUrl.
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — package matches PII catalogue.
//   - `is_credential_exposure_risk=1` — readable file +
//     PII-handling product metadata exposed in shared
//     workstation cache.
//
// Read-only by intent. (Project guideline 4.2.)
package winchocolatey

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

// MaxFileBytes bounds per-file read (4 MiB — nuspec files
// are small; log files capped to avoid pulling the whole
// chocolatey.log into memory).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install-date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_chocolatey_inventory.artifact_kind.
type ArtifactKind string

const (
	KindChocoNuspec          ArtifactKind = "choco-nuspec"
	KindChocoLog             ArtifactKind = "choco-log"
	KindChocoConfig          ArtifactKind = "choco-config"
	KindChocoExtensionNuspec ArtifactKind = "choco-extension-nuspec"
	KindChocoPin             ArtifactKind = "choco-pin"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// DPDSClass pinned to host_chocolatey_inventory.dp_ds_class.
type DPDSClass string

const (
	DPDSHandlesPII       DPDSClass = "handles-pii"
	DPDSHandlesFinancial DPDSClass = "handles-financial"
	DPDSHandlesPHI       DPDSClass = "handles-phi"
	DPDSHandlesPCI       DPDSClass = "handles-pci"
	DPDSSystemUtility    DPDSClass = "system-utility"
	DPDSDevTool          DPDSClass = "dev-tool"
	DPDSMediaTool        DPDSClass = "media-tool"
	DPDSOSSNoPII         DPDSClass = "oss-no-pii"
	DPDSOther            DPDSClass = "other"
	DPDSUnknown          DPDSClass = "unknown"
)

// Row mirrors host_chocolatey_inventory' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	PackageID                string       `json:"package_id,omitempty"`
	Title                    string       `json:"title,omitempty"`
	Publisher                string       `json:"publisher,omitempty"`
	Version                  string       `json:"version,omitempty"`
	ProjectURL               string       `json:"project_url,omitempty"`
	LicenseURL               string       `json:"license_url,omitempty"`
	Description              string       `json:"description,omitempty"`
	Tags                     string       `json:"tags,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasLicenseURL            bool         `json:"has_license_url"`
	HasProjectURL            bool         `json:"has_project_url"`
	HasRecentInstall         bool         `json:"has_recent_install"`
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
// Chocolatey is Windows-native but Linux/macOS variants
// (chocolatey-core on PowerShell) deploy to /usr/local.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ProgramData\chocolatey\lib`,
		`C:\ProgramData\chocolatey\.chocolatey`,
		`C:\ProgramData\chocolatey\config`,
		`C:\ProgramData\chocolatey\extensions`,
		`C:\ProgramData\chocolatey\logs`,
		`/usr/local/chocolatey/lib`,
		`/usr/local/chocolatey/logs`,
		`/opt/chocolatey/lib`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserChocoDirs is the curated per-user relative path set.
func UserChocoDirs() [][]string {
	return [][]string{
		{"AppData", "Local", "Chocolatey"},
		{"AppData", "Roaming", "Chocolatey"},
		{"Documents", "chocolatey"},
		{".chocolatey"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Chocolatey artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".nuspec", ".log", ".config", ".xml":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Chocolatey catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	if strings.HasSuffix(n, ".nuspec") {
		return true
	}
	for _, tok := range []string{
		"chocolatey.log", "chocolatey.config",
		"chocolatey-", "chocolatey_",
		".chocolatey",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromPath classifies the artifact by full path
// because the same `.nuspec` extension can be either a regular
// package or a Chocolatey extension under `extensions\`.
// Normalises both `\` and `/` separators so Windows-style
// paths resolve correctly when this code runs on Linux CI.
func ArtifactKindFromPath(path string) ArtifactKind {
	if strings.TrimSpace(path) == "" {
		return KindUnknown
	}
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	parent := strings.ToLower(normalised)
	var n string
	if idx := strings.LastIndex(parent, "/"); idx >= 0 {
		n = parent[idx+1:]
	} else {
		n = parent
	}
	switch {
	case strings.HasSuffix(n, ".nuspec") &&
		strings.Contains(parent, "/extensions/"):
		return KindChocoExtensionNuspec
	case strings.HasSuffix(n, ".nuspec"):
		return KindChocoNuspec
	case n == "chocolatey.log":
		return KindChocoLog
	case n == "chocolatey.config":
		return KindChocoConfig
	case strings.Contains(n, "pin"):
		return KindChocoPin
	}
	return KindOther
}

// PIIHandlingMarkers — fingerprints shared with iters 121-124.
// Each marker substring match in a nuspec id/title/tags counts
// toward DP/DS classification.
func PIIHandlingMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// PII / CRM / ERP
		"salesforce":   DPDSHandlesPII,
		"sap":          DPDSHandlesPII,
		"dynamics-365": DPDSHandlesPII,
		"hubspot":      DPDSHandlesPII,
		"zoho":         DPDSHandlesPII,
		"workday":      DPDSHandlesPII,
		// Email / collaboration
		"outlook":         DPDSHandlesPII,
		"thunderbird":     DPDSHandlesPII,
		"slack":           DPDSHandlesPII,
		"microsoft-teams": DPDSHandlesPII,
		"zoom":            DPDSHandlesPII,
		// Browsers
		"googlechrome":   DPDSHandlesPII,
		"firefox":        DPDSHandlesPII,
		"microsoft-edge": DPDSHandlesPII,
		// Financial / accounting (incl. LATAM)
		"quickbooks":  DPDSHandlesFinancial,
		"sage":        DPDSHandlesFinancial,
		"xero":        DPDSHandlesFinancial,
		"tango04":     DPDSHandlesFinancial,
		"meta4":       DPDSHandlesFinancial,
		"bejerman":    DPDSHandlesFinancial,
		"contabilium": DPDSHandlesFinancial,
		"tiendanube":  DPDSHandlesFinancial,
		// EHR / PHI
		"epic-emr": DPDSHandlesPHI,
		"openemr":  DPDSHandlesPHI,
		// PCI / payments
		"stripe-cli": DPDSHandlesPCI,
		"adyen":      DPDSHandlesPCI,
		"posnet":     DPDSHandlesPCI,
		// Dev tools / utilities
		"git":                   DPDSDevTool,
		"jetbrains":             DPDSDevTool,
		"intellijidea-ultimate": DPDSDevTool,
		"vscode":                DPDSDevTool,
		"visualstudiocode":      DPDSDevTool,
		"docker-desktop":        DPDSDevTool,
		// Media
		"adobereader": DPDSMediaTool,
		"obs":         DPDSMediaTool,
	}
}

// ClassifyDPDS returns the DP/DS class for a Chocolatey
// package using id + title + tags. Empty inputs default to
// `DPDSUnknown`.
func ClassifyDPDS(packageID, title, tags string) DPDSClass {
	hay := strings.ToLower(packageID + " " + title + " " + tags)
	hay = strings.TrimSpace(hay)
	if hay == "" {
		return DPDSUnknown
	}
	for marker, cls := range PIIHandlingMarkers() {
		if strings.Contains(hay, marker) {
			return cls
		}
	}
	return DPDSUnknown
}

// IsPIIHandlingClass reports membership in the PII set.
func IsPIIHandlingClass(c DPDSClass) bool {
	switch c {
	case DPDSHandlesPII, DPDSHandlesFinancial,
		DPDSHandlesPHI, DPDSHandlesPCI:
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
	if r.LicenseURL != "" {
		r.HasLicenseURL = true
	}
	if r.ProjectURL != "" {
		r.HasProjectURL = true
	}
	if IsPIIHandlingClass(r.DPDSClass) {
		r.IsPIIHandling = true
	}
	// Recent-install: install-date YYYYMMDD vs clock.
	if r.InstallDateYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.InstallDateYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.IsPIIHandling && r.PackageID != "" {
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
		return rs[i].PackageID < rs[j].PackageID
	})
}
