// Package winwingetexport audits Microsoft winget (Windows
// Package Manager) export + state files cached on Windows
// workstations. Closes the Windows-package-manager pair
// alongside iter 125 winchocolatey by adding the
// Microsoft-native counterpart.
//
// winget export produces canonical JSON listing every
// installed package with PackageIdentifier of the form
// `<Publisher>.<Product>` (e.g. `Microsoft.Office`,
// `Google.Chrome`, `Intuit.QuickBooks`). The Publisher
// half of the identifier maps directly to the inventory's
// `manufacturer` field; the Product half to `title`.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (host-native Uninstall), iter 124
// winsbom (SBOM artifacts), and iter 125 winchocolatey
// (Chocolatey nuspec).
//
// Headline finding shapes:
//
//   - `has_msstore_source=1` — Microsoft Store source in
//     sources list (consumer licence-channel risk).
//   - `has_third_party_source=1` — custom non-default
//     source configured (supply-chain attack vector).
//   - `has_pii_packages=1` — > 0 packages match the PII /
//     financial / PHI catalogue.
//   - `is_credential_exposure_risk=1` — readable file +
//     packages + (PII OR third-party-source).
//
// Read-only by intent. (Project guideline 4.2.)
package winwingetexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read (16 MiB — winget export
// for a fully-loaded endpoint with hundreds of packages can
// exceed a few MiB).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_winget_exports.artifact_kind.
type ArtifactKind string

const (
	KindWingetExportJSON   ArtifactKind = "winget-export-json"
	KindWingetPinList      ArtifactKind = "winget-pin-list"
	KindWingetSourceList   ArtifactKind = "winget-source-list"
	KindWingetInstallLog   ArtifactKind = "winget-install-log"
	KindWingetUninstallLog ArtifactKind = "winget-uninstall-log"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// Row mirrors host_winget_exports' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	WingetVersion            string       `json:"winget_version,omitempty"`
	SourceName               string       `json:"source_name,omitempty"`
	SourceArgument           string       `json:"source_argument,omitempty"`
	CreationTimestamp        string       `json:"creation_timestamp,omitempty"`
	PackageCount             int64        `json:"package_count,omitempty"`
	MicrosoftPackageCount    int64        `json:"microsoft_package_count,omitempty"`
	ThirdPartyPackageCount   int64        `json:"third_party_package_count,omitempty"`
	PIIPackageCount          int64        `json:"pii_package_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasMSStoreSource         bool         `json:"has_msstore_source"`
	HasThirdPartySource      bool         `json:"has_third_party_source"`
	HasPIIPackages           bool         `json:"has_pii_packages"`
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

// DefaultInstallRoots is the curated install-root set for
// winget state files.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ProgramData\Microsoft\WinGet`,
		`C:\ProgramData\WinGet`,
		`C:\Windows\Logs\WinGet`,
		`C:\Windows\Temp\WinGetLogs`,
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

// UserWingetDirs is the curated per-user relative path set.
func UserWingetDirs() [][]string {
	return [][]string{
		{
			"AppData", "Local", "Packages",
			"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe",
			"LocalState",
		},
		{
			"AppData", "Local", "Packages",
			"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe",
			"LocalCache",
		},
		{"AppData", "Local", "Microsoft", "WinGet"},
		{"AppData", "Local", "Microsoft", "WinGet", "Settings"},
		{"AppData", "Local", "Microsoft", "WinGet", "Logs"},
		{"Documents", "WinGet"},
		{"Documents", "Inventory", "winget"},
	}
}

// IsCandidateExt reports whether the extension carries a
// winget artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml", ".log", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the winget catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"winget-export", "winget_export",
		"winget-pin", "winget_pin", "pinned.json",
		"winget-source", "winget_source", "sources.json",
		"winget-install", "winget_install",
		"winget-uninstall", "winget_uninstall",
		"winget.log", "winget-log", "winget_log",
		".installlog", ".uninstalllog",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "winget-export") ||
		strings.Contains(n, "winget_export"):
		return KindWingetExportJSON
	case strings.Contains(n, "pinned.json") ||
		strings.Contains(n, "winget-pin") ||
		strings.Contains(n, "winget_pin"):
		return KindWingetPinList
	case strings.Contains(n, "sources.json") ||
		strings.Contains(n, "winget-source") ||
		strings.Contains(n, "winget_source"):
		return KindWingetSourceList
	case strings.Contains(n, "winget-uninstall") ||
		strings.Contains(n, "winget_uninstall") ||
		strings.HasSuffix(n, ".uninstalllog"):
		return KindWingetUninstallLog
	case strings.Contains(n, "winget-install") ||
		strings.Contains(n, "winget_install") ||
		strings.HasSuffix(n, ".installlog") ||
		strings.Contains(n, "winget.log") ||
		strings.Contains(n, "winget-log") ||
		strings.Contains(n, "winget_log"):
		return KindWingetInstallLog
	}
	return KindOther
}

// pkgIdentRE captures PackageIdentifier strings like
// "Microsoft.Office", "Google.Chrome", "Intuit.QuickBooks"
// inside winget-export JSON.
var pkgIdentRE = regexp.MustCompile(`(?i)"packageidentifier"\s*:\s*"([A-Za-z0-9][A-Za-z0-9_\-]{0,48}\.[A-Za-z0-9._\-]{1,96})"`)

// CountPackages returns the number of PackageIdentifier
// occurrences in a winget-export JSON body.
func CountPackages(body []byte) int64 {
	return int64(len(pkgIdentRE.FindAllIndex(body, -1)))
}

// PackagePublisher reports the leading `<Publisher>` segment
// of a winget PackageIdentifier (`Microsoft.Office` →
// `microsoft`). Returns "" for malformed input.
func PackagePublisher(identifier string) string {
	t := strings.ToLower(strings.TrimSpace(identifier))
	if t == "" {
		return ""
	}
	idx := strings.IndexByte(t, '.')
	if idx <= 0 {
		return ""
	}
	return t[:idx]
}

// PublisherSplit counts how many PackageIdentifier rows start
// with `microsoft.` vs other publishers. Operates on raw
// body so it works for both JSON and YAML exports.
func PublisherSplit(body []byte) (microsoft, thirdParty int64) {
	matches := pkgIdentRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		pub := PackagePublisher(m[1])
		if pub == "microsoft" {
			microsoft++
		} else {
			thirdParty++
		}
	}
	return microsoft, thirdParty
}

// winget-source detection — sources.json carries a top-level
// "Sources" array; each item has `"Name"`, `"Argument"`,
// `"Type"`. Look for `Microsoft Store` source (msstore) and
// custom corporate sources (anything not named "winget" or
// "msstore").
var (
	sourceNameRE = regexp.MustCompile(`(?i)"name"\s*:\s*"([^"]+)"`)
	sourceArgRE  = regexp.MustCompile(`(?i)"argument"\s*:\s*"([^"]+)"`)
)

// SourceListFromBody extracts the first source name and
// argument from a winget sources.json body.
func SourceListFromBody(body []byte) (name, argument string) {
	if m := sourceNameRE.FindStringSubmatch(string(body)); m != nil {
		name = strings.TrimSpace(m[1])
	}
	if m := sourceArgRE.FindStringSubmatch(string(body)); m != nil {
		argument = strings.TrimSpace(m[1])
	}
	return name, argument
}

// HasMSStoreSource reports whether `msstore` appears in any
// source-name slot of the body.
func HasMSStoreSource(body []byte) bool {
	matches := sourceNameRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		if strings.EqualFold(strings.TrimSpace(m[1]), "msstore") {
			return true
		}
	}
	return false
}

// HasThirdPartySource reports whether any source-name other
// than "winget" / "msstore" is present (custom corporate
// source — supply-chain attack vector).
func HasThirdPartySource(body []byte) bool {
	matches := sourceNameRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		nm := strings.ToLower(strings.TrimSpace(m[1]))
		switch nm {
		case "winget", "msstore", "":
			// known-good or empty.
		default:
			return true
		}
	}
	return false
}

// wingetVersionRE captures the `"WinGetVersion"` field.
var wingetVersionRE = regexp.MustCompile(`(?i)"wingetversion"\s*:\s*"([^"]+)"`)

// WingetVersionFromBody extracts the winget version.
func WingetVersionFromBody(body []byte) string {
	m := wingetVersionRE.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// creationDateRE captures `"CreationDate":` in export JSON.
var creationDateRE = regexp.MustCompile(`(?i)"creationdate"\s*:\s*"([^"]+)"`)

// CreationTimestampFromBody extracts the CreationDate.
func CreationTimestampFromBody(body []byte) string {
	m := creationDateRE.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// PIIHandlingMarkers — winget package-identifier substrings
// that map to PII / financial / PHI / PCI handling. Keys are
// lowercased and matched against PackageIdentifier values.
func PIIHandlingMarkers() []string {
	return []string{
		// Microsoft PII apps
		"microsoft.office", "microsoft.outlook",
		"microsoft.teams", "microsoft.onedrive",
		"microsoft.skype", "microsoft.edge",
		// Browsers + email
		"google.chrome", "mozilla.firefox", "mozilla.thunderbird",
		"google.gmail", "apple.safari",
		// CRM / ERP
		"salesforce.", "sap.", "oracle.",
		"hubspot.", "zoho.", "workday.",
		// Accounting / financial
		"intuit.quickbooks", "sage.", "xero.",
		"tango04.", "meta4.", "bejerman.",
		"contabilium.", "tiendanube.", "mercadopago.",
		// EHR / PHI
		"epicgames.", "cerner.", "openemr.",
		// Payments / PCI
		"stripe.", "adyen.", "firstdata.",
		"prisma.", "posnet.",
		// Collaboration
		"slack.slack", "zoom.zoom", "webex.",
	}
}

// CountPIIPackages walks PackageIdentifier matches and counts
// those whose lowercased value contains a PII marker.
func CountPIIPackages(body []byte) int64 {
	matches := pkgIdentRE.FindAllStringSubmatch(string(body), -1)
	markers := PIIHandlingMarkers()
	var count int64
	for _, m := range matches {
		id := strings.ToLower(m[1])
		for _, marker := range markers {
			if strings.Contains(id, marker) {
				count++
				break
			}
		}
	}
	return count
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.PIIPackageCount > 0 {
		r.HasPIIPackages = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasRisk := r.HasPIIPackages || r.HasThirdPartySource
	if hasReadable && r.PackageCount > 0 && hasRisk {
		r.IsCredentialExposureRisk = true
	}
	// Also flag exposure when a sources list shows third-party
	// source — even with package_count == 0 (a misconfigured
	// source is itself a supply-chain risk).
	if !r.IsCredentialExposureRisk && hasReadable &&
		r.HasThirdPartySource && r.ArtifactKind == KindWingetSourceList {
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
		return rs[i].CreationTimestamp < rs[j].CreationTimestamp
	})
}
