// Package winregistryuninstall audits Windows software-
// inventory dump files cached on workstations: Uninstall-
// registry .reg exports (HKLM + HKCU), Add/Remove Programs
// CSVs, PowerShell Get-Package / Get-CimInstance
// Win32_Product / Get-AppxPackage outputs, and DISM feature
// exports.
//
// This is the host-native software-inventory layer.
// Complements iter 121 winsoftwarelicences (per-licence)
// and iter 122 winsamexports (third-party SAM tools).
//
// Headline finding shapes:
//
//   - `has_recent_install=1` — entry installed within 30d.
//   - `has_unsigned_publisher=1` — > 0 entries with no
//     publisher field (suspicious / unmanaged install).
//   - `has_pii_software=1` — > 0 entries match the PII /
//     financial / PHI catalogue.
//   - `is_credential_exposure_risk=1` — readable file +
//     (PII OR unsigned-publisher + entry_count > 0).
//
// Read-only by intent. (Project guideline 4.2.)
package winregistryuninstall

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

// MaxFileBytes bounds per-file read (32 MiB — Uninstall-key
// exports for fully-loaded endpoints can be hundreds of KiB
// to a few MiB).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install-date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_win_uninstall_inventory.artifact_kind.
type ArtifactKind string

const (
	KindRegUninstallHKLM  ArtifactKind = "reg-uninstall-hklm"
	KindRegUninstallHKCU  ArtifactKind = "reg-uninstall-hkcu"
	KindAddRemoveCSV      ArtifactKind = "addremove-csv"
	KindAppxPackagesJSON  ArtifactKind = "appx-packages-json"
	KindAppxPackagesCSV   ArtifactKind = "appx-packages-csv"
	KindPSGetPackage      ArtifactKind = "ps-get-package"
	KindWMIWin32Product   ArtifactKind = "wmi-win32-product"
	KindDISMFeaturesCSV   ArtifactKind = "dism-features-csv"
	KindProgramsFeatures  ArtifactKind = "programs-features-csv"
	KindInstalledPrograms ArtifactKind = "installed-programs-csv"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// Row mirrors host_win_uninstall_inventory' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	InventoryTimestamp       string       `json:"inventory_timestamp,omitempty"`
	MaxInstallDateYYYYMMDD   string       `json:"max_install_date_yyyymmdd,omitempty"`
	MinInstallDateYYYYMMDD   string       `json:"min_install_date_yyyymmdd,omitempty"`
	EntryCount               int64        `json:"entry_count,omitempty"`
	MicrosoftPublisherCount  int64        `json:"microsoft_publisher_count,omitempty"`
	ThirdPartyPublisherCount int64        `json:"third_party_publisher_count,omitempty"`
	UnsignedPublisherCount   int64        `json:"unsigned_publisher_count,omitempty"`
	PIISoftwareCount         int64        `json:"pii_software_count,omitempty"`
	RecentInstallCount       int64        `json:"recent_install_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasRecentInstall         bool         `json:"has_recent_install"`
	HasUnsignedPublisher     bool         `json:"has_unsigned_publisher"`
	HasPIISoftware           bool         `json:"has_pii_software"`
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
// Windows-centric; cross-OS roots are kept for portability
// when inventory dumps are exported to shared mounts.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ProgramData\Inventory`,
		`C:\ProgramData\SoftwareInventory`,
		`C:\Scripts\inventory`,
		`C:\Scripts\software`,
		`C:\Admin\inventory`,
		`C:\Windows\Logs\Inventory`,
		`C:\Windows\Temp\inventory`,
		`/var/lib/inventory`,
		`/srv/inventory`,
		`/opt/inventory`,
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

// UserUninstDirs is the curated per-user relative path set.
func UserUninstDirs() [][]string {
	return [][]string{
		{"Documents", "Inventory"},
		{"Documents", "Software"},
		{"Documents", "Scripts", "inventory"},
		{"AppData", "Local", "Inventory"},
		{"AppData", "Roaming", "Inventory"},
		{"Desktop", "inventory"},
	}
}

// IsCandidateExt reports whether the extension carries an
// uninstall-inventory artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".reg", ".csv", ".json", ".tsv", ".xml", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the uninstall-inventory catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"uninstall_export_hklm", "uninstall_export_hkcu",
		"uninstall-export-hklm", "uninstall-export-hkcu",
		"uninstall_hklm", "uninstall_hkcu",
		"addremoveprograms", "addremove-programs",
		"add_remove_programs", "add-remove-programs",
		"appx_packages", "appx-packages",
		"get-package", "get_package",
		"get-appxpackage", "get_appxpackage",
		"win32_product", "win32product",
		"win32_installedwin32program",
		"dism_features", "dism-features",
		"dism_get-features",
		"programs_and_features", "programs-and-features",
		"installed_programs", "installed-programs",
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
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case strings.Contains(n, "uninstall") && strings.Contains(n, "hklm"):
		return KindRegUninstallHKLM
	case strings.Contains(n, "uninstall") && strings.Contains(n, "hkcu"):
		return KindRegUninstallHKCU
	case strings.Contains(n, "addremove") || strings.Contains(n, "add_remove") ||
		strings.Contains(n, "add-remove"):
		return KindAddRemoveCSV
	case strings.Contains(n, "appx_packages") || strings.Contains(n, "appx-packages") ||
		strings.Contains(n, "get-appxpackage") || strings.Contains(n, "get_appxpackage"):
		if ext == ".csv" {
			return KindAppxPackagesCSV
		}
		return KindAppxPackagesJSON
	case strings.Contains(n, "get-package") || strings.Contains(n, "get_package"):
		return KindPSGetPackage
	case strings.Contains(n, "win32_product") || strings.Contains(n, "win32product") ||
		strings.Contains(n, "win32_installedwin32program"):
		return KindWMIWin32Product
	case strings.Contains(n, "dism_features") || strings.Contains(n, "dism-features") ||
		strings.Contains(n, "dism_get-features"):
		return KindDISMFeaturesCSV
	case strings.Contains(n, "programs_and_features") ||
		strings.Contains(n, "programs-and-features"):
		return KindProgramsFeatures
	case strings.Contains(n, "installed_programs") ||
		strings.Contains(n, "installed-programs"):
		return KindInstalledPrograms
	}
	return KindOther
}

// regKeyRE matches a registry-key block opening (e.g.
// `[HKEY_LOCAL_MACHINE\Software\...\Uninstall\{GUID}]`). One
// match = one software entry in `.reg` exports.
var regKeyRE = regexp.MustCompile(`(?m)^\[HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\Software\\.+Uninstall\\.+\]`)

// publisherFieldRE captures the `"Publisher"="<value>"` field
// inside Uninstall-key `.reg` exports.
var publisherFieldRE = regexp.MustCompile(`(?im)^"Publisher"="([^"]*)"`)

// installDateFieldRE captures `"InstallDate"="<yyyymmdd>"`.
var installDateFieldRE = regexp.MustCompile(`(?im)^"InstallDate"="(\d{8})"`)

// CSVRowCount returns the count of non-empty, non-header
// rows in a CSV-like body.
func CSVRowCount(body []byte) int64 {
	lines := strings.Split(string(body), "\n")
	var count int64
	headerSeen := false
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if !headerSeen && !strings.ContainsAny(l, "0123456789") &&
			strings.Contains(l, ",") {
			headerSeen = true
			continue
		}
		count++
	}
	return count
}

// RegEntryCount returns the count of [HKEY_...\Uninstall\..]
// key blocks in a `.reg` export.
func RegEntryCount(body []byte) int64 {
	return int64(len(regKeyRE.FindAllIndex(body, -1)))
}

// PublisherSplit classifies publisher fields across the body
// into Microsoft / third-party / unsigned counts. Works on
// both `.reg` and CSV/JSON bodies via case-insensitive scan.
func PublisherSplit(body []byte) (microsoft, thirdParty, unsigned int64) {
	// .reg explicit fields first.
	regMatches := publisherFieldRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range regMatches {
		pub := strings.TrimSpace(m[1])
		switch {
		case pub == "":
			unsigned++
		case strings.Contains(strings.ToLower(pub), "microsoft"):
			microsoft++
		default:
			thirdParty++
		}
	}
	if microsoft+thirdParty+unsigned > 0 {
		return microsoft, thirdParty, unsigned
	}
	// CSV / JSON heuristic — search columns named Publisher.
	for _, line := range strings.Split(string(body), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "microsoft") {
			microsoft++
		} else if strings.Contains(lower, "publisher") {
			continue // header
		}
	}
	return microsoft, thirdParty, unsigned
}

// RecentInstallStats walks InstallDate fields in the body and
// returns the count of entries installed within RecentInstallWindow
// of `now`, plus min/max install dates as YYYYMMDD.
func RecentInstallStats(body []byte, now time.Time) (recent int64, minDate, maxDate string) {
	matches := installDateFieldRE.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		// Fall back to CSV scan — look for YYYY-MM-DD or YYYYMMDD
		// in lines.
		matches = installDateAnyRE.FindAllStringSubmatch(string(body), -1)
	}
	cutoff := now.Add(-RecentInstallWindow)
	for _, m := range matches {
		date := normaliseInstallDate(m[1])
		if date == "" {
			continue
		}
		if t, err := time.Parse("20060102", date); err == nil {
			if t.After(cutoff) || t.Equal(cutoff) {
				recent++
			}
			if minDate == "" || date < minDate {
				minDate = date
			}
			if maxDate == "" || date > maxDate {
				maxDate = date
			}
		}
	}
	return recent, minDate, maxDate
}

// installDateAnyRE matches an install-date column value in CSV
// bodies that don't use the .reg quote syntax.
var installDateAnyRE = regexp.MustCompile(`(?:install[_\-\s]?date|installdate)\s*[:=,]?\s*"?(\d{8}|\d{4}-\d{2}-\d{2})`)

func normaliseInstallDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		return s
	}
	if len(s) == 10 {
		return s[0:4] + s[5:7] + s[8:10]
	}
	return ""
}

// PIIHandlingMarkers — fingerprints shared with iters 121/122.
func PIIHandlingMarkers() []string {
	return []string{
		"salesforce", "sap", "dynamics 365", "hubspot",
		"zoho", "workday", "successfactor", "oracle ebs",
		"outlook", "thunderbird", "slack", "teams", "zoom",
		"chrome", "firefox", "edge", "safari",
		"quickbooks", "sage", "xero", "tango/04", "tango04",
		"meta4", "bejerman", "calipso", "holistor",
		"contabilium", "tiendanube", "mercadopago",
		"epic", "cerner", "openemr", "meditech",
		"stripe", "adyen", "first data", "prisma", "posnet",
	}
}

// CountPIIRows scans the body line-by-line and returns the
// count of rows that match a PII / financial / PHI marker.
func CountPIIRows(body []byte) int64 {
	lower := strings.ToLower(string(body))
	var count int64
	for _, line := range strings.Split(lower, "\n") {
		for _, marker := range PIIHandlingMarkers() {
			if strings.Contains(line, marker) {
				count++
				break
			}
		}
	}
	return count
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
	if r.RecentInstallCount > 0 {
		r.HasRecentInstall = true
	}
	if r.UnsignedPublisherCount > 0 {
		r.HasUnsignedPublisher = true
	}
	if r.PIISoftwareCount > 0 {
		r.HasPIISoftware = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasRisk := r.HasPIISoftware ||
		(r.HasUnsignedPublisher && r.EntryCount > 0)
	if hasReadable && hasRisk {
		r.IsCredentialExposureRisk = true
	}
	_ = now // reserved for future clock-driven flags
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
		return rs[i].InventoryTimestamp < rs[j].InventoryTimestamp
	})
}
