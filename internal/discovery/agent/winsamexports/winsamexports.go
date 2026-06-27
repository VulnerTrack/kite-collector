// Package winsamexports audits Windows-centric Software-
// Asset-Management (SAM) export files cached on workstations.
// Targets the enterprise tooling that dumps per-asset
// installed-software inventory (SCCM, Intune, Lansweeper,
// Snow LM, Flexera, Desktop Central, BigFix, GLPI, OCS,
// winget, Chocolatey).
//
// Complements iter 121 winsoftwarelicences (single licence-
// artifact files) with the *aggregate per-asset* layer.
//
// Asset hostname is stored ONLY as a SHA-256 hash so that
// the per-row metadata is meaningful for correlation without
// retaining identifiable workstation names.
//
// **Distinct from**:
//   - iter 121 winsoftwarelicences — individual licence files
//
// Headline finding shapes:
//
//   - `has_pii_software=1` — at least one inventory row
//     matches the PII/financial/PHI catalogue.
//   - `has_unlicensed_software=1` — unlicensed / activation-
//     pending marker present.
//   - `is_stale_inventory=1` — inventory timestamp older
//     than 90 days from clock.
//   - `is_credential_exposure_risk=1` — readable file +
//     hostname + (PII OR unlicensed).
//
// Read-only by intent. (Project guideline 4.2.)
package winsamexports

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

// MaxFileBytes bounds per-file read (32 MiB — SAM dumps for
// large environments can be sizable).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// StaleInventoryWindow — inventory_age_days > this triggers
// is_stale_inventory.
const StaleInventoryWindow = 90 * 24 * time.Hour

// ToolKind pinned to host_sam_exports.tool_kind.
type ToolKind string

const (
	ToolSCCM           ToolKind = "sccm"
	ToolIntune         ToolKind = "intune"
	ToolLansweeper     ToolKind = "lansweeper"
	ToolSnowLM         ToolKind = "snow-lm"
	ToolFlexera        ToolKind = "flexera"
	ToolDesktopCentral ToolKind = "desktop-central"
	ToolBigFix         ToolKind = "bigfix"
	ToolWingetExport   ToolKind = "winget-export"
	ToolChocolateyList ToolKind = "chocolatey-list"
	ToolGLPI           ToolKind = "glpi"
	ToolOCSInventory   ToolKind = "ocs-inventory"
	ToolGenericCSV     ToolKind = "generic-csv"
	ToolOther          ToolKind = "other"
	ToolUnknown        ToolKind = "unknown"
)

// Row mirrors host_sam_exports' column shape.
type Row struct {
	FilePath                 string   `json:"file_path"`
	FileHash                 string   `json:"file_hash"`
	UserProfile              string   `json:"user_profile,omitempty"`
	ToolKind                 ToolKind `json:"tool_kind"`
	AssetHostnameHash        string   `json:"asset_hostname_hash,omitempty"`
	InventoryTimestamp       string   `json:"inventory_timestamp,omitempty"`
	SoftwareCount            int64    `json:"software_count,omitempty"`
	PIISoftwareCount         int64    `json:"pii_software_count,omitempty"`
	UnlicensedCount          int64    `json:"unlicensed_count,omitempty"`
	PublishersDistinctCount  int64    `json:"publishers_distinct_count,omitempty"`
	InventoryAgeDays         int64    `json:"inventory_age_days,omitempty"`
	FileOwnerUID             int      `json:"file_owner_uid,omitempty"`
	FileMode                 int      `json:"file_mode,omitempty"`
	FileSize                 int64    `json:"file_size,omitempty"`
	HasPIISoftware           bool     `json:"has_pii_software"`
	HasUnlicensedSoftware    bool     `json:"has_unlicensed_software"`
	IsStaleInventory         bool     `json:"is_stale_inventory"`
	IsRecent                 bool     `json:"is_recent"`
	IsWorldReadable          bool     `json:"is_world_readable"`
	IsGroupReadable          bool     `json:"is_group_readable"`
	IsCredentialExposureRisk bool     `json:"is_credential_exposure_risk"`
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

// HashHostname returns the SHA-256 hex of a hostname, prefixed
// with `sha256:` so callers can tell hashed vs raw apart at a
// glance.
func HashHostname(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(h))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set for
// SAM-tool exports. Windows-centric first.
func DefaultInstallRoots() []string {
	return []string{
		// Windows — SCCM / Intune / Lansweeper / SnowLM / Flexera
		// commonly drop exports under ProgramData or per-tool
		// install paths.
		`C:\ProgramData\Microsoft\Configuration Manager\Inventory`,
		`C:\Program Files\Microsoft Configuration Manager`,
		`C:\ProgramData\Lansweeper`,
		`C:\ProgramData\SnowSoftware`,
		`C:\Program Files (x86)\Snow Software`,
		`C:\ProgramData\Flexera Software`,
		`C:\Program Files (x86)\Flexera`,
		`C:\ProgramData\DesktopCentral`,
		`C:\Program Files (x86)\ManageEngine\DesktopCentral_Server`,
		`C:\Program Files (x86)\BigFix Enterprise`,
		`C:\ProgramData\BigFix`,
		`C:\ProgramData\GLPI-Agent`,
		`C:\ProgramData\OCS Inventory NG`,
		`C:\Program Files\WindowsApps`,
		`C:\ProgramData\chocolatey`,
		// Cross-OS bonus.
		`/var/lib/glpi-agent`,
		`/var/lib/ocsinventory-agent`,
		`/opt/lansweeper`,
		`/opt/snow`,
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

// UserSAMDirs is the curated per-user relative path set.
// winget export and choco list are typically dropped under
// Documents or AppData.
func UserSAMDirs() [][]string {
	return [][]string{
		{"Documents", "SAM"},
		{"Documents", "Inventory"},
		{"Documents", "SoftwareInventory"},
		{
			"AppData", "Local", "Packages",
			"Microsoft.DesktopAppInstaller_8wekyb3d8bbwe",
		},
		{"AppData", "Local", "Microsoft", "WinGet"},
		{"AppData", "Roaming", "chocolatey"},
	}
}

// IsCandidateExt reports whether the extension carries a
// SAM-export artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".csv", ".xml", ".json", ".tsv", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SAM-export catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"sccm_software", "sccm-software",
		"intune_software", "intune-software", "intune-devices",
		"lansweeper_software", "lansweeper-software",
		"lansweeper-inventory",
		"snow_inventory", "snow-inventory",
		"snowlm-export",
		"flexera_inventory", "flexera-inventory",
		"flexera_software",
		"desktopcentral_software", "desktopcentral-software",
		"dc_software", "dc-software",
		"bigfix_software", "bigfix-software", "bigfix_inventory",
		"winget-export", "winget_export",
		"choco-list", "choco_list", "chocolatey-list",
		"glpi_software", "glpi-software", "glpi_inventory",
		"ocs_software", "ocs-software", "ocs_inventory",
		"software_inventory", "software-inventory",
		"installed_software",
		"asset_software", "asset-software",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ToolKindFromName classifies the SAM-tool kind by filename.
func ToolKindFromName(name string) ToolKind {
	if strings.TrimSpace(name) == "" {
		return ToolUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "sccm"):
		return ToolSCCM
	case strings.Contains(n, "intune"):
		return ToolIntune
	case strings.Contains(n, "lansweeper"):
		return ToolLansweeper
	case strings.Contains(n, "snow_inventory") ||
		strings.Contains(n, "snow-inventory") ||
		strings.Contains(n, "snowlm"):
		return ToolSnowLM
	case strings.Contains(n, "flexera"):
		return ToolFlexera
	case strings.Contains(n, "desktopcentral") ||
		strings.Contains(n, "dc_software") ||
		strings.Contains(n, "dc-software"):
		return ToolDesktopCentral
	case strings.Contains(n, "bigfix"):
		return ToolBigFix
	case strings.Contains(n, "winget"):
		return ToolWingetExport
	case strings.Contains(n, "choco"):
		return ToolChocolateyList
	case strings.Contains(n, "glpi"):
		return ToolGLPI
	case strings.Contains(n, "ocs_") || strings.Contains(n, "ocs-"):
		return ToolOCSInventory
	case strings.Contains(n, "software_inventory") ||
		strings.Contains(n, "software-inventory") ||
		strings.Contains(n, "installed_software"):
		return ToolGenericCSV
	}
	return ToolOther
}

// hostnameRE matches a hostname field in CSV / XML / JSON
// SAM exports. Accepts `hostname`, `host_name`, `host-name`,
// `computer_name`, `computername`, etc. with `:`, `=`, `,`,
// or `>` (XML tag) as the separator.
var hostnameRE = regexp.MustCompile(`(?i)(?:host[_\-\s]?name?|computer[_\-\s]?name?|asset[_\-\s]?name|machine[_\-\s]?name)\s*[:=,>]\s*"?([A-Za-z0-9._\-]{2,64})"?`)

// HostnameFromText extracts a hostname from text. Returns the
// raw hostname — caller MUST hash before persisting.
func HostnameFromText(text string) string {
	m := hostnameRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// inventoryTimeRE matches an ISO timestamp on lines containing
// inventory / scan / collection markers.
var inventoryTimeRE = regexp.MustCompile(`(?i)(?:inventory|scan|collection|generated|exported)[_\-\s]?(?:at|date|time|timestamp)?\s*[:=,>]?\s*"?(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[Tt\s](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)?)`)

// InventoryTimestampFromText extracts an ISO timestamp.
func InventoryTimestampFromText(text string) string {
	m := inventoryTimeRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// PIIHandlingMarkers — fingerprints copied from iter 121
// winsoftwarelicences (kept local to avoid cross-package
// dependency). Any line whose lowercased content contains
// one of these markers counts as a PII-handling software row.
func PIIHandlingMarkers() []string {
	return []string{
		// PII / CRM / ERP
		"salesforce", "sap", "dynamics 365", "hubspot",
		"zoho", "workday", "successfactor", "oracle ebs",
		// Email / collaboration
		"outlook", "thunderbird", "slack", "teams", "zoom",
		// Browsers
		"chrome", "firefox", "edge", "safari",
		// Financial / accounting
		"quickbooks", "sage", "xero", "tango/04", "tango04",
		"meta4", "bejerman", "calipso", "holistor",
		"contabilium", "tiendanube", "mercadopago",
		// EHR / PHI
		"epic", "cerner", "openemr", "meditech",
		// PCI / payments
		"stripe", "adyen", "first data", "prisma", "posnet",
	}
}

// CountPIIRows scans the body, returning the count of lines
// containing PII-handling product markers.
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

// UnlicensedMarkers — lowercased substring fingerprints that
// indicate an unlicensed / activation-pending row.
func UnlicensedMarkers() []string {
	return []string{
		"unlicensed", "not licensed", "activation required",
		"trial expired", "license expired", "deactivated",
		"not activated", "license missing",
	}
}

// CountUnlicensedRows scans the body, returning the count of
// rows that match any unlicensed marker.
func CountUnlicensedRows(body []byte) int64 {
	lower := strings.ToLower(string(body))
	var count int64
	for _, line := range strings.Split(lower, "\n") {
		for _, marker := range UnlicensedMarkers() {
			if strings.Contains(line, marker) {
				count++
				break
			}
		}
	}
	return count
}

// SoftwareRowCount returns the number of non-header CSV-like
// rows in the body (used as a software-row proxy for non-XML
// formats).
func SoftwareRowCount(body []byte) int64 {
	scanner := strings.Split(string(body), "\n")
	if len(scanner) == 0 {
		return 0
	}
	var count int64
	for i, line := range scanner {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Skip the first non-empty line if it looks like a CSV
		// header (no digits and contains a comma).
		if i == 0 && !strings.ContainsAny(line, "0123456789") &&
			strings.Contains(line, ",") {
			continue
		}
		count++
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
	if r.PIISoftwareCount > 0 {
		r.HasPIISoftware = true
	}
	if r.UnlicensedCount > 0 {
		r.HasUnlicensedSoftware = true
	}
	// Stale inventory: compare inventory_timestamp to clock.
	if r.InventoryTimestamp != "" {
		// Accept either YYYY-MM-DD or full RFC3339-ish.
		layouts := []string{
			time.RFC3339, "2006-01-02T15:04:05",
			"2006-01-02 15:04:05", "2006-01-02",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, r.InventoryTimestamp); err == nil {
				age := now().Sub(t)
				if age > 0 {
					r.InventoryAgeDays = int64(age.Hours() / 24)
				}
				if age > StaleInventoryWindow {
					r.IsStaleInventory = true
				}
				break
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasRisk := r.HasPIISoftware || r.HasUnlicensedSoftware
	if hasReadable && r.AssetHostnameHash != "" && hasRisk {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ToolKind != rs[j].ToolKind {
			return rs[i].ToolKind < rs[j].ToolKind
		}
		return rs[i].InventoryTimestamp < rs[j].InventoryTimestamp
	})
}
