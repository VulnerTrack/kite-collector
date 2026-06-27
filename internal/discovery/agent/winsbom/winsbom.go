// Package winsbom audits SBOM (Software Bill of Materials)
// artifact files cached on workstations: SPDX, CycloneDX,
// and SWID tags. SBOM is the compliance-mandated standard
// for software-licence + supply-chain inventory under US
// EO 14028, NIST SP 800-218 SSDF, EU CRA, ISO/IEC 5962
// (SPDX), and ISO/IEC 19770-2 (SWID).
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), and iter 123
// winregistryuninstall (host-native).
//
// Headline finding shapes:
//
//   - `has_pii_components=1` — at least one component
//     matches the PII / financial / PHI catalogue.
//   - `has_vulnerable_components=1` — any CVE-XXXX-YYYYY
//     reference present in the body.
//   - `has_oss_components=1` — at least one OSS-licensed
//     component.
//   - `is_credential_exposure_risk=1` — readable file +
//     components > 0 + (PII OR vulnerable).
//
// Read-only by intent. (Project guideline 4.2.)
package winsbom

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

// MaxFileBytes bounds per-file read (64 MiB — large
// SBOMs for OS images can be sizable).
const MaxFileBytes = 64 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_sbom_artifacts.artifact_kind.
type ArtifactKind string

const (
	KindSPDXJSON      ArtifactKind = "spdx-json"
	KindSPDXTagValue  ArtifactKind = "spdx-tag-value"
	KindSPDXYAML      ArtifactKind = "spdx-yaml"
	KindCycloneDXJSON ArtifactKind = "cyclonedx-json"
	KindCycloneDXXML  ArtifactKind = "cyclonedx-xml"
	KindSWIDTag       ArtifactKind = "swid-tag"
	KindOther         ArtifactKind = "other"
	KindUnknown       ArtifactKind = "unknown"
)

// SBOMFormat pinned to host_sbom_artifacts.sbom_format.
type SBOMFormat string

const (
	FormatSPDX22      SBOMFormat = "spdx-2.2"
	FormatSPDX23      SBOMFormat = "spdx-2.3"
	FormatSPDX30      SBOMFormat = "spdx-3.0"
	FormatCycloneDX14 SBOMFormat = "cyclonedx-1.4"
	FormatCycloneDX15 SBOMFormat = "cyclonedx-1.5"
	FormatCycloneDX16 SBOMFormat = "cyclonedx-1.6"
	FormatSWID197702  SBOMFormat = "swid-iso-19770-2"
	FormatOther       SBOMFormat = "other"
	FormatUnknown     SBOMFormat = "unknown"
)

// Row mirrors host_sbom_artifacts' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	SBOMFormat               SBOMFormat   `json:"sbom_format"`
	DocumentName             string       `json:"document_name,omitempty"`
	DocumentNamespace        string       `json:"document_namespace,omitempty"`
	CreatorOrg               string       `json:"creator_org,omitempty"`
	CreationDateYYYYMMDD     string       `json:"creation_date_yyyymmdd,omitempty"`
	ComponentCount           int64        `json:"component_count,omitempty"`
	PIIComponentCount        int64        `json:"pii_component_count,omitempty"`
	VulnerableComponentCount int64        `json:"vulnerable_component_count,omitempty"`
	OSSComponentCount        int64        `json:"oss_component_count,omitempty"`
	LicenseDistinctCount     int64        `json:"license_distinct_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPIIComponents         bool         `json:"has_pii_components"`
	HasVulnerableComponents  bool         `json:"has_vulnerable_components"`
	HasOSSComponents         bool         `json:"has_oss_components"`
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
// SBOM artifacts.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ProgramData\SBOM`,
		`C:\ProgramData\sbom-cache`,
		`C:\Scripts\sbom`,
		`C:\Build\sbom`,
		`C:\Artifacts\sbom`,
		`/var/lib/sbom`,
		`/srv/sbom`,
		`/opt/sbom`,
		`/usr/share/sbom`,
		`/etc/sbom`,
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

// UserSBOMDirs is the curated per-user relative path set.
func UserSBOMDirs() [][]string {
	return [][]string{
		{"Documents", "SBOM"},
		{"Documents", "sbom"},
		{"Documents", "Compliance", "sbom"},
		{".cache", "sbom"},
		{"AppData", "Local", "SBOM"},
		{"AppData", "Roaming", "SBOM"},
	}
}

// IsCandidateExt reports whether the extension carries an
// SBOM artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".spdx", ".json", ".xml", ".yaml", ".yml",
		".swidtag", ".tag":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SBOM catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		".spdx", "spdx.json", "spdx.yaml", "spdx.yml",
		".cdx.json", ".cdx.xml",
		".bom.json", ".bom.xml",
		".cyclonedx.json", ".cyclonedx.xml",
		"cyclonedx-", "cyclonedx_",
		"sbom-", "sbom_", "sbom.json", "sbom.xml",
		".swidtag",
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
	case strings.HasSuffix(n, ".swidtag"):
		return KindSWIDTag
	case strings.HasSuffix(n, ".cdx.json") ||
		strings.HasSuffix(n, ".cyclonedx.json") ||
		strings.HasSuffix(n, ".bom.json"):
		return KindCycloneDXJSON
	case strings.HasSuffix(n, ".cdx.xml") ||
		strings.HasSuffix(n, ".cyclonedx.xml") ||
		strings.HasSuffix(n, ".bom.xml"):
		return KindCycloneDXXML
	case strings.HasSuffix(n, ".spdx.json") ||
		strings.HasSuffix(n, "spdx.json"):
		return KindSPDXJSON
	case strings.HasSuffix(n, ".spdx.yaml") ||
		strings.HasSuffix(n, ".spdx.yml") ||
		strings.HasSuffix(n, "spdx.yaml") ||
		strings.HasSuffix(n, "spdx.yml"):
		return KindSPDXYAML
	case strings.HasSuffix(n, ".spdx"):
		return KindSPDXTagValue
	case strings.Contains(n, "cyclonedx"):
		return KindCycloneDXJSON
	case strings.Contains(n, "sbom"):
		return KindOther
	}
	return KindOther
}

// DetectFormat returns the SBOM format from a body excerpt.
func DetectFormat(body []byte) SBOMFormat {
	if len(body) == 0 {
		return FormatUnknown
	}
	lower := strings.ToLower(string(body))
	// SPDX explicit versions.
	switch {
	case strings.Contains(lower, `"spdxversion": "spdx-2.2"`),
		strings.Contains(lower, `spdxversion: spdx-2.2`):
		return FormatSPDX22
	case strings.Contains(lower, `"spdxversion": "spdx-2.3"`),
		strings.Contains(lower, `spdxversion: spdx-2.3`):
		return FormatSPDX23
	case strings.Contains(lower, `"spdxversion": "spdx-3.0"`),
		strings.Contains(lower, `spdxversion: spdx-3.0`):
		return FormatSPDX30
	}
	// CycloneDX specVersion.
	switch {
	case strings.Contains(lower, `"specversion": "1.4"`),
		strings.Contains(lower, `specversion="1.4"`):
		return FormatCycloneDX14
	case strings.Contains(lower, `"specversion": "1.5"`),
		strings.Contains(lower, `specversion="1.5"`):
		return FormatCycloneDX15
	case strings.Contains(lower, `"specversion": "1.6"`),
		strings.Contains(lower, `specversion="1.6"`):
		return FormatCycloneDX16
	}
	// SWID.
	if strings.Contains(lower, "<softwareidentity") {
		return FormatSWID197702
	}
	// Generic SPDX.
	if strings.Contains(lower, "spdx") {
		return FormatSPDX23
	}
	// Generic CycloneDX.
	if strings.Contains(lower, "cyclonedx") {
		return FormatCycloneDX15
	}
	return FormatOther
}

// cveRefRE matches CVE-YYYY-NNNN (4-7 digits).
var cveRefRE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// CountVulnerableComponents counts CVE references seen in
// the body.
func CountVulnerableComponents(body []byte) int64 {
	return int64(len(cveRefRE.FindAllIndex(body, -1)))
}

// componentSPDXRE matches an SPDX `PackageName:` entry or
// JSON `"name":` inside SPDX `packages[]`.
var componentSPDXRE = regexp.MustCompile(`(?im)^PackageName:\s*(\S.*)$`)

// componentCDXRE matches a CycloneDX `"name":` field inside a
// components[] block. Best-effort regex.
var componentCDXRE = regexp.MustCompile(`(?i)"name"\s*:\s*"([^"]+)"`)

// CountComponentsSPDX counts PackageName: entries.
func CountComponentsSPDX(body []byte) int64 {
	return int64(len(componentSPDXRE.FindAllIndex(body, -1)))
}

// CountComponentsCycloneDX counts "name": occurrences in a
// CycloneDX body. Over-counts metadata-name fields, so callers
// should subtract 1 for the document-level name when present.
func CountComponentsCycloneDX(body []byte) int64 {
	return int64(len(componentCDXRE.FindAllIndex(body, -1)))
}

// CountComponents returns the best-effort component count for
// any SBOM format.
func CountComponents(body []byte, kind ArtifactKind) int64 {
	switch kind {
	case KindSPDXTagValue, KindSPDXYAML:
		return CountComponentsSPDX(body)
	case KindSPDXJSON:
		c := CountComponentsCycloneDX(body)
		if c > 0 {
			c--
		}
		return c
	case KindCycloneDXJSON, KindCycloneDXXML:
		c := CountComponentsCycloneDX(body)
		if c > 0 {
			c--
		}
		return c
	case KindSWIDTag:
		// SWID = one softwareIdentity tag per file.
		if strings.Contains(strings.ToLower(string(body)),
			"<softwareidentity") {
			return 1
		}
		return 0
	case KindOther, KindUnknown:
		return CountComponentsCycloneDX(body)
	}
	return 0
}

// ossLicenseMarkers — SPDX licence identifiers / common OSS
// licence-name substrings (lowercase).
func ossLicenseMarkers() []string {
	return []string{
		"mit", "apache-2.0", "apache 2.0", "bsd-2-clause",
		"bsd-3-clause", "bsd", "gpl-2.0", "gpl-3.0", "gpl",
		"lgpl-2.1", "lgpl-3.0", "lgpl", "mpl-2.0", "mpl",
		"isc", "cc0-1.0", "unlicense", "wtfpl", "epl-2.0",
		"agpl-3.0", "agpl",
	}
}

// licenseRE matches `"licenseConcluded":` / `"licenseDeclared":`
// / SPDX `LicenseConcluded:` tag-value pairs / CycloneDX
// `"license":` blocks.
var licenseRE = regexp.MustCompile(`(?i)(?:licenseconcluded|licensedeclared|"license"\s*:\s*\{\s*"id"|"license"\s*:)\s*"?([A-Za-z0-9\.\-_+]+)"?`)

// CountOSSComponents returns the count of distinct lines
// containing an OSS-licence marker.
func CountOSSComponents(body []byte) int64 {
	var count int64
	matches := licenseRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		license := strings.ToLower(m[1])
		for _, marker := range ossLicenseMarkers() {
			if license == marker || strings.HasPrefix(license, marker+"-") {
				count++
				break
			}
		}
	}
	return count
}

// CountDistinctLicenses returns the number of distinct
// licence identifiers seen in the body.
func CountDistinctLicenses(body []byte) int64 {
	const maxTokens = 256
	licenses := make(map[string]struct{}, 32)
	for _, m := range licenseRE.FindAllStringSubmatch(string(body), -1) {
		key := strings.ToLower(m[1])
		licenses[key] = struct{}{}
		if len(licenses) >= maxTokens {
			return int64(maxTokens)
		}
	}
	return int64(len(licenses))
}

// PIIHandlingMarkers — fingerprints shared with iters
// 121/122/123. Each marker substring match in the body
// counts toward pii_component_count.
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

// CountPIIComponents walks the body line-by-line and returns
// the count of lines matching a PII marker.
func CountPIIComponents(body []byte) int64 {
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

// docNameSPDXRE / docNameCDXRE extract document name. The
// CycloneDX matcher uses (?is) so `.` crosses newlines and
// the search spans the nested metadata.component block.
var (
	docNameSPDXRE = regexp.MustCompile(`(?im)^DocumentName:\s*(.+)$`)
	docNameCDXRE  = regexp.MustCompile(`(?is)"metadata"\s*:.*?"component"\s*:\s*\{.*?"name"\s*:\s*"([^"]+)"`)
)

// DocumentNameFromBody returns the SBOM document name.
func DocumentNameFromBody(body []byte) string {
	if m := docNameSPDXRE.FindStringSubmatch(string(body)); m != nil {
		return strings.TrimSpace(m[1])
	}
	if m := docNameCDXRE.FindStringSubmatch(string(body)); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// docNamespaceRE captures SPDX DocumentNamespace.
var docNamespaceRE = regexp.MustCompile(`(?im)^DocumentNamespace:\s*(\S+)$|"documentnamespace"\s*:\s*"([^"]+)"|"serialnumber"\s*:\s*"([^"]+)"`)

// DocumentNamespaceFromBody returns SPDX namespace or
// CycloneDX serialNumber.
func DocumentNamespaceFromBody(body []byte) string {
	m := docNamespaceRE.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return strings.TrimSpace(m[i])
		}
	}
	return ""
}

// creatorRE captures SPDX Creator: Organization: <name> or
// CycloneDX metadata.tools[].vendor / supplier.name.
var creatorRE = regexp.MustCompile(`(?im)^Creator:\s*Organization:\s*(.+)$|"vendor"\s*:\s*"([^"]+)"|"supplier"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"`)

// CreatorOrgFromBody returns the SBOM creator-org name.
func CreatorOrgFromBody(body []byte) string {
	m := creatorRE.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return strings.TrimSpace(m[i])
		}
	}
	return ""
}

// creationDateRE captures SPDX `Created:` or CycloneDX
// `"timestamp":` values.
var creationDateRE = regexp.MustCompile(`(?im)^Created:\s*(20\d{2}-\d{2}-\d{2})|"created"\s*:\s*"(20\d{2}-\d{2}-\d{2})|"timestamp"\s*:\s*"(20\d{2}-\d{2}-\d{2})`)

// CreationDateFromBody returns the SBOM creation date as
// YYYYMMDD.
func CreationDateFromBody(body []byte) string {
	m := creationDateRE.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			d := strings.TrimSpace(m[i])
			if len(d) == 10 {
				return d[0:4] + d[5:7] + d[8:10]
			}
			return ""
		}
	}
	return ""
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.PIIComponentCount > 0 {
		r.HasPIIComponents = true
	}
	if r.VulnerableComponentCount > 0 {
		r.HasVulnerableComponents = true
	}
	if r.OSSComponentCount > 0 {
		r.HasOSSComponents = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasRisk := r.HasPIIComponents || r.HasVulnerableComponents
	if hasReadable && r.ComponentCount > 0 && hasRisk {
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
		return rs[i].CreationDateYYYYMMDD < rs[j].CreationDateYYYYMMDD
	})
}
