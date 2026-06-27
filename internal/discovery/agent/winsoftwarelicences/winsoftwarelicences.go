// Package winsoftwarelicences audits Windows-centric
// software-licence artifact files (the most-relevant
// commercial + line-of-business software an enterprise
// typically deploys on Windows endpoints) to support
// ISO/IEC 27001:2022 A.5.32 (software-licence inventory).
// Linux + macOS install roots are also walked for the same
// licence artifact filenames as a portability bonus.
//
// Per asset, the inventory captures product title,
// publisher, install date, purpose, vendor URL, and DP/DS
// classification (datos personales / datos sensibles —
// Ley 25.326 / GDPR / HIPAA / PCI scope).
//
// License keys are NEVER persisted verbatim. Only:
//   - SHA-256 hash of the key (license_key_hash)
//   - SHA-256 hash of the file body (file_hash)
//
// Headline finding shapes:
//
//   - `is_expired=1` — expiry date < clock.
//   - `has_license_key=1` — file body contains a key.
//   - `is_oss_license=1` — recognised OSS licence.
//   - `is_pii_handling=1` — product matches PII catalogue.
//   - `is_credential_exposure_risk=1` — readable file +
//     license key + (PII OR financial OR PHI).
//
// Read-only by intent. (Project guideline 4.2.)
package winsoftwarelicences

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
const MaxRows = 32768

// MaxFileBytes bounds per-file read (4 MiB — licence files
// are small; LICENSE.txt for big OSS packages can grow).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_software_licences.artifact_kind.
type ArtifactKind string

const (
	KindLicKeyfile      ArtifactKind = "lic-keyfile"
	KindLicenseJSON     ArtifactKind = "license-json"
	KindLicenseXML      ArtifactKind = "license-xml"
	KindLicenseText     ArtifactKind = "license-text"
	KindEULAText        ArtifactKind = "eula-text"
	KindRegistrationDat ArtifactKind = "registration-dat"
	KindPlistLicense    ArtifactKind = "plist-license"
	KindDpkgCopyright   ArtifactKind = "dpkg-copyright"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// LicenseType pinned to host_software_licences.license_type.
type LicenseType string

const (
	LicensePerpetual    LicenseType = "perpetual"
	LicenseSubscription LicenseType = "subscription"
	LicenseOSSMIT       LicenseType = "oss-mit"
	LicenseOSSApache    LicenseType = "oss-apache"
	LicenseOSSBSD       LicenseType = "oss-bsd"
	LicenseOSSGPL       LicenseType = "oss-gpl"
	LicenseOSSLGPL      LicenseType = "oss-lgpl"
	LicenseOSSMPL       LicenseType = "oss-mpl"
	LicenseOSSOther     LicenseType = "oss-other"
	LicenseFreeware     LicenseType = "freeware"
	LicenseTrial        LicenseType = "trial"
	LicenseEvaluation   LicenseType = "evaluation"
	LicenseOEM          LicenseType = "oem"
	LicenseEnterprise   LicenseType = "enterprise"
	LicenseOther        LicenseType = "other"
	LicenseUnknown      LicenseType = "unknown"
)

// DPDSClass pinned to host_software_licences.dp_ds_class.
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

// Row mirrors host_software_licences' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	ProductTitle             string       `json:"product_title,omitempty"`
	Publisher                string       `json:"publisher,omitempty"`
	ProductURL               string       `json:"product_url,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	ExpiryDateYYYYMMDD       string       `json:"expiry_date_yyyymmdd,omitempty"`
	LicenseType              LicenseType  `json:"license_type"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	LicenseKeyHash           string       `json:"license_key_hash,omitempty"`
	LicensePurpose           string       `json:"license_purpose,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	IsExpired                bool         `json:"is_expired"`
	HasLicenseKey            bool         `json:"has_license_key"`
	IsOSSLicense             bool         `json:"is_oss_license"`
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

// DefaultInstallRoots is the curated install-root set for
// system-wide licence material. Windows roots come first
// because the target population is enterprise Windows
// endpoints; cross-OS roots follow as a portability bonus.
func DefaultInstallRoots() []string {
	return []string{
		// Windows — most-relevant enterprise install roots.
		`C:\Program Files`,
		`C:\Program Files (x86)`,
		`C:\ProgramData`,
		`C:\ProgramData\Microsoft\Office`,
		`C:\ProgramData\Adobe`,
		`C:\ProgramData\Autodesk`,
		`C:\ProgramData\MathWorks`,
		`C:\ProgramData\JetBrains`,
		`C:\ProgramData\Citrix`,
		`C:\ProgramData\VMware`,
		`C:\ProgramData\Intuit`, // QuickBooks
		`C:\ProgramData\Tango04`,
		`C:\ProgramData\SAP`,
		`C:\ProgramData\ESET`,
		`C:\ProgramData\Symantec`,
		// Cross-OS bonus.
		`/etc`,
		`/opt`,
		`/usr/share/doc`,
		`/usr/share/licenses`,
		`/Applications`,
		`/Library/Application Support`,
	}
}

// MostRelevantWindowsProducts returns the curated catalogue
// of enterprise Windows software whose licences this
// collector is primarily designed to inventory. Used for
// publisher / product hinting when licence files are
// otherwise sparse.
func MostRelevantWindowsProducts() []string {
	return []string{
		// Microsoft
		"microsoft office", "office 365", "microsoft 365",
		"windows server", "sql server", "visual studio",
		"power bi", "dynamics 365",
		// Adobe
		"acrobat", "photoshop", "illustrator", "indesign",
		"premiere pro", "after effects", "lightroom",
		"creative cloud",
		// Engineering / CAD
		"autocad", "revit", "civil 3d", "inventor",
		"solidworks", "matlab", "simulink", "ansys",
		"plaxis", "etabs",
		// Developer tools
		"jetbrains", "intellij", "pycharm", "rider",
		"webstorm", "datagrip", "github desktop",
		// Virtualization / VDI
		"vmware workstation", "vmware horizon",
		"citrix workspace", "citrix receiver",
		"vmware tools", "hyper-v manager",
		// Security
		"eset", "symantec", "mcafee", "trend micro",
		"kaspersky", "crowdstrike", "sentinelone",
		"bitdefender",
		// VPN / Remote
		"forticlient", "cisco anyconnect", "globalprotect",
		"openvpn", "teamviewer", "anydesk",
		// Accounting / ERP (LATAM / global)
		"quickbooks", "sage", "tango", "tango04",
		"meta4", "bejerman", "calipso", "holistor",
		"contabilium", "tiendanube", "sap business one",
		// Collaboration
		"slack", "teams", "zoom", "webex",
		// Browsers + email
		"google chrome", "firefox", "microsoft edge",
		"thunderbird", "outlook",
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

// UserLicenceDirs is the curated per-user relative path set.
func UserLicenceDirs() [][]string {
	return [][]string{
		{".config"},
		{".local", "share"},
		{"AppData", "Local"},
		{"AppData", "Roaming"},
		{"Library", "Application Support"},
		{"Library", "Preferences"},
		{"Documents", "Licenses"},
	}
}

// IsCandidateExt reports whether the extension carries a
// licence artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".lic", ".license", ".key", ".json", ".xml",
		".plist", ".txt", ".dat", ".cer":
		return true
	case "":
		// LICENSE / COPYING / EULA with no extension
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the licence catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	// Bare canonical names.
	for _, tok := range []string{
		"license", "licence", "license.txt", "licence.txt",
		"licensing", "copying", "copyright", "eula",
		"license.json", "license.xml", "license.plist",
		"registration.dat", "activation.dat",
		".lic", ".license", ".key",
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
	switch ext {
	case ".lic", ".key":
		return KindLicKeyfile
	case ".json":
		if strings.Contains(n, "license") || strings.Contains(n, "licence") {
			return KindLicenseJSON
		}
	case ".xml":
		if strings.Contains(n, "license") || strings.Contains(n, "licence") {
			return KindLicenseXML
		}
	case ".plist":
		return KindPlistLicense
	case ".dat":
		if strings.Contains(n, "registration") ||
			strings.Contains(n, "activation") {
			return KindRegistrationDat
		}
	}
	switch {
	case strings.Contains(n, "eula"):
		return KindEULAText
	case strings.Contains(n, "license.txt") ||
		strings.Contains(n, "licence.txt") ||
		strings.HasSuffix(n, "/license") || n == "license" ||
		strings.HasSuffix(n, "/licence") || n == "licence":
		return KindLicenseText
	case strings.Contains(n, "copyright") &&
		strings.Contains(name, "/usr/share/doc/"):
		return KindDpkgCopyright
	case strings.Contains(n, "copying") ||
		strings.Contains(n, "copyright"):
		return KindLicenseText
	}
	return KindOther
}

// productURLRE finds an http/https URL in licence body text.
var productURLRE = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ProductURLFromText extracts the first URL seen.
func ProductURLFromText(text string) string {
	m := productURLRE.FindString(text)
	if m == "" {
		return ""
	}
	// Trim trailing punctuation.
	m = strings.TrimRight(m, ".,);:]")
	return m
}

// licenseKeyRE looks for typical licence-key shapes
// (XXXXX-XXXXX-XXXXX-... or hex-32 or base64-ish strings
// 32+ chars in length introduced by "key" / "license").
var licenseKeyRE = regexp.MustCompile(`(?i)(?:license[_\-\s]?key|product[_\-\s]?key|activation[_\-\s]?key|serial[_\-\s]?number)\s*[:=]?\s*([A-Z0-9]{4,}(?:-[A-Z0-9]{4,}){2,}|[a-f0-9]{32,}|[A-Za-z0-9+/=]{40,})`)

// ExtractLicenseKey returns the first detected raw key.
// Callers MUST hash before persisting — never store raw.
func ExtractLicenseKey(text string) string {
	m := licenseKeyRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// HashLicenseKey returns the SHA-256 hex of the key, prefixed
// with `sha256:` for clarity.
func HashLicenseKey(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OSSMarkers maps body-substring markers to the canonical
// OSS license type.
func OSSMarkers() map[string]LicenseType {
	return map[string]LicenseType{
		"mit license":                       LicenseOSSMIT,
		"permission is hereby granted":      LicenseOSSMIT,
		"apache license":                    LicenseOSSApache,
		"licensed under the apache":         LicenseOSSApache,
		"bsd license":                       LicenseOSSBSD,
		"redistribution and use in source":  LicenseOSSBSD,
		"gnu general public license":        LicenseOSSGPL,
		"gnu lesser general public license": LicenseOSSLGPL,
		"lgpl":                              LicenseOSSLGPL,
		"mozilla public license":            LicenseOSSMPL,
	}
}

// CommercialMarkers maps body-substring markers to commercial
// license types.
func CommercialMarkers() map[string]LicenseType {
	return map[string]LicenseType{
		"subscription":       LicenseSubscription,
		"trial version":      LicenseTrial,
		"evaluation copy":    LicenseEvaluation,
		"perpetual license":  LicensePerpetual,
		"enterprise license": LicenseEnterprise,
		"oem license":        LicenseOEM,
		"original equipment": LicenseOEM,
		"freeware":           LicenseFreeware,
		"free for personal":  LicenseFreeware,
	}
}

// ClassifyLicenseTypeFromText returns the best-match license
// type.
func ClassifyLicenseTypeFromText(text string) LicenseType {
	lower := strings.ToLower(text)
	for marker, typ := range OSSMarkers() {
		if strings.Contains(lower, marker) {
			return typ
		}
	}
	for marker, typ := range CommercialMarkers() {
		if strings.Contains(lower, marker) {
			return typ
		}
	}
	return LicenseUnknown
}

// IsOSSLicenseType reports whether the license type is OSS.
func IsOSSLicenseType(t LicenseType) bool {
	switch t {
	case LicenseOSSMIT, LicenseOSSApache, LicenseOSSBSD,
		LicenseOSSGPL, LicenseOSSLGPL, LicenseOSSMPL,
		LicenseOSSOther:
		return true
	case LicensePerpetual, LicenseSubscription, LicenseFreeware,
		LicenseTrial, LicenseEvaluation, LicenseOEM,
		LicenseEnterprise, LicenseOther, LicenseUnknown:
		return false
	}
	return false
}

// PIIHandlingProducts is the curated catalogue of product
// fingerprints that indicate PII / financial / medical
// data processing. Keys are lowercase substring matches
// against product title or publisher.
func PIIHandlingProducts() map[string]DPDSClass {
	return map[string]DPDSClass{
		// PII / CRM / ERP
		"salesforce":    DPDSHandlesPII,
		"sap":           DPDSHandlesPII,
		"oracle ebs":    DPDSHandlesPII,
		"dynamics":      DPDSHandlesPII,
		"hubspot":       DPDSHandlesPII,
		"zoho":          DPDSHandlesPII,
		"workday":       DPDSHandlesPII,
		"successfactor": DPDSHandlesPII,
		// Email / collaboration
		"outlook":     DPDSHandlesPII,
		"thunderbird": DPDSHandlesPII,
		"slack":       DPDSHandlesPII,
		"teams":       DPDSHandlesPII,
		// Browsers (process credentials + cookies)
		"chrome":  DPDSHandlesPII,
		"firefox": DPDSHandlesPII,
		"edge":    DPDSHandlesPII,
		"safari":  DPDSHandlesPII,
		// Financial / payment / accounting
		"quickbooks":       DPDSHandlesFinancial,
		"sage":             DPDSHandlesFinancial,
		"xero":             DPDSHandlesFinancial,
		"tango":            DPDSHandlesFinancial,
		"tango/04":         DPDSHandlesFinancial,
		"tango04":          DPDSHandlesFinancial,
		"meta4":            DPDSHandlesFinancial,
		"bejerman":         DPDSHandlesFinancial,
		"calipso":          DPDSHandlesFinancial,
		"holistor":         DPDSHandlesFinancial,
		"tango financiero": DPDSHandlesFinancial,
		"contabilium":      DPDSHandlesFinancial,
		"tiendanube":       DPDSHandlesFinancial,
		"mercadopago":      DPDSHandlesFinancial,
		// EHR / PHI
		"epic":     DPDSHandlesPHI,
		"cerner":   DPDSHandlesPHI,
		"openemr":  DPDSHandlesPHI,
		"meditech": DPDSHandlesPHI,
		// PCI
		"stripe":     DPDSHandlesPCI,
		"adyen":      DPDSHandlesPCI,
		"first data": DPDSHandlesPCI,
		"prisma":     DPDSHandlesPCI,
		"posnet":     DPDSHandlesPCI,
		// Dev tools / system utilities
		"jetbrains":     DPDSDevTool,
		"intellij":      DPDSDevTool,
		"visual studio": DPDSDevTool,
		"vscode":        DPDSDevTool,
		"git":           DPDSDevTool,
		"docker":        DPDSDevTool,
		// Media
		"adobe":     DPDSMediaTool,
		"photoshop": DPDSMediaTool,
		"lightroom": DPDSMediaTool,
	}
}

// ClassifyDPDS returns the DP/DS classification for a given
// product/publisher pair.
func ClassifyDPDS(productTitle, publisher string) DPDSClass {
	hay := strings.ToLower(productTitle + " " + publisher)
	if hay == " " {
		return DPDSUnknown
	}
	for marker, cls := range PIIHandlingProducts() {
		if strings.Contains(hay, marker) {
			return cls
		}
	}
	return DPDSUnknown
}

// IsPIIHandlingClass reports whether the DP/DS class implies
// personal-data scope.
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

// dateRE matches an ISO-style date YYYY-MM-DD anywhere.
var dateRE = regexp.MustCompile(`(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])`)

// FirstDateFromText returns the first YYYY-MM-DD seen.
func FirstDateFromText(text string) string {
	m := dateRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[0]
}

// ExpiryDateRE matches a date preceded by an expiry-like word.
var expiryRE = regexp.MustCompile(`(?i)(?:expir(?:y|es?|ation)|valid\s+until|vence|vto\.?|until)[\s:\-]*(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))`)

// ExpiryDateFromText extracts an expiry date from licence text.
func ExpiryDateFromText(text string) string {
	m := expiryRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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
	if r.LicenseKeyHash != "" {
		r.HasLicenseKey = true
	}
	if IsOSSLicenseType(r.LicenseType) {
		r.IsOSSLicense = true
	}
	if IsPIIHandlingClass(r.DPDSClass) {
		r.IsPIIHandling = true
	}
	if r.ExpiryDateYYYYMMDD != "" {
		if t, err := time.Parse("2006-01-02", r.ExpiryDateYYYYMMDD); err == nil {
			if t.Before(now()) {
				r.IsExpired = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.HasLicenseKey && r.IsPIIHandling {
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
		return rs[i].ProductTitle < rs[j].ProductTitle
	})
}
