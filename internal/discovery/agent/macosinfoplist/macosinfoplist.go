// Package macosinfoplist audits macOS .app bundle Info.plist
// files cached on macOS workstations.
//
// macOS plists carry the canonical software-licence
// inventory fields (CFBundleIdentifier, CFBundleDisplayName,
// CFBundleShortVersionString, NSHumanReadableCopyright,
// LSApplicationCategoryType) AND the authoritative DP/DS
// declaration set — Apple's NS*UsageDescription privacy keys
// that TCC enforces at the OS level.
//
// **Distinct from**:
//   - iter 121 winsoftwarelicences  per-licence file (any OS)
//   - iter 122 winsamexports        SAM-tool exports
//   - iter 123 winregistryuninstall Windows Uninstall
//   - iter 124 winsbom              SBOM artifacts
//   - iter 125 winchocolatey        Chocolatey nuspec
//   - iter 126 winwingetexport      winget exports
//
// Headline finding shapes:
//
//   - `has_camera_access=1` — NSCameraUsageDescription.
//   - `has_microphone_access=1` — NSMicrophoneUsageDescription.
//   - `has_location_access=1` — any NSLocation* key.
//   - `has_contacts_access=1` — NSContactsUsageDescription.
//   - `has_photos_access=1` — NSPhotoLibraryUsageDescription.
//   - `has_calendar_access=1` — NSCalendarsUsageDescription.
//   - `has_health_access=1` — NSHealth* keys (HIPAA scope).
//   - `has_faceid_access=1` — NSFaceIDUsageDescription
//     (biometric PII).
//   - `is_pii_handling=1` — any privacy key OR catalogue
//     match on bundle_id / publisher.
//   - `is_credential_exposure_risk=1` — readable file +
//     bundle_id + is_pii_handling.
//
// Read-only by intent. (Project guideline 4.2.)
package macosinfoplist

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

// MaxFileBytes bounds per-file read (2 MiB — Info.plist
// files are typically a few KiB; embedded ones can reach
// hundreds of KiB).
const MaxFileBytes = 2 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_macos_info_plist.artifact_kind.
type ArtifactKind string

const (
	KindAppInfoPlist      ArtifactKind = "app-info-plist"
	KindLicensePlist      ArtifactKind = "license-plist"
	KindEmbeddedInfoPlist ArtifactKind = "embedded-info-plist"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// DPDSClass pinned to host_macos_info_plist.dp_ds_class.
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

// Row mirrors host_macos_info_plist' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	BundleID                 string       `json:"bundle_id,omitempty"`
	Publisher                string       `json:"publisher,omitempty"`
	DisplayName              string       `json:"display_name,omitempty"`
	Version                  string       `json:"version,omitempty"`
	Copyright                string       `json:"copyright,omitempty"`
	Category                 string       `json:"category,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	PrivacyKeysCount         int64        `json:"privacy_keys_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCameraAccess          bool         `json:"has_camera_access"`
	HasMicrophoneAccess      bool         `json:"has_microphone_access"`
	HasLocationAccess        bool         `json:"has_location_access"`
	HasContactsAccess        bool         `json:"has_contacts_access"`
	HasPhotosAccess          bool         `json:"has_photos_access"`
	HasCalendarAccess        bool         `json:"has_calendar_access"`
	HasHealthAccess          bool         `json:"has_health_access"`
	HasFaceIDAccess          bool         `json:"has_faceid_access"`
	HasAppleEventsAccess     bool         `json:"has_appleevents_access"`
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

// DefaultInstallRoots is the curated macOS install-root set.
func DefaultInstallRoots() []string {
	return []string{
		"/Applications",
		"/System/Applications",
		"/Library/Application Support",
		"/Library/Caches",
		// Cross-OS fallback when plist exports land on shared mounts.
		`C:\Apple\plists`,
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

// UserPlistDirs is the curated per-user relative path set
// for Info.plist + license.plist files.
func UserPlistDirs() [][]string {
	return [][]string{
		{"Applications"},
		{"Library", "Application Support"},
		{"Library", "Containers"},
		{"Library", "Preferences"},
		{"Documents", "plists"},
	}
}

// IsCandidateExt reports whether the extension carries a
// plist artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".plist":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the plist catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"info.plist", "license.plist", "license-info.plist",
		"registration.plist", "softwareupdate.plist",
		"appstore.plist", "purchasehistory.plist",
	} {
		if n == tok {
			return true
		}
	}
	if strings.HasSuffix(n, ".plist") &&
		(strings.HasPrefix(n, "info") || strings.HasPrefix(n, "license") ||
			strings.HasPrefix(n, "registration")) {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a plist by its path.
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
	case strings.HasSuffix(base, "info.plist") &&
		strings.Contains(lower, ".app/contents/"):
		return KindAppInfoPlist
	case strings.HasSuffix(base, "info.plist"):
		// Helper bundles / frameworks under
		// /Library/Application Support carry embedded
		// Info.plist files without the .app suffix.
		return KindEmbeddedInfoPlist
	case strings.HasSuffix(base, "license.plist") ||
		strings.HasSuffix(base, "license-info.plist") ||
		strings.HasSuffix(base, "registration.plist"):
		return KindLicensePlist
	}
	return KindOther
}

// PublisherFromBundleID extracts the publisher slug from a
// reverse-DNS bundle identifier. `com.microsoft.Outlook` →
// `microsoft`, `us.zoom.xos` → `zoom`. Returns "" for
// unparseable input.
func PublisherFromBundleID(bundleID string) string {
	t := strings.ToLower(strings.TrimSpace(bundleID))
	parts := strings.Split(t, ".")
	switch {
	case len(parts) < 2:
		return ""
	case isCommonTLD(parts[0]):
		if len(parts) < 3 {
			return ""
		}
		return parts[1]
	}
	return parts[0]
}

// ProductFromBundleID extracts the product slug from a
// reverse-DNS bundle identifier — the segment after the
// publisher. Returns the bundle_id unchanged when the
// reverse-DNS pattern doesn't apply.
func ProductFromBundleID(bundleID string) string {
	t := strings.TrimSpace(bundleID)
	parts := strings.Split(t, ".")
	switch {
	case len(parts) < 2:
		return t
	case len(parts) >= 3 && isCommonTLD(strings.ToLower(parts[0])):
		return parts[2]
	default:
		return parts[1]
	}
}

func isCommonTLD(s string) bool {
	switch s {
	case "com", "org", "net", "io", "ar", "br", "edu", "gov",
		"us", "uk", "de", "fr", "jp", "ca", "au", "es",
		"mx", "co", "info", "app", "dev":
		return true
	}
	return false
}

// PrivacyKeyMap maps lowercased macOS privacy keys to the
// boolean field they should set on a Row. Used by parser
// + classifier.
func PrivacyKeyMap() map[string]string {
	return map[string]string{
		"nscamerausagedescription":                     "camera",
		"nsmicrophoneusagedescription":                 "microphone",
		"nslocationusagedescription":                   "location",
		"nslocationwheninuseusagedescription":          "location",
		"nslocationalwaysusagedescription":             "location",
		"nslocationalwaysandwheninuseusagedescription": "location",
		"nscontactsusagedescription":                   "contacts",
		"nsphotolibraryusagedescription":               "photos",
		"nsphotolibraryaddusagedescription":            "photos",
		"nscalendarsusagedescription":                  "calendar",
		"nsremindersusagedescription":                  "calendar",
		"nshealthshareusagedescription":                "health",
		"nshealthupdateusagedescription":               "health",
		"nsfaceidusagedescription":                     "faceid",
		"nsappleeventsusagedescription":                "appleevents",
	}
}

// PrivacyKeyToField updates the matching boolean field on r
// for a given lowercased privacy-key name.
func PrivacyKeyToField(r *Row, key string) bool {
	field := PrivacyKeyMap()[strings.ToLower(key)]
	switch field {
	case "camera":
		r.HasCameraAccess = true
	case "microphone":
		r.HasMicrophoneAccess = true
	case "location":
		r.HasLocationAccess = true
	case "contacts":
		r.HasContactsAccess = true
	case "photos":
		r.HasPhotosAccess = true
	case "calendar":
		r.HasCalendarAccess = true
	case "health":
		r.HasHealthAccess = true
	case "faceid":
		r.HasFaceIDAccess = true
	case "appleevents":
		r.HasAppleEventsAccess = true
	default:
		return false
	}
	return true
}

// PIIBundleMarkers — lowercased bundle-id substrings that
// flag a PII/financial/PHI/PCI app irrespective of privacy
// keys. Shared with iters 121-126.
func PIIBundleMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// Microsoft
		"com.microsoft.outlook":   DPDSHandlesPII,
		"com.microsoft.teams":     DPDSHandlesPII,
		"com.microsoft.onedrive":  DPDSHandlesPII,
		"com.microsoft.skype":     DPDSHandlesPII,
		"com.microsoft.edgemac":   DPDSHandlesPII,
		"com.microsoft.officemac": DPDSHandlesPII,
		// Browsers
		"com.google.chrome":   DPDSHandlesPII,
		"org.mozilla.firefox": DPDSHandlesPII,
		"com.apple.safari":    DPDSHandlesPII,
		"com.brave.browser":   DPDSHandlesPII,
		// Collaboration
		"com.tinyspeck.slackmacgap": DPDSHandlesPII,
		"us.zoom.xos":               DPDSHandlesPII,
		"com.webex.meetingmanager":  DPDSHandlesPII,
		// CRM / ERP
		"com.salesforce.": DPDSHandlesPII,
		"com.sap.":        DPDSHandlesPII,
		// Accounting / financial
		"com.intuit.quickbooksmac": DPDSHandlesFinancial,
		"com.sage.":                DPDSHandlesFinancial,
		"com.xero.":                DPDSHandlesFinancial,
		"com.tango04.":             DPDSHandlesFinancial,
		"com.bejerman.":            DPDSHandlesFinancial,
		"com.contabilium.":         DPDSHandlesFinancial,
		"com.mercadopago.":         DPDSHandlesFinancial,
		// EHR / PHI
		"com.epic.":   DPDSHandlesPHI,
		"com.cerner.": DPDSHandlesPHI,
		// Payments / PCI
		"com.stripe.": DPDSHandlesPCI,
		"com.adyen.":  DPDSHandlesPCI,
		"com.prisma.": DPDSHandlesPCI,
		// Dev / utility
		"com.jetbrains.":       DPDSDevTool,
		"com.microsoft.vscode": DPDSDevTool,
		"com.docker.":          DPDSDevTool,
		"org.git-scm.":         DPDSDevTool,
		// Media
		"com.adobe.acrobat.reader": DPDSMediaTool,
		"com.adobe.photoshop":      DPDSMediaTool,
		"com.apple.preview":        DPDSMediaTool,
	}
}

// ClassifyDPDS returns the best-effort DP/DS classification
// for a row based on its privacy-key flags + catalogue. Order
// of precedence:
//  1. catalogue match on bundle_id wins (most specific).
//  2. health-access → handles-phi.
//  3. faceid-access → handles-biometric.
//  4. camera/microphone/contacts/photos/calendar/location →
//     handles-pii.
//  5. anything else → unknown.
func ClassifyDPDS(r *Row) DPDSClass {
	hay := strings.ToLower(r.BundleID)
	for marker, cls := range PIIBundleMarkers() {
		if strings.Contains(hay, marker) {
			return cls
		}
	}
	switch {
	case r.HasHealthAccess:
		return DPDSHandlesPHI
	case r.HasFaceIDAccess:
		return DPDSHandlesBiometric
	case r.HasCameraAccess, r.HasMicrophoneAccess,
		r.HasContactsAccess, r.HasPhotosAccess,
		r.HasCalendarAccess, r.HasLocationAccess:
		return DPDSHandlesPII
	}
	return DPDSUnknown
}

// IsPIIHandlingClass reports membership in the PII-handling
// set (incl. financial, PHI, PCI, biometric).
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
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.DPDSClass == "" || r.DPDSClass == DPDSUnknown {
		r.DPDSClass = ClassifyDPDS(r)
	}
	if IsPIIHandlingClass(r.DPDSClass) {
		r.IsPIIHandling = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.BundleID != "" && r.IsPIIHandling {
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
		return rs[i].BundleID < rs[j].BundleID
	})
}
