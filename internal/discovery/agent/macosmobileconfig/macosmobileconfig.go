// Package macosmobileconfig audits macOS MDM configuration
// profile (.mobileconfig) artifacts cached on macOS endpoints
// managed by Apple Business Manager + a third-party MDM
// (Jamf, Microsoft Intune, Kandji, Mosyle, WorkspaceOne).
//
// The licence-inventory mapping is:
//   - title: PayloadDisplayName
//   - manufacturer: PayloadOrganization (MDM authority)
//   - install date: file mtime
//   - purpose: PayloadDescription
//   - URL: vendor page (derived from PayloadOrganization)
//   - DP/DS: handles-pii (MDM profiles control credentials,
//     certificates, FileVault recovery keys, WiFi/VPN secrets)
//
// Closes the macOS device-management layer alongside iter 127
// (Info.plist + TCC privacy keys) and iter 130 (Homebrew).
//
// Headline finding shapes:
//
//   - `has_wifi_payload=1` — WiFi credentials configured.
//   - `has_vpn_payload=1` — VPN config (often with shared
//     secret).
//   - `has_certificate_payload=1` — cert enrollment / trust
//     store modification.
//   - `has_mail_payload=1` — managed mail account.
//   - `has_filevault_payload=1` — FileVault enforcement +
//     recovery-key escrow.
//   - `has_passcode_payload=1` — passcode complexity policy.
//   - `has_app_restrictions=1` — managed app list / blocklist.
//   - `has_managed_apps=1` — managed App Store apps.
//   - `has_kernel_extensions=1` — system extension allowlist.
//   - `has_screensharing=1` — screen-sharing / remote-mgmt.
//   - `is_mdm_enrolled=1` — PayloadOrganization present.
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — always (MDM is credential-bearing).
//   - `is_credential_exposure_risk=1` — readable + payload_uuid
//   - (wifi OR vpn OR certificate OR mail).
//
// Read-only by intent. (Project guideline 4.2.)
package macosmobileconfig

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
const MaxRows = 16384

// MaxFileBytes bounds per-file read (8 MiB — mobileconfig
// profiles are KiB-scale but bundled CA chains can grow).
const MaxFileBytes = 8 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install_date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_macos_mobileconfig.artifact_kind.
type ArtifactKind string

const (
	KindMobileconfigPlist       ArtifactKind = "mobileconfig-plist"
	KindMDMEnrollmentXML        ArtifactKind = "mdm-enrollment-xml"
	KindManagedPreferencesPlist ArtifactKind = "managed-preferences-plist"
	KindJamfPolicyXML           ArtifactKind = "jamf-policy-xml"
	KindIntuneConfigXML         ArtifactKind = "intune-config-xml"
	KindOther                   ArtifactKind = "other"
	KindUnknown                 ArtifactKind = "unknown"
)

// DPDSClass pinned to host_macos_mobileconfig.dp_ds_class.
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

// Row mirrors host_macos_mobileconfig' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	PayloadIdentifier        string       `json:"payload_identifier,omitempty"`
	PayloadDisplayName       string       `json:"payload_display_name,omitempty"`
	PayloadOrganization      string       `json:"payload_organization,omitempty"`
	PayloadUUID              string       `json:"payload_uuid,omitempty"`
	PayloadDescription       string       `json:"payload_description,omitempty"`
	PayloadVersion           string       `json:"payload_version,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	SubpayloadsCount         int64        `json:"subpayloads_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasWifiPayload           bool         `json:"has_wifi_payload"`
	HasVPNPayload            bool         `json:"has_vpn_payload"`
	HasCertificatePayload    bool         `json:"has_certificate_payload"`
	HasMailPayload           bool         `json:"has_mail_payload"`
	HasFileVaultPayload      bool         `json:"has_filevault_payload"`
	HasPasscodePayload       bool         `json:"has_passcode_payload"`
	HasAppRestrictions       bool         `json:"has_app_restrictions"`
	HasManagedApps           bool         `json:"has_managed_apps"`
	HasKernelExtensions      bool         `json:"has_kernel_extensions"`
	HasScreenSharing         bool         `json:"has_screensharing"`
	IsMDMEnrolled            bool         `json:"is_mdm_enrolled"`
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
func DefaultInstallRoots() []string {
	return []string{
		"/Library/Managed Preferences",
		"/var/db/ConfigurationProfiles/Setup",
		"/var/db/ConfigurationProfiles/Store",
		"/Library/Mobile Device Management",
		"/Library/Application Support/JAMF",
		"/Library/Application Support/Microsoft/Intune",
		"/Library/Application Support/Kandji",
		"/Library/Application Support/Mosyle",
		"/Library/Application Support/VMware/WS1",
		// Cross-OS fallback for shared-mount exports.
		`C:\Apple\mobileconfig`,
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

// UserConfigDirs is the curated per-user relative path set.
func UserConfigDirs() [][]string {
	return [][]string{
		{"Library", "Preferences", "com.apple.MCX"},
		{"Library", "Managed Preferences"},
		{"Documents", "MDM"},
	}
}

// IsCandidateExt reports whether the extension carries a
// mobileconfig artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".mobileconfig", ".plist", ".xml":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the mobileconfig catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	if strings.HasSuffix(n, ".mobileconfig") {
		return true
	}
	if strings.HasSuffix(n, ".plist") {
		return true
	}
	if strings.Contains(n, "mdm") && strings.HasSuffix(n, ".xml") {
		return true
	}
	if strings.Contains(n, "jamf") && strings.HasSuffix(n, ".xml") {
		return true
	}
	if strings.Contains(n, "intune") && strings.HasSuffix(n, ".xml") {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a file by its full path.
// Normalises both `\` and `/` separators so Windows-style
// shared-mount paths resolve correctly on Linux CI.
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
	case strings.HasSuffix(base, ".mobileconfig"):
		return KindMobileconfigPlist
	case strings.HasSuffix(base, ".plist") &&
		(strings.Contains(lower, "/managed preferences") ||
			strings.Contains(lower, "/configurationprofiles")):
		return KindManagedPreferencesPlist
	case strings.HasSuffix(base, ".xml") &&
		strings.Contains(lower, "jamf"):
		return KindJamfPolicyXML
	case strings.HasSuffix(base, ".xml") &&
		strings.Contains(lower, "intune"):
		return KindIntuneConfigXML
	case strings.HasSuffix(base, ".xml") &&
		strings.Contains(lower, "mdm"):
		return KindMDMEnrollmentXML
	}
	return KindOther
}

// PayloadTypeMap maps a lowercased PayloadType value (the
// canonical Apple identifier under each PayloadContent dict)
// to the Row field name. Used by parser + classifier.
func PayloadTypeMap() map[string]string {
	return map[string]string{
		"com.apple.wifi.managed":                      "wifi",
		"com.apple.vpn.managed":                       "vpn",
		"com.apple.vpn.managed.applayer":              "vpn",
		"com.apple.security.scep":                     "certificate",
		"com.apple.security.pem":                      "certificate",
		"com.apple.security.pkcs1":                    "certificate",
		"com.apple.security.pkcs12":                   "certificate",
		"com.apple.security.root":                     "certificate",
		"com.apple.security.ca.cert":                  "certificate",
		"com.apple.mail.managed":                      "mail",
		"com.apple.eas.account":                       "mail",
		"com.apple.mcx.filevault2":                    "filevault",
		"com.apple.mobiledevice.passwordpolicy":       "passcode",
		"com.apple.applicationaccess":                 "apprestrictions",
		"com.apple.app.manage":                        "managedapps",
		"com.apple.mdm":                               "managedapps",
		"com.apple.system-extension-policy":           "kernelext",
		"com.apple.syspolicy.kernel-extension-policy": "kernelext",
		"com.apple.systemextension":                   "kernelext",
		"com.apple.screensharing":                     "screensharing",
		"com.apple.remotedesktop":                     "screensharing",
	}
}

// PayloadTypeToField updates the matching boolean field on r
// for a given lowercased PayloadType value. Returns true when
// a field was set.
func PayloadTypeToField(r *Row, ptype string) bool {
	field := PayloadTypeMap()[strings.ToLower(strings.TrimSpace(ptype))]
	switch field {
	case "wifi":
		r.HasWifiPayload = true
	case "vpn":
		r.HasVPNPayload = true
	case "certificate":
		r.HasCertificatePayload = true
	case "mail":
		r.HasMailPayload = true
	case "filevault":
		r.HasFileVaultPayload = true
	case "passcode":
		r.HasPasscodePayload = true
	case "apprestrictions":
		r.HasAppRestrictions = true
	case "managedapps":
		r.HasManagedApps = true
	case "kernelext":
		r.HasKernelExtensions = true
	case "screensharing":
		r.HasScreenSharing = true
	default:
		return false
	}
	return true
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
	// Default DP/DS class for MDM profiles = handles-pii. They
	// are inherently credential-bearing.
	if r.DPDSClass == "" || r.DPDSClass == DPDSUnknown {
		r.DPDSClass = DPDSHandlesPII
	}
	r.IsPIIHandling = IsPIIHandlingClass(r.DPDSClass)
	if r.PayloadOrganization != "" {
		r.IsMDMEnrolled = true
	}
	if r.InstallDateYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.InstallDateYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasCredential := r.HasWifiPayload || r.HasVPNPayload ||
		r.HasCertificatePayload || r.HasMailPayload ||
		r.HasFileVaultPayload
	if hasReadable && r.PayloadUUID != "" && hasCredential {
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
		return rs[i].PayloadUUID < rs[j].PayloadUUID
	})
}
