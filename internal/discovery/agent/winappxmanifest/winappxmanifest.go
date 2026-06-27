// Package winappxmanifest audits Windows MSIX/AppX manifests
// cached on Windows workstations. Closes the privacy-
// capability quartet alongside iter 127 (macOS), iter 131
// (Snap), and iter 132 (Flatpak): every modern app-packaging
// format declares its OS-enforced permissions in a manifest,
// and this iteration covers Windows.
//
// MSIX <Capabilities> are enforced by the Windows AppContainer
// at kernel level — an app cannot access webcam / microphone /
// location / contacts / photos without the matching
// <DeviceCapability> or <Capability> element. So per-
// capability booleans are compliance-grade DP/DS signals.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget),
// iter 127 macosinfoplist (macOS Info.plist), iter 128
// linuxdpkginventory (Debian dpkg), iter 129
// linuxrpminventory (RHEL/Fedora rpm), iter 130
// macoshomebrew (macOS Homebrew), iter 131 linuxsnap
// (Snap plugs), and iter 132 linuxflatpak (Context
// permissions).
//
// Headline finding shapes:
//
//   - `has_camera_capability=1` — <DeviceCapability Name="webcam">.
//   - `has_microphone_capability=1` — microphone.
//   - `has_location_capability=1` — location.
//   - `has_contacts_capability=1` — contacts.
//   - `has_appointments_capability=1` — appointments/calendar.
//   - `has_phonecall_capability=1` — phoneCallHistory*.
//   - `has_documents_lib=1` — documentsLibrary.
//   - `has_pictures_lib=1` — picturesLibrary.
//   - `has_videos_lib=1` — videosLibrary.
//   - `has_music_lib=1` — musicLibrary.
//   - `has_internet_client=1` — internetClient.
//   - `has_internet_server=1` — internetClientServer.
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — capability OR catalogue.
//   - `is_credential_exposure_risk=1` — readable + package_name
//   - PII-handling.
//
// Read-only by intent. (Project guideline 4.2.)
package winappxmanifest

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

// MaxFileBytes bounds per-file read (4 MiB — AppxManifest.xml
// files are typically KiB-scale; AppxBlockMap.xml can grow
// for large packages but stays under a few MiB).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install_date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_win_appx_manifest.artifact_kind.
type ArtifactKind string

const (
	KindAppxManifestXML  ArtifactKind = "appxmanifest-xml"
	KindAppxBlockMapXML  ArtifactKind = "appxblockmap-xml"
	KindAppxMetadata     ArtifactKind = "appxmetadata"
	KindAppxSignatureP7X ArtifactKind = "appxsignature-p7x"
	KindMSIXInstaller    ArtifactKind = "msix-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// DPDSClass pinned to host_win_appx_manifest.dp_ds_class.
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

// Row mirrors host_win_appx_manifest' column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	PackageName               string       `json:"package_name,omitempty"`
	PackagePublisher          string       `json:"package_publisher,omitempty"`
	DisplayName               string       `json:"display_name,omitempty"`
	PublisherDisplayName      string       `json:"publisher_display_name,omitempty"`
	Description               string       `json:"description,omitempty"`
	Version                   string       `json:"version,omitempty"`
	LogoPath                  string       `json:"logo_path,omitempty"`
	InstallDateYYYYMMDD       string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                 DPDSClass    `json:"dp_ds_class"`
	CapabilitiesCount         int64        `json:"capabilities_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasCameraCapability       bool         `json:"has_camera_capability"`
	HasMicrophoneCapability   bool         `json:"has_microphone_capability"`
	HasLocationCapability     bool         `json:"has_location_capability"`
	HasContactsCapability     bool         `json:"has_contacts_capability"`
	HasAppointmentsCapability bool         `json:"has_appointments_capability"`
	HasPhonecallCapability    bool         `json:"has_phonecall_capability"`
	HasDocumentsLib           bool         `json:"has_documents_lib"`
	HasPicturesLib            bool         `json:"has_pictures_lib"`
	HasVideosLib              bool         `json:"has_videos_lib"`
	HasMusicLib               bool         `json:"has_music_lib"`
	HasInternetClient         bool         `json:"has_internet_client"`
	HasInternetServer         bool         `json:"has_internet_server"`
	HasRecentInstall          bool         `json:"has_recent_install"`
	IsPIIHandling             bool         `json:"is_pii_handling"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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
		`C:\Program Files\WindowsApps`,
		`C:\Program Files (x86)\WindowsApps`,
		`C:\Windows\SystemApps`,
		`C:\ProgramData\Microsoft\Windows\AppRepository`,
		`C:\Admin\inventory\msix`,
		// Bonus: shared-mount copies on Linux/macOS hosts.
		`/srv/windows/msix`,
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

// UserAppxDirs is the curated per-user relative path set.
func UserAppxDirs() [][]string {
	return [][]string{
		{"AppData", "Local", "Packages"},
		{"AppData", "Local", "Microsoft", "WindowsApps"},
		{"Documents", "Inventory", "appx"},
	}
}

// IsCandidateExt reports whether the extension carries a
// MSIX/AppX artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".p7x", ".msix", ".appx", ".appxbundle",
		".msixbundle":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MSIX/AppX catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	switch n {
	case "appxmanifest.xml", "appxblockmap.xml":
		return true
	case "appxsignature.p7x":
		return true
	}
	if strings.HasSuffix(n, ".msix") ||
		strings.HasSuffix(n, ".appx") ||
		strings.HasSuffix(n, ".appxbundle") ||
		strings.HasSuffix(n, ".msixbundle") {
		return true
	}
	if strings.HasPrefix(n, "appxmetadata") {
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
	case base == "appxmanifest.xml":
		return KindAppxManifestXML
	case base == "appxblockmap.xml":
		return KindAppxBlockMapXML
	case base == "appxsignature.p7x":
		return KindAppxSignatureP7X
	case strings.HasPrefix(base, "appxmetadata"):
		return KindAppxMetadata
	case strings.HasSuffix(base, ".msix"),
		strings.HasSuffix(base, ".appx"),
		strings.HasSuffix(base, ".appxbundle"),
		strings.HasSuffix(base, ".msixbundle"):
		return KindMSIXInstaller
	}
	return KindOther
}

// publisherCNRE extracts the CN= value from an Identity
// Publisher attribute. e.g. `CN=Microsoft Corporation,
// O=Microsoft Corporation, L=Redmond, S=Washington, C=US`
// → `Microsoft Corporation`.
var publisherCNRE = regexp.MustCompile(`(?i)CN\s*=\s*([^,]+)`)

// PublisherCN extracts the CN= value from an Identity
// Publisher distinguished name.
func PublisherCN(dn string) string {
	m := publisherCNRE.FindStringSubmatch(dn)
	if m == nil {
		return strings.TrimSpace(dn)
	}
	return strings.TrimSpace(m[1])
}

// PIIHandlingMarkers — lowercased package name substrings
// that flag PII / financial / PHI handling. Shared concept
// with iters 121-132. MSIX package names typically use
// `<Publisher>.<Product>` (`Microsoft.WindowsCalculator`,
// `Mozilla.Firefox`).
func PIIHandlingMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// Microsoft built-in
		"microsoft.outlook":                   DPDSHandlesPII,
		"microsoft.outlookforios":             DPDSHandlesPII,
		"microsoft.officeoutlook":             DPDSHandlesPII,
		"microsoft.teams":                     DPDSHandlesPII,
		"microsoft.skypeapp":                  DPDSHandlesPII,
		"microsoft.people":                    DPDSHandlesPII,
		"microsoft.contacts":                  DPDSHandlesPII,
		"microsoft.bingmaps":                  DPDSHandlesPII,
		"microsoft.windowsmaps":               DPDSHandlesPII,
		"microsoft.microsoftedge":             DPDSHandlesPII,
		"microsoft.windowscalendar":           DPDSHandlesPII,
		"microsoft.microsoft365apps":          DPDSHandlesPII,
		"microsoft.office.outlook":            DPDSHandlesPII,
		"microsoft.office.word":               DPDSHandlesPII,
		"microsoft.office.excel":              DPDSHandlesPII,
		"microsoft.windows.cortana":           DPDSHandlesPII,
		"microsoft.zune":                      DPDSMediaTool,
		"microsoft.windowscamera":             DPDSHandlesPII,
		"microsoft.windowscommunicationsapps": DPDSHandlesPII,
		// Browsers
		"google.chrome":   DPDSHandlesPII,
		"mozilla.firefox": DPDSHandlesPII,
		"brave.brave":     DPDSHandlesPII,
		// Collaboration
		"slacktechnologies.slack":           DPDSHandlesPII,
		"zoomvideocommunications.zoom":      DPDSHandlesPII,
		"discordinc.discord":                DPDSHandlesPII,
		"signalfoundation.signal":           DPDSHandlesPII,
		"telegrammessenger.telegramdesktop": DPDSHandlesPII,
		// Credential
		"keepassxcteam.keepassxc":           DPDSHandlesPII,
		"8bitsolutionsllc.bitwardendesktop": DPDSHandlesPII,
		"agilebits.1password":               DPDSHandlesPII,
		// Financial
		"intuit.quickbooks": DPDSHandlesFinancial,
		// Dev / utility
		"microsoft.windowsterminal":  DPDSDevTool,
		"microsoft.visualstudiocode": DPDSDevTool,
		"microsoft.dotnet":           DPDSDevTool,
		"jetbrains.toolbox":          DPDSDevTool,
		// Media
		"videolan.vlc":           DPDSMediaTool,
		"spotifyab.spotifymusic": DPDSMediaTool,
		"adobeinc.adobeacrobat":  DPDSMediaTool,
	}
}

// ClassifyDPDS returns the best-effort DP/DS classification.
// Catalogue match wins; otherwise capability-based.
func ClassifyDPDS(r *Row) DPDSClass {
	if cls, ok := PIIHandlingMarkers()[strings.ToLower(r.PackageName)]; ok {
		return cls
	}
	switch {
	case r.HasCameraCapability, r.HasMicrophoneCapability,
		r.HasLocationCapability, r.HasContactsCapability,
		r.HasAppointmentsCapability, r.HasPhonecallCapability,
		r.HasDocumentsLib, r.HasPicturesLib,
		r.HasVideosLib, r.HasMusicLib:
		return DPDSHandlesPII
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

// CapabilityToField updates the matching boolean field on r
// for a given capability name. Returns true when a field was
// set. Recognises both <Capability Name="..."> and
// <DeviceCapability Name="..."> values.
func CapabilityToField(r *Row, cap string) bool {
	switch strings.ToLower(cap) {
	case "webcam":
		r.HasCameraCapability = true
	case "microphone":
		r.HasMicrophoneCapability = true
	case "location":
		r.HasLocationCapability = true
	case "contacts":
		r.HasContactsCapability = true
	case "appointments":
		r.HasAppointmentsCapability = true
	case "phonecall", "phonecallhistory", "phonecallhistorypublic":
		r.HasPhonecallCapability = true
	case "documentslibrary":
		r.HasDocumentsLib = true
	case "pictureslibrary":
		r.HasPicturesLib = true
	case "videoslibrary":
		r.HasVideosLib = true
	case "musiclibrary":
		r.HasMusicLib = true
	case "internetclient":
		r.HasInternetClient = true
	case "internetclientserver":
		r.HasInternetServer = true
	default:
		return false
	}
	return true
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
	if r.DPDSClass == "" || r.DPDSClass == DPDSUnknown {
		r.DPDSClass = ClassifyDPDS(r)
	}
	if IsPIIHandlingClass(r.DPDSClass) {
		r.IsPIIHandling = true
	}
	if r.InstallDateYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.InstallDateYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.PackageName != "" && r.IsPIIHandling {
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
		return rs[i].PackageName < rs[j].PackageName
	})
}
