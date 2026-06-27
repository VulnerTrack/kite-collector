// Package linuxsnap audits Linux Snap package metadata
// cached on workstations across Ubuntu, Fedora, openSUSE,
// Manjaro and any distro running snapd.
//
// Snap's `plugs:` declarations are the OS-enforced
// DP/DS surface — analogous to macOS NSUsageDescription
// (iter 127). snapd will not grant a capability to a snap
// that has not declared the matching plug.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget
// exports), iter 127 macosinfoplist (macOS Info.plist),
// iter 128 linuxdpkginventory (Debian dpkg), iter 129
// linuxrpminventory (RHEL/Fedora rpm), and iter 130
// macoshomebrew (macOS Homebrew).
//
// Headline finding shapes:
//
//   - `has_camera_plug=1` — camera capability declared.
//   - `has_audio_plug=1` — audio-record / pulseaudio.
//   - `has_location_plug=1` — location-observe / control.
//   - `has_contacts_plug=1` — contacts-service.
//   - `has_home_plug=1` — home directory access.
//   - `has_personal_files_plug=1` — personal-files raw FS.
//   - `has_network_plug=1` — network capability.
//   - `has_classic_confinement=1` — full host access
//     (supply-chain risk — bypasses snapd security model).
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — catalogue OR plug-based PII.
//   - `is_credential_exposure_risk=1` — readable + snap_name
//   - PII.
//
// Read-only by intent. (Project guideline 4.2.)
package linuxsnap

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

// MaxFileBytes bounds per-file read (4 MiB — snap.yaml and
// manifest.yaml are KiB-scale; .snap blobs are out of scope).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — file mtime within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_linux_snap.artifact_kind.
type ArtifactKind string

const (
	KindSnapYAML         ArtifactKind = "snap-yaml"
	KindSnapManifestYAML ArtifactKind = "snap-manifest-yaml"
	KindSnapStateJSON    ArtifactKind = "snap-state-json"
	KindSnapSeed         ArtifactKind = "snap-seed"
	KindSnapDesktopEntry ArtifactKind = "snap-desktop-entry"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// Confinement pinned to host_linux_snap.confinement.
type Confinement string

const (
	ConfinementStrict  Confinement = "strict"
	ConfinementDevmode Confinement = "devmode"
	ConfinementClassic Confinement = "classic"
	ConfinementOther   Confinement = "other"
	ConfinementUnknown Confinement = "unknown"
	ConfinementEmpty   Confinement = ""
)

// SnapType pinned to host_linux_snap.snap_type.
type SnapType string

const (
	SnapTypeApp     SnapType = "app"
	SnapTypeGadget  SnapType = "gadget"
	SnapTypeKernel  SnapType = "kernel"
	SnapTypeBase    SnapType = "base"
	SnapTypeSnapd   SnapType = "snapd"
	SnapTypeCore    SnapType = "core"
	SnapTypeOther   SnapType = "other"
	SnapTypeUnknown SnapType = "unknown"
	SnapTypeEmpty   SnapType = ""
)

// DPDSClass pinned to host_linux_snap.dp_ds_class.
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

// Row mirrors host_linux_snap' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	SnapName                 string       `json:"snap_name,omitempty"`
	SnapVersion              string       `json:"snap_version,omitempty"`
	Publisher                string       `json:"publisher,omitempty"`
	Summary                  string       `json:"summary,omitempty"`
	Website                  string       `json:"website,omitempty"`
	License                  string       `json:"license,omitempty"`
	BaseSnap                 string       `json:"base_snap,omitempty"`
	Confinement              Confinement  `json:"confinement"`
	SnapType                 SnapType     `json:"snap_type"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	PlugsCount               int64        `json:"plugs_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCameraPlug            bool         `json:"has_camera_plug"`
	HasAudioPlug             bool         `json:"has_audio_plug"`
	HasLocationPlug          bool         `json:"has_location_plug"`
	HasContactsPlug          bool         `json:"has_contacts_plug"`
	HasHomePlug              bool         `json:"has_home_plug"`
	HasPersonalFilesPlug     bool         `json:"has_personal_files_plug"`
	HasNetworkPlug           bool         `json:"has_network_plug"`
	HasClassicConfinement    bool         `json:"has_classic_confinement"`
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

// DefaultInstallRoots is the curated install-root set for
// snap artifacts on Linux.
func DefaultInstallRoots() []string {
	return []string{
		"/snap",
		"/var/lib/snapd",
		"/var/lib/snapd/seed/snaps",
		"/var/cache/snapd",
		// Cross-OS fallback for shared-mount exports.
		`C:\Linux\snap`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		"/home",
		"/Users",
		`C:\Users`,
	}
}

// UserSnapDirs is the curated per-user relative path set.
func UserSnapDirs() [][]string {
	return [][]string{
		{"snap"},
		{".local", "share", "snapd"},
	}
}

// IsCandidateExt reports whether the extension carries a
// snap artifact. Empty extension covers extensionless files
// in `meta/` directories.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".yaml", ".yml", ".json", ".desktop", ".snap", "":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the snap catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	switch n {
	case "snap.yaml", "manifest.yaml", "state.json":
		return true
	}
	if strings.HasSuffix(n, ".snap") {
		return true
	}
	if strings.HasSuffix(n, ".desktop") {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a snap file by its path.
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
	case base == "snap.yaml":
		return KindSnapYAML
	case base == "manifest.yaml":
		return KindSnapManifestYAML
	case base == "state.json" && strings.Contains(lower, "/snapd"):
		return KindSnapStateJSON
	case strings.HasSuffix(base, ".snap") &&
		strings.Contains(lower, "/snapd/seed/snaps"):
		return KindSnapSeed
	case strings.HasSuffix(base, ".desktop") &&
		strings.Contains(lower, "/snap/"):
		return KindSnapDesktopEntry
	}
	return KindOther
}

// SnapNameFromPath extracts the snap name from the install
// path: /snap/<name>/current/meta/snap.yaml → "<name>".
func SnapNameFromPath(path string) string {
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	parts := strings.Split(normalised, "/")
	for i, p := range parts {
		if strings.ToLower(p) == "snap" && i+1 < len(parts) {
			next := parts[i+1]
			// Skip "snap/snaps" + "snap/seed" — the next-segment
			// is then a leaf dir we want to skip.
			if next == "snaps" || next == "seed" || next == "" {
				continue
			}
			return next
		}
	}
	return ""
}

// PIIHandlingMarkers — lowercased snap names that flag PII /
// financial / PHI handling. Shared concept with iters 121-130.
func PIIHandlingMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// Browsers (privacy keys + cookies + passwords)
		"firefox":        DPDSHandlesPII,
		"chromium":       DPDSHandlesPII,
		"brave":          DPDSHandlesPII,
		"microsoft-edge": DPDSHandlesPII,
		// Email + collaboration
		"thunderbird":      DPDSHandlesPII,
		"slack":            DPDSHandlesPII,
		"zoom-client":      DPDSHandlesPII,
		"discord":          DPDSHandlesPII,
		"signal-desktop":   DPDSHandlesPII,
		"telegram-desktop": DPDSHandlesPII,
		"teams-for-linux":  DPDSHandlesPII,
		// Productivity
		"libreoffice":               DPDSHandlesPII,
		"onlyoffice-desktopeditors": DPDSHandlesPII,
		// Databases / DBMS
		"postgresql": DPDSHandlesPII,
		"redis":      DPDSHandlesPII,
		"mongodb":    DPDSHandlesPII,
		// Credential stores
		"keepassxc": DPDSHandlesPII,
		"bitwarden": DPDSHandlesPII,
		"1password": DPDSHandlesPII,
		// Financial / accounting
		"gnucash": DPDSHandlesFinancial,
		// Dev tools (formulas / IDEs)
		"code":                    DPDSDevTool,
		"intellij-idea-community": DPDSDevTool,
		"goland":                  DPDSDevTool,
		"docker":                  DPDSDevTool,
		// Media
		"vlc":        DPDSMediaTool,
		"spotify":    DPDSMediaTool,
		"obs-studio": DPDSMediaTool,
	}
}

// ClassifyDPDS returns the best-effort DP/DS classification
// for a snap. Order of precedence:
//  1. catalogue match on snap name (most specific)
//  2. health-related plugs — not in Snap's standard set
//  3. camera / audio / contacts / location / personal-files →
//     handles-pii
//  4. anything else → unknown.
func ClassifyDPDS(r *Row) DPDSClass {
	if cls, ok := PIIHandlingMarkers()[strings.ToLower(r.SnapName)]; ok {
		return cls
	}
	switch {
	case r.HasContactsPlug, r.HasPersonalFilesPlug,
		r.HasCameraPlug, r.HasAudioPlug, r.HasLocationPlug:
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

// PlugCapabilityKnown returns true if a snap-plug name is a
// recognised PII-relevant capability.
func PlugCapabilityKnown(p string) bool {
	switch strings.ToLower(p) {
	case "camera", "audio-record", "audio-playback",
		"pulseaudio", "alsa",
		"location-observe", "location-control",
		"contacts-service",
		"home", "personal-files", "system-files",
		"removable-media", "network",
		"hardware-observe":
		return true
	}
	return false
}

// PlugToField updates the matching boolean field on r for a
// recognised plug name. Returns true when a flag was set.
func PlugToField(r *Row, plug string) bool {
	switch strings.ToLower(plug) {
	case "camera":
		r.HasCameraPlug = true
	case "audio-record", "pulseaudio", "alsa", "audio-playback":
		r.HasAudioPlug = true
	case "location-observe", "location-control":
		r.HasLocationPlug = true
	case "contacts-service":
		r.HasContactsPlug = true
	case "home":
		r.HasHomePlug = true
	case "personal-files", "system-files", "removable-media":
		r.HasPersonalFilesPlug = true
	case "network", "network-bind", "network-control",
		"network-manager":
		r.HasNetworkPlug = true
	default:
		return false
	}
	return true
}

// ConfinementFromText normalises a snap-yaml confinement
// value to the enum.
func ConfinementFromText(s string) Confinement {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ConfinementEmpty
	case "strict":
		return ConfinementStrict
	case "devmode":
		return ConfinementDevmode
	case "classic":
		return ConfinementClassic
	}
	return ConfinementOther
}

// SnapTypeFromText normalises a snap-yaml type value.
func SnapTypeFromText(s string) SnapType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return SnapTypeEmpty
	case "app":
		return SnapTypeApp
	case "gadget":
		return SnapTypeGadget
	case "kernel":
		return SnapTypeKernel
	case "base":
		return SnapTypeBase
	case "snapd":
		return SnapTypeSnapd
	case "core":
		return SnapTypeCore
	}
	return SnapTypeOther
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// AnnotateSecurityWithClock is the time-injectable variant.
// File-mtime-derived install date is set by the collector
// before invoking this function.
func AnnotateSecurityWithClock(r *Row, now func() time.Time) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.Confinement == ConfinementClassic {
		r.HasClassicConfinement = true
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
	if hasReadable && r.SnapName != "" && r.IsPIIHandling {
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
		return rs[i].SnapName < rs[j].SnapName
	})
}
