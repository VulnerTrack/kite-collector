// Package linuxflatpak audits Linux Flatpak metadata cached
// on workstations across any distro running flatpak.
//
// Flatpak's `[Context]` section in /var/lib/flatpak/app/<id>/
// current/active/metadata is the OS-enforced DP/DS surface —
// analogous to Snap plugs (iter 131) and macOS
// NSUsageDescription keys (iter 127). The bubblewrap sandbox
// will not grant a permission the manifest hasn't declared.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget),
// iter 127 macosinfoplist (macOS Info.plist), iter 128
// linuxdpkginventory (Debian dpkg), iter 129
// linuxrpminventory (RHEL/Fedora rpm), iter 130
// macoshomebrew (macOS Homebrew), and iter 131 linuxsnap.
//
// Headline finding shapes:
//
//   - `has_x11_socket=1` — X11 (key-logger surface).
//   - `has_wayland_socket=1` — Wayland.
//   - `has_pulseaudio_socket=1` — audio access.
//   - `has_camera_device=1` — devices=all OR camera-specific.
//   - `has_network_shared=1` — network shared.
//   - `has_home_filesystem=1` — $HOME access.
//   - `has_host_filesystem=1` — full / read (supply-chain
//     risk; sandbox bypass).
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — permissions OR catalogue.
//   - `is_credential_exposure_risk=1` — readable + app_id
//   - PII-handling.
//
// Read-only by intent. (Project guideline 4.2.)
package linuxflatpak

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

// MaxFileBytes bounds per-file read (4 MiB — metadata + XML
// + .desktop files are typically KiB-scale).
const MaxFileBytes = 4 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install_date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_linux_flatpak.artifact_kind.
type ArtifactKind string

const (
	KindFlatpakMetadata    ArtifactKind = "flatpak-metadata"
	KindFlatpakMetainfoXML ArtifactKind = "flatpak-metainfo-xml"
	KindFlatpakAppdataXML  ArtifactKind = "flatpak-appdata-xml"
	KindFlatpakDesktop     ArtifactKind = "flatpak-desktop"
	KindFlatpakRepoRef     ArtifactKind = "flatpak-repo-ref"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// DPDSClass pinned to host_linux_flatpak.dp_ds_class.
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

// Row mirrors host_linux_flatpak' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AppID                    string       `json:"app_id,omitempty"`
	Publisher                string       `json:"publisher,omitempty"`
	DisplayName              string       `json:"display_name,omitempty"`
	Summary                  string       `json:"summary,omitempty"`
	Homepage                 string       `json:"homepage,omitempty"`
	License                  string       `json:"license,omitempty"`
	Version                  string       `json:"version,omitempty"`
	Runtime                  string       `json:"runtime,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	DPDSClass                DPDSClass    `json:"dp_ds_class"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasX11Socket             bool         `json:"has_x11_socket"`
	HasWaylandSocket         bool         `json:"has_wayland_socket"`
	HasPulseaudioSocket      bool         `json:"has_pulseaudio_socket"`
	HasCameraDevice          bool         `json:"has_camera_device"`
	HasNetworkShared         bool         `json:"has_network_shared"`
	HasHomeFilesystem        bool         `json:"has_home_filesystem"`
	HasHostFilesystem        bool         `json:"has_host_filesystem"`
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
		"/var/lib/flatpak/app",
		"/var/lib/flatpak/exports",
		"/var/lib/flatpak/runtime",
		// Cross-OS fallback for shared-mount exports.
		`C:\Linux\flatpak`,
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

// UserFlatpakDirs is the curated per-user relative path set.
func UserFlatpakDirs() [][]string {
	return [][]string{
		{".local", "share", "flatpak", "app"},
		{".local", "share", "flatpak", "exports"},
	}
}

// IsCandidateExt reports whether the extension carries a
// flatpak artifact. Empty extension covers the `metadata`
// file (no extension).
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".desktop", ".ref", "":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Flatpak catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	if n == "metadata" {
		return true
	}
	if strings.HasSuffix(n, ".desktop") {
		return true
	}
	if strings.HasSuffix(n, ".metainfo.xml") {
		return true
	}
	if strings.HasSuffix(n, ".appdata.xml") {
		return true
	}
	if strings.HasSuffix(n, ".ref") {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a Flatpak file by its path.
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
	// Match `flatpak` anywhere in the path so that env-overridden
	// custom roots (e.g. `/tmp/custom-flatpak/...`) still classify
	// correctly. Bare `metadata` / `.desktop` files outside any
	// flatpak-ish tree fall through to KindOther.
	flatpakish := strings.Contains(lower, "flatpak") ||
		strings.Contains(lower, "/app/")
	switch {
	case base == "metadata" && flatpakish:
		return KindFlatpakMetadata
	case strings.HasSuffix(base, ".metainfo.xml"):
		return KindFlatpakMetainfoXML
	case strings.HasSuffix(base, ".appdata.xml"):
		return KindFlatpakAppdataXML
	case strings.HasSuffix(base, ".desktop") && flatpakish:
		return KindFlatpakDesktop
	case strings.HasSuffix(base, ".ref"):
		return KindFlatpakRepoRef
	}
	return KindOther
}

// AppIDFromPath extracts the reverse-DNS app ID from a
// Flatpak install path. Looks for the segment after `/app/`
// or `/exports/share/applications/` or `/exports/share/
// metainfo/`. For metainfo XML the filename itself often
// carries the app ID (`org.mozilla.firefox.metainfo.xml`).
func AppIDFromPath(path string) string {
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	parts := strings.Split(normalised, "/")
	for i, p := range parts {
		if p == "app" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	// Try filename-encoded app ID.
	base := filepath.Base(normalised)
	switch {
	case strings.HasSuffix(base, ".metainfo.xml"):
		return strings.TrimSuffix(base, ".metainfo.xml")
	case strings.HasSuffix(base, ".appdata.xml"):
		return strings.TrimSuffix(base, ".appdata.xml")
	case strings.HasSuffix(base, ".desktop"):
		return strings.TrimSuffix(base, ".desktop")
	}
	return ""
}

// PublisherFromAppID extracts the publisher slug from a
// reverse-DNS Flatpak app ID. `org.mozilla.firefox` →
// `mozilla`, `com.spotify.Client` → `spotify`. Returns ""
// for unparseable input.
func PublisherFromAppID(appID string) string {
	t := strings.ToLower(strings.TrimSpace(appID))
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

func isCommonTLD(s string) bool {
	switch s {
	case "com", "org", "net", "io", "ar", "br", "edu", "gov",
		"us", "uk", "de", "fr", "jp", "ca", "au", "es",
		"mx", "co", "info", "app", "dev":
		return true
	}
	return false
}

// PIIHandlingMarkers — lowercased Flatpak app-id substrings
// that flag PII / financial / PHI handling. Shared concept
// with iters 121-131.
func PIIHandlingMarkers() map[string]DPDSClass {
	return map[string]DPDSClass{
		// Browsers
		"org.mozilla.firefox":   DPDSHandlesPII,
		"org.chromium.chromium": DPDSHandlesPII,
		"com.brave.browser":     DPDSHandlesPII,
		"com.microsoft.edge":    DPDSHandlesPII,
		"com.google.chrome":     DPDSHandlesPII,
		// Email + collaboration
		"org.mozilla.thunderbird": DPDSHandlesPII,
		"com.slack.slack":         DPDSHandlesPII,
		"us.zoom.zoom":            DPDSHandlesPII,
		"com.discordapp.discord":  DPDSHandlesPII,
		"org.signal.signal":       DPDSHandlesPII,
		"org.telegram.desktop":    DPDSHandlesPII,
		"com.microsoft.teams":     DPDSHandlesPII,
		// Office / productivity
		"org.libreoffice.libreoffice":   DPDSHandlesPII,
		"org.onlyoffice.desktopeditors": DPDSHandlesPII,
		// Credential stores
		"org.keepassxc.keepassxc": DPDSHandlesPII,
		"com.bitwarden.desktop":   DPDSHandlesPII,
		"com.1password.1password": DPDSHandlesPII,
		// Financial / accounting
		"org.gnucash.gnucash":   DPDSHandlesFinancial,
		"org.homebank.homebank": DPDSHandlesFinancial,
		// Dev tools
		"com.visualstudio.code":                 DPDSDevTool,
		"com.jetbrains.intellij-idea-community": DPDSDevTool,
		"com.jetbrains.pycharm-community":       DPDSDevTool,
		"io.github.shiftey.desktop":             DPDSDevTool,
		"com.github.tchx84.flatseal":            DPDSSystemUtility,
		// Media
		"org.videolan.vlc":      DPDSMediaTool,
		"com.spotify.client":    DPDSMediaTool,
		"com.obsproject.studio": DPDSMediaTool,
	}
}

// ClassifyDPDS returns the best-effort DP/DS classification.
// Catalogue match wins; otherwise permission-based.
func ClassifyDPDS(r *Row) DPDSClass {
	if cls, ok := PIIHandlingMarkers()[strings.ToLower(r.AppID)]; ok {
		return cls
	}
	switch {
	case r.HasCameraDevice, r.HasPulseaudioSocket,
		r.HasHomeFilesystem, r.HasHostFilesystem:
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

// ContextValueToFields walks a Context-section key/value pair
// and sets the matching Row booleans. Returns true when any
// field was set.
//
// Examples:
//
//	sockets=x11;wayland;pulseaudio;pcsc
//	devices=all
//	filesystems=home;xdg-download;host
//	shared=network;ipc
func ContextValueToFields(r *Row, key, value string) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ";")
	matched := false
	for _, raw := range parts {
		token := strings.ToLower(strings.TrimSpace(raw))
		if token == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "sockets":
			switch token {
			case "x11", "fallback-x11":
				r.HasX11Socket = true
				matched = true
			case "wayland":
				r.HasWaylandSocket = true
				matched = true
			case "pulseaudio":
				r.HasPulseaudioSocket = true
				matched = true
			}
		case "devices":
			switch token {
			case "all":
				r.HasCameraDevice = true
				matched = true
			case "dri", "kvm", "shm":
				// hardware devices but not camera-specific
				matched = true
			}
		case "filesystems":
			switch {
			case token == "home", strings.HasPrefix(token, "home/"):
				r.HasHomeFilesystem = true
				matched = true
			case token == "host", strings.HasPrefix(token, "host:"):
				r.HasHostFilesystem = true
				matched = true
			case strings.HasPrefix(token, "xdg-"):
				r.HasHomeFilesystem = true
				matched = true
			}
		case "shared":
			switch token {
			case "network":
				r.HasNetworkShared = true
				matched = true
			}
		}
	}
	return matched
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
	if hasReadable && r.AppID != "" && r.IsPIIHandling {
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
		return rs[i].AppID < rs[j].AppID
	})
}
