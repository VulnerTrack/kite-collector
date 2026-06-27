// Package winofficec2r audits Microsoft Office Click-to-Run
// (C2R) artifacts on Windows endpoints. C2R is the modern
// Office delivery channel — every Microsoft 365 / Office
// Pro Plus / Visio / Project install uses it.
//
// The licence-inventory mapping is direct:
//   - title: Product ID (e.g. O365ProPlusRetail)
//   - manufacturer: Microsoft Corporation
//   - install date: Configuration.xml / inventory.xml mtime
//   - purpose: "office productivity"
//   - URL: https://www.microsoft.com/microsoft-365/
//   - DP/DS: handles-pii (Office always processes documents,
//     email, contacts, calendar, OneDrive sync, etc.)
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget),
// iter 127 macosinfoplist (macOS Info.plist), iter 128
// linuxdpkginventory (Debian dpkg), iter 129
// linuxrpminventory (RHEL/Fedora rpm), iter 130
// macoshomebrew (macOS Homebrew), iter 131 linuxsnap (Snap),
// iter 132 linuxflatpak (Flatpak), and iter 133
// winappxmanifest (Windows MSIX).
//
// Headline finding shapes:
//
//   - `has_visio=1` — Visio Pro / Standard deployed.
//   - `has_project=1` — Project Pro / Standard deployed.
//   - `has_access=1` — Microsoft Access (database).
//   - `has_publisher=1` — Microsoft Publisher.
//   - `has_skype_for_business=1` — SfB client deployed.
//   - `has_groove_excluded=1` — Groove (legacy OneDrive sync)
//     explicitly excluded.
//   - `has_lync_excluded=1` — Lync explicitly excluded.
//   - `has_shared_computer_lic=1` — Shared Computer Licensing
//     enabled (RDS / VDI scenarios).
//   - `is_enterprise_channel=1` — channel in
//     {MonthlyEnterprise, SemiAnnualEnterprise,
//     PerpetualVL2019/2021/2024}.
//   - `is_perpetual_channel=1` — security-only updates window.
//   - `is_beta_channel=1` — Beta / Current Preview (insider).
//   - `has_recent_install=1` — file mtime within 30d.
//   - `is_pii_handling=1` — always true for Office C2R.
//   - `is_credential_exposure_risk=1` — readable + product_id
//   - handles-pii.
//
// Read-only by intent. (Project guideline 4.2.)
package winofficec2r

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

// MaxFileBytes bounds per-file read (8 MiB — Configuration.xml
// + inventory.xml are KiB-scale but cached ospp.vbs outputs
// can grow on multi-product deployments).
const MaxFileBytes = 8 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install_date within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_win_office_c2r.artifact_kind.
type ArtifactKind string

const (
	KindC2RConfigurationXML ArtifactKind = "c2r-configuration-xml"
	KindC2RInventoryXML     ArtifactKind = "c2r-inventory-xml"
	KindC2RLicenseXML       ArtifactKind = "c2r-license-xml"
	KindC2RAppvManifest     ArtifactKind = "c2r-appv-manifest"
	KindOSPPDstatusTxt      ArtifactKind = "ospp-dstatus-txt"
	KindUserLicenseBin      ArtifactKind = "user-license-bin"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// Channel pinned to host_win_office_c2r.channel.
type Channel string

const (
	ChannelMonthlyEnterprise    Channel = "monthlyenterprise"
	ChannelSemiAnnualEnterprise Channel = "semiannualenterprise"
	ChannelCurrent              Channel = "current"
	ChannelCurrentPreview       Channel = "currentpreview"
	ChannelBeta                 Channel = "beta"
	ChannelPerpetualVL2019      Channel = "perpetualvl2019"
	ChannelPerpetualVL2021      Channel = "perpetualvl2021"
	ChannelPerpetualVL2024      Channel = "perpetualvl2024"
	ChannelOther                Channel = "other"
	ChannelUnknown              Channel = "unknown"
	ChannelEmpty                Channel = ""
)

// Row mirrors host_win_office_c2r' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	ProductID                string       `json:"product_id,omitempty"`
	Channel                  Channel      `json:"channel"`
	OfficeClientEdition      string       `json:"office_client_edition,omitempty"`
	InstallDateYYYYMMDD      string       `json:"install_date_yyyymmdd,omitempty"`
	LanguagesCount           int64        `json:"languages_count,omitempty"`
	ExcludedAppsCount        int64        `json:"excluded_apps_count,omitempty"`
	ProductsCount            int64        `json:"products_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasVisio                 bool         `json:"has_visio"`
	HasProject               bool         `json:"has_project"`
	HasAccess                bool         `json:"has_access"`
	HasPublisher             bool         `json:"has_publisher"`
	HasSkypeForBusiness      bool         `json:"has_skype_for_business"`
	HasGrooveExcluded        bool         `json:"has_groove_excluded"`
	HasLyncExcluded          bool         `json:"has_lync_excluded"`
	HasSharedComputerLic     bool         `json:"has_shared_computer_lic"`
	IsEnterpriseChannel      bool         `json:"is_enterprise_channel"`
	IsPerpetualChannel       bool         `json:"is_perpetual_channel"`
	IsBetaChannel            bool         `json:"is_beta_channel"`
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
		`C:\ProgramData\Microsoft\ClickToRun`,
		`C:\Program Files\Common Files\Microsoft Shared\ClickToRun`,
		`C:\Program Files\Microsoft Office\root\Office16`,
		`C:\Program Files\Microsoft Office\root\Office16\Licenses`,
		`C:\Program Files (x86)\Microsoft Office\root\Office16`,
		`C:\Program Files (x86)\Microsoft Office\root\Office16\Licenses`,
		`C:\Program Files (x86)\Common Files\Microsoft Shared\ClickToRun`,
		`C:\ODT`,
		`C:\Admin\inventory\office`,
		// Cross-OS fallback for shared-mount exports.
		`/srv/windows/office`,
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

// UserOfficeDirs is the curated per-user relative path set.
func UserOfficeDirs() [][]string {
	return [][]string{
		{"AppData", "Local", "Microsoft", "Office", "Licenses"},
		{"AppData", "Roaming", "Microsoft", "Office"},
		{"Documents", "Inventory", "office"},
	}
}

// IsCandidateExt reports whether the extension carries an
// Office C2R artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".txt", ".bin":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the C2R catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	switch n {
	case "configuration.xml", "inventory.xml":
		return true
	}
	if strings.HasPrefix(n, "configuration") && strings.HasSuffix(n, ".xml") {
		return true
	}
	if strings.Contains(n, "office") && strings.HasSuffix(n, ".xml") {
		return true
	}
	if strings.Contains(n, "ospp") &&
		(strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".log")) {
		return true
	}
	if strings.Contains(n, "license") && strings.HasSuffix(n, ".xml") {
		return true
	}
	if strings.Contains(n, "license") && strings.HasSuffix(n, ".bin") {
		return true
	}
	if n == "appvmanifest.xml" {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a file by its full path.
// Normalises both `\` and `/` separators so Windows-style
// paths resolve correctly on Linux CI.
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
	case base == "inventory.xml" && strings.Contains(lower, "clicktorun"):
		return KindC2RInventoryXML
	case base == "appvmanifest.xml" && strings.Contains(lower, "clicktorun"):
		return KindC2RAppvManifest
	case strings.HasSuffix(base, ".xml") &&
		strings.Contains(lower, "/licenses/"):
		return KindC2RLicenseXML
	case base == "configuration.xml" ||
		(strings.HasPrefix(base, "configuration") && strings.HasSuffix(base, ".xml")):
		return KindC2RConfigurationXML
	case strings.Contains(base, "ospp") &&
		(strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".log")):
		return KindOSPPDstatusTxt
	case strings.HasSuffix(base, ".bin") &&
		strings.Contains(lower, "/licenses/"):
		return KindUserLicenseBin
	}
	return KindOther
}

// ChannelFromText normalises a Channel attribute value.
// Examples: "MonthlyEnterprise" → ChannelMonthlyEnterprise,
// "SemiAnnualEnterpriseChannel" → ChannelSemiAnnualEnterprise.
func ChannelFromText(s string) Channel {
	t := strings.ToLower(strings.TrimSpace(s))
	// Strip trailing "channel" suffix.
	t = strings.TrimSuffix(t, "channel")
	t = strings.TrimSpace(t)
	switch t {
	case "":
		return ChannelEmpty
	case "monthlyenterprise":
		return ChannelMonthlyEnterprise
	case "semiannualenterprise", "semiannual":
		return ChannelSemiAnnualEnterprise
	case "current":
		return ChannelCurrent
	case "currentpreview", "monthlychannelpreview":
		return ChannelCurrentPreview
	case "beta", "insiderfast":
		return ChannelBeta
	case "perpetualvl2019":
		return ChannelPerpetualVL2019
	case "perpetualvl2021":
		return ChannelPerpetualVL2021
	case "perpetualvl2024":
		return ChannelPerpetualVL2024
	}
	return ChannelOther
}

// IsEnterpriseChannelValue reports whether a Channel is one
// of the enterprise-update channels.
func IsEnterpriseChannelValue(c Channel) bool {
	switch c {
	case ChannelMonthlyEnterprise,
		ChannelSemiAnnualEnterprise,
		ChannelPerpetualVL2019,
		ChannelPerpetualVL2021,
		ChannelPerpetualVL2024:
		return true
	case ChannelCurrent, ChannelCurrentPreview, ChannelBeta,
		ChannelOther, ChannelUnknown, ChannelEmpty:
		return false
	}
	return false
}

// IsPerpetualChannelValue reports whether a Channel is one of
// the perpetual-licence channels.
func IsPerpetualChannelValue(c Channel) bool {
	switch c {
	case ChannelPerpetualVL2019,
		ChannelPerpetualVL2021,
		ChannelPerpetualVL2024:
		return true
	case ChannelMonthlyEnterprise, ChannelSemiAnnualEnterprise,
		ChannelCurrent, ChannelCurrentPreview, ChannelBeta,
		ChannelOther, ChannelUnknown, ChannelEmpty:
		return false
	}
	return false
}

// IsBetaChannelValue reports whether a Channel is the Beta /
// insider preview track.
func IsBetaChannelValue(c Channel) bool {
	switch c {
	case ChannelBeta, ChannelCurrentPreview:
		return true
	case ChannelMonthlyEnterprise, ChannelSemiAnnualEnterprise,
		ChannelCurrent, ChannelPerpetualVL2019,
		ChannelPerpetualVL2021, ChannelPerpetualVL2024,
		ChannelOther, ChannelUnknown, ChannelEmpty:
		return false
	}
	return false
}

// ProductIDFlags maps a lowercased ProductID substring to the
// per-product boolean(s) that should be set. Returns true when
// at least one flag is set.
func ProductIDFlags(r *Row, pid string) bool {
	t := strings.ToLower(strings.TrimSpace(pid))
	matched := false
	switch {
	case strings.Contains(t, "visio"):
		r.HasVisio = true
		matched = true
	case strings.Contains(t, "project"):
		r.HasProject = true
		matched = true
	case strings.Contains(t, "access"):
		r.HasAccess = true
		matched = true
	case strings.Contains(t, "publisher"):
		r.HasPublisher = true
		matched = true
	case strings.Contains(t, "skypeforbusiness"),
		strings.Contains(t, "skype"):
		r.HasSkypeForBusiness = true
		matched = true
	}
	return matched
}

// ExcludedAppToField sets the matching excluded-app boolean.
// Returns true on match.
func ExcludedAppToField(r *Row, app string) bool {
	switch strings.ToLower(strings.TrimSpace(app)) {
	case "groove":
		r.HasGrooveExcluded = true
		return true
	case "lync":
		r.HasLyncExcluded = true
		return true
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
	// Channel-based flags.
	if IsEnterpriseChannelValue(r.Channel) {
		r.IsEnterpriseChannel = true
	}
	if IsPerpetualChannelValue(r.Channel) {
		r.IsPerpetualChannel = true
	}
	if IsBetaChannelValue(r.Channel) {
		r.IsBetaChannel = true
	}
	// Office always handles PII (documents/email/contacts).
	r.IsPIIHandling = true
	if r.InstallDateYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.InstallDateYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.ProductID != "" && r.IsPIIHandling {
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
		return rs[i].ProductID < rs[j].ProductID
	})
}
