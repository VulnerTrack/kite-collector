// Package winmsix inventories installed MSIX / UWP / AppX packages
// on Windows by walking the on-disk `AppxManifest.xml` artifacts
// under C:\Program Files\WindowsApps\<PackageFullName>\ (machine-
// wide) and %LOCALAPPDATA%\Packages\<PackageFamily>\ (per-user
// staged copies). Each manifest is a small XML document declaring
// the package's identity, application entry points, and capability
// set — the Windows-runtime equivalent of an Android Permissions
// block.
//
// File-based discovery is the deliberate design choice. WindowsApps
// is ACL-restricted by default, but on a defender-elevated kite
// agent the manifest reads cleanly. The audit pipeline cross-
// references (identity_name, identity_version) against the Store
// catalog for known packages and against vendor allowlists for
// sideloaded ones.
//
// Headline finding shapes (MITRE T1518 — Software Discovery, plus
// T1620 — Reflective Code Loading via full-trust, T1195 — Supply
// Chain Compromise for sideloads):
//
//   - `has_run_full_trust=1` — package declared the restricted
//     `runFullTrust` capability. Runs outside the AppContainer
//     sandbox with the user's full token. Microsoft Store review
//     gates this; sideloaded packages with the same capability
//     deserve close inspection (CWE-269).
//   - `has_broad_file_system_access=1` — `broadFileSystemAccess`
//     restricted capability. Reads every file the user can.
//   - `has_allow_elevation=1` — `allowElevation` restricted
//     capability. UAC bypass primitive.
//   - `is_sideloaded=1` — Publisher CN doesn't match the curated
//     Microsoft set. Sideloaded packages skip Store vetting.
//
// Read-only by intent — we walk WindowsApps + Packages only,
// never invoke `Get-AppxPackage` or other Win32 APIs.
// (Project guideline 4.2.)
package winmsix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxPackages bounds per-scan output. A typical Windows host has
// 50-200 installed AppX packages; the 8192 ceiling covers
// developer boxes with vendor-heavy sideloaded extensions.
const MaxPackages = 8192

// InstallScope classifies machine-wide vs per-user. Pinned to
// the host_msix_packages.install_scope CHECK enum.
type InstallScope string

const (
	ScopeMachineWide InstallScope = "machine-wide"
	ScopePerUser     InstallScope = "per-user"
	ScopeUnknown     InstallScope = "unknown"
)

// Package mirrors host_msix_packages' column shape exactly.
type Package struct {
	PublisherDisplayName     string       `json:"publisher_display_name,omitempty"`
	IdentityPublisherCN      string       `json:"identity_publisher_cn,omitempty"`
	PackageDir               string       `json:"package_dir"`
	PackageFullName          string       `json:"package_full_name,omitempty"`
	IdentityName             string       `json:"identity_name"`
	IdentityVersion          string       `json:"identity_version"`
	IdentityPublisher        string       `json:"identity_publisher,omitempty"`
	InstallScope             InstallScope `json:"install_scope"`
	IdentityArchitecture     string       `json:"identity_architecture,omitempty"`
	PrimaryExecutable        string       `json:"primary_executable,omitempty"`
	FileHash                 string       `json:"file_hash"`
	FilePath                 string       `json:"file_path"`
	DisplayName              string       `json:"display_name,omitempty"`
	Capabilities             []string     `json:"capabilities,omitempty"`
	ApplicationCount         int          `json:"application_count"`
	CapabilityCount          int          `json:"capability_count"`
	HasRunFullTrust          bool         `json:"has_run_full_trust"`
	HasBroadFileSystemAccess bool         `json:"has_broad_file_system_access"`
	HasAllowElevation        bool         `json:"has_allow_elevation"`
	HasRestrictedCapability  bool         `json:"has_restricted_capability"`
	IsMicrosoftPublisher     bool         `json:"is_microsoft_publisher"`
	IsSideloaded             bool         `json:"is_sideloaded"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Package, error)
}

// HashContents returns the SHA-256 hex of a manifest body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MicrosoftPublisherSubstrings is the curated set of CN / O
// substrings the audit pipeline considers a Microsoft-signed
// package. Match is case-insensitive.
func MicrosoftPublisherSubstrings() []string {
	return []string{
		"cn=microsoft corporation",
		"cn=microsoft windows",
		"o=microsoft corporation",
	}
}

// RestrictedCapabilities is the curated set of `rescap:Capability`
// names that escape the default AppContainer sandbox. Any package
// declaring one of these gets `has_restricted_capability=1` and,
// when the name matches the dedicated columns, the specific
// boolean too.
func RestrictedCapabilities() []string {
	return []string{
		"runFullTrust",
		"broadFileSystemAccess",
		"allowElevation",
		"elevatedExtensionHostBroker",
		"unvirtualizedResources",
		"packagePolicySystem",
		"protectedApp",
		"developmentModeNetwork",
	}
}

// ExtractPublisherCN returns the `CN=…` segment of an X.500
// distinguished name. The DSC subject in MSIX manifests follows
// "CN=Microsoft Corporation, O=Microsoft Corporation, …". Returns
// the trimmed value, or the whole publisher string when no CN= is
// present.
func ExtractPublisherCN(publisher string) string {
	if publisher == "" {
		return ""
	}
	parts := strings.Split(publisher, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "CN") {
			return strings.TrimSpace(kv[1])
		}
	}
	return strings.TrimSpace(publisher)
}

// IsMicrosoftPublisher reports whether the publisher subject
// matches one of the curated Microsoft substrings (case-
// insensitive). Empty publisher returns false.
func IsMicrosoftPublisher(publisher string) bool {
	if strings.TrimSpace(publisher) == "" {
		return false
	}
	lower := strings.ToLower(publisher)
	for _, s := range MicrosoftPublisherSubstrings() {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Package that
// has its raw fields populated.
func AnnotateSecurity(p *Package) {
	p.IdentityPublisherCN = ExtractPublisherCN(p.IdentityPublisher)
	p.IsMicrosoftPublisher = IsMicrosoftPublisher(p.IdentityPublisher)
	// Sideloaded = not Microsoft-signed. Conservative — store-
	// vendor packages (Slack, Adobe) will flag too; the audit
	// pipeline allow-lists by publisher CN.
	p.IsSideloaded = !p.IsMicrosoftPublisher
	p.CapabilityCount = len(p.Capabilities)

	restricted := false
	for _, c := range p.Capabilities {
		name := strings.TrimSpace(c)
		// Strip namespace prefix if present.
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		switch name {
		case "runFullTrust":
			p.HasRunFullTrust = true
			restricted = true
		case "broadFileSystemAccess":
			p.HasBroadFileSystemAccess = true
			restricted = true
		case "allowElevation":
			p.HasAllowElevation = true
			restricted = true
		}
		// Any restricted name flips the rollup.
		for _, r := range RestrictedCapabilities() {
			if name == r {
				restricted = true
				break
			}
		}
	}
	p.HasRestrictedCapability = restricted
}

// SortPackages returns a deterministic ordering by identity_name
// then identity_version.
func SortPackages(ps []Package) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].IdentityName != ps[j].IdentityName {
			return ps[i].IdentityName < ps[j].IdentityName
		}
		return ps[i].IdentityVersion < ps[j].IdentityVersion
	})
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}
