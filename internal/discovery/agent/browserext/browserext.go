// Package browserext enumerates installed browser extensions across
// Chromium-family browsers (Chrome, Edge, Brave, Opera, Vivaldi, Arc),
// Firefox-family browsers (Firefox, Firefox ESR, LibreWolf), and Safari.
//
// Extensions are a top-3 MITRE ATT&CK persistence + collection primitive
// (T1176 Browser Extensions): they run in-page with full DOM access on
// any URL they hold host_permissions for, can read cookies, intercept
// XHR responses (steal MFA tokens), and survive reboots. The collector
// is the inventory side of the audit; cross-referencing against known-
// bad ext IDs (CRXcavator, etc.) lives in the audit pipeline.
//
// Every collector is **read-only** — it parses manifest.json, walks
// profile directories, reads extensions.json. It never installs,
// enables, disables, or removes any extension.
//
// Extension rows feed the audit pipeline:
//
//   - T1176 (Browser Extensions) — every row IS a persistence primitive.
//   - CWE-829 (Untrusted Functionality) — install_source='sideloaded'
//     extensions bypassed the store vetting.
//   - Permission audit — host_permissions containing "<all_urls>" or
//     "*://*/*" grants the extension full-DOM access to every site,
//     including SaaS/banking login flows.
//   - Manifest V2 deprecation — manifest_version=2 in Chromium-family
//     browsers ≥ v127 is unsupported and indicates abandoned code.
package browserext

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Extension, error)
}

// MaxExtensions bounds per-scan output. A typical user has 10-40
// extensions per profile × 2-5 profiles per browser × multiple browsers.
// The 1024 ceiling protects the SQLite write path.
const MaxExtensions = 1024

// Browser identifies the parent browser. Strings pinned to the
// host_browser_extensions.browser CHECK enum.
type Browser string

const (
	BrowserChrome     Browser = "chrome"
	BrowserChromium   Browser = "chromium"
	BrowserEdge       Browser = "edge"
	BrowserBrave      Browser = "brave"
	BrowserOpera      Browser = "opera"
	BrowserVivaldi    Browser = "vivaldi"
	BrowserArc        Browser = "arc"
	BrowserFirefox    Browser = "firefox"
	BrowserFirefoxESR Browser = "firefox-esr"
	BrowserLibrewolf  Browser = "librewolf"
	BrowserSafari     Browser = "safari"
	BrowserUnknown    Browser = "unknown"
)

// InstallSource describes how the extension landed on the system.
// Pinned to the host_browser_extensions.install_source CHECK enum.
type InstallSource string

const (
	InstallStore            InstallSource = "store"
	InstallSideloaded       InstallSource = "sideloaded"
	InstallEnterprisePolicy InstallSource = "enterprise-policy"
	InstallDeveloper        InstallSource = "developer"
	InstallSystem           InstallSource = "system"
	InstallUnknown          InstallSource = "unknown"
)

// Extension is the cross-browser record produced by every collector.
// Mirrors the host_browser_extensions column shape; the slice fields
// serialise to JSON arrays via the Encode helpers.
type Extension struct {
	Browser         Browser       `json:"browser"`
	Profile         string        `json:"profile"`
	ExtensionID     string        `json:"extension_id"`
	Name            string        `json:"name,omitempty"`
	Version         string        `json:"version,omitempty"`
	Description     string        `json:"description,omitempty"`
	UpdateURL       string        `json:"update_url,omitempty"`
	ProfilePath     string        `json:"profile_path"`
	ManifestPath    string        `json:"manifest_path,omitempty"`
	InstallSource   InstallSource `json:"install_source"`
	Permissions     []string      `json:"permissions,omitempty"`
	HostPermissions []string      `json:"host_permissions,omitempty"`
	ManifestVersion int           `json:"manifest_version,omitempty"`
	Enabled         bool          `json:"enabled"`
}

// EncodeStringList returns a JSON array suitable for the *_json columns.
// Empty input always emits "[]" so the column is never NULL.
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

// IsBroadHostPermission reports whether a host-permission pattern grants
// the extension access to *every* site. These are the patterns to flag
// in the T1176 / permission audit.
func IsBroadHostPermission(p string) bool {
	switch p {
	case "<all_urls>",
		"*://*/*",
		"http://*/*",
		"https://*/*",
		"*://*:*/*",
		"file:///*":
		return true
	}
	// Schemeless wildcard top-level domain (e.g. "*://*").
	if strings.HasPrefix(p, "*://*") && (len(p) <= 6 || p[5] == '/') {
		return true
	}
	return false
}

// HasBroadPermissions reports whether any of the extension's host
// permissions grant universal-site access. Used by the T1176 audit rule.
func HasBroadPermissions(e Extension) bool {
	for _, p := range e.HostPermissions {
		if IsBroadHostPermission(p) {
			return true
		}
	}
	return false
}

// IsManifestV2Deprecated reports whether a Chromium-family extension is
// running on the deprecated MV2 platform. Firefox still supports MV2 so
// this only flags Chromium-family entries.
func IsManifestV2Deprecated(e Extension) bool {
	if e.ManifestVersion != 2 {
		return false
	}
	switch e.Browser {
	case BrowserChrome, BrowserChromium, BrowserEdge, BrowserBrave,
		BrowserOpera, BrowserVivaldi, BrowserArc:
		return true
	case BrowserFirefox, BrowserFirefoxESR, BrowserLibrewolf,
		BrowserSafari, BrowserUnknown:
		return false
	}
	return false
}

// SortExtensions returns a deterministic ordering: browser, profile,
// then extension_id (the natural key).
func SortExtensions(es []Extension) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Browser != es[j].Browser {
			return es[i].Browser < es[j].Browser
		}
		if es[i].Profile != es[j].Profile {
			return es[i].Profile < es[j].Profile
		}
		return es[i].ExtensionID < es[j].ExtensionID
	})
}
