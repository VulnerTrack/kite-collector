// Package browserpolicies inventories enterprise-managed browser
// policy files for Chrome, Edge, and Firefox. These policies are
// the MDM/AD-enforced configuration knobs that override per-user
// settings — exactly the surface a defender needs to confirm.
//
// File-based discovery is the deliberate design choice: every
// managed deployment writes these files at a vendor-canonical path
// (different per browser + per OS, but stable). The audit pipeline
// can hash each file for drift detection without invoking any
// browser process.
//
// Headline finding shapes (MITRE T1562.001 — Disable or Modify
// Tools, T1176 — Browser Extensions for the force-install rows):
//
//   - `is_safe_browsing_off=1` — `SafeBrowsingProtectionLevel=0`
//     (Chrome/Edge) or `DisableSafeBrowsing=true` (Firefox).
//     Phishing/malware download protection is off (CWE-693).
//   - `is_password_manager_off=1` — `PasswordManagerEnabled=false`.
//     Users reuse credentials elsewhere (CWE-256-adjacent).
//   - `is_download_restrictions_off=1` — `DownloadRestrictions=0`
//     allows binary downloads with no scan (T1105 staging).
//   - `is_extension_force_installed=1` — non-empty
//     `ExtensionInstallForcelist` / `Extensions` policy. Every
//     extension shipped this way runs in every tab; one bad
//     entry = browser-wide RCE (T1176 + T1195).
//   - `is_url_blocklist_empty=1` — `URLBlocklist` policy absent
//     OR empty. Managed deployments should ship at minimum a
//     phishing/malware blocklist.
//
// Read-only by intent — we parse JSON only, never invoke a
// browser. (Project guideline 4.2.)
package browserpolicies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A heavily-managed enterprise
// browser has 50-200 policies; three browsers per host = ~600 max
// in practice. The 4096 ceiling covers the long tail.
const MaxRows = 4096

// BrowserKind tags which vendor a policy file belongs to. Pinned
// to the host_browser_policies.browser_kind CHECK enum.
type BrowserKind string

const (
	BrowserChrome  BrowserKind = "chrome"
	BrowserEdge    BrowserKind = "edge"
	BrowserFirefox BrowserKind = "firefox"
	BrowserUnknown BrowserKind = "unknown"
)

// PolicyValueKind tags the JSON shape of a policy value. Pinned to
// the host_browser_policies.policy_value_kind CHECK enum.
type PolicyValueKind string

const (
	KindBool   PolicyValueKind = "bool"
	KindNumber PolicyValueKind = "number"
	KindString PolicyValueKind = "string"
	KindArray  PolicyValueKind = "array"
	KindObject PolicyValueKind = "object"
	KindNull   PolicyValueKind = "null"
)

// Policy mirrors host_browser_policies' column shape exactly.
type Policy struct {
	BrowserKind               BrowserKind     `json:"browser_kind"`
	FilePath                  string          `json:"file_path"`
	FileHash                  string          `json:"file_hash"`
	PolicyName                string          `json:"policy_name"`
	PolicyValueKind           PolicyValueKind `json:"policy_value_kind"`
	PolicyValue               string          `json:"policy_value"`
	IsSafeBrowsingOff         bool            `json:"is_safe_browsing_off"`
	IsPasswordManagerOff      bool            `json:"is_password_manager_off"`
	IsDownloadRestrictionsOff bool            `json:"is_download_restrictions_off"`
	IsExtensionForceInstalled bool            `json:"is_extension_force_installed"`
	IsURLBlocklistEmpty       bool            `json:"is_url_blocklist_empty"`
	IsConcerning              bool            `json:"is_concerning"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Policy, error)
}

// HashContents returns the SHA-256 hex of a policy-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AnnotateSecurity sets the derived booleans on a Policy that has
// its raw fields populated. The per-policy classifiers know about
// both Chrome/Edge keys (which share most names) and Firefox keys
// (which use a different scheme).
func AnnotateSecurity(p *Policy) {
	name := p.PolicyName
	val := p.PolicyValue
	kind := p.PolicyValueKind

	switch p.BrowserKind {
	case BrowserChrome, BrowserEdge:
		annotateChromeFamily(p, name, val, kind)
	case BrowserFirefox:
		annotateFirefox(p, name, val, kind)
	case BrowserUnknown:
		// Unknown vendor — leave booleans cleared.
	}

	p.IsConcerning = p.IsSafeBrowsingOff ||
		p.IsPasswordManagerOff ||
		p.IsDownloadRestrictionsOff ||
		p.IsExtensionForceInstalled ||
		p.IsURLBlocklistEmpty
}

func annotateChromeFamily(p *Policy, name, val string, kind PolicyValueKind) {
	switch name {
	case "SafeBrowsingProtectionLevel":
		// Levels: 0=disabled, 1=standard, 2=enhanced.
		p.IsSafeBrowsingOff = val == "0"
	case "SafeBrowsingEnabled":
		p.IsSafeBrowsingOff = val == "false"
	case "PasswordManagerEnabled":
		p.IsPasswordManagerOff = val == "false"
	case "DownloadRestrictions":
		// 0 = no restrictions, 1-4 increasingly strict.
		p.IsDownloadRestrictionsOff = val == "0"
	case "ExtensionInstallForcelist":
		if kind == KindArray && val != "[]" && strings.TrimSpace(val) != "" {
			p.IsExtensionForceInstalled = true
		}
	case "URLBlocklist":
		if kind == KindArray && (val == "[]" || strings.TrimSpace(val) == "") {
			p.IsURLBlocklistEmpty = true
		}
	}
}

func annotateFirefox(p *Policy, name, val string, kind PolicyValueKind) {
	switch name {
	case "DisableSafeBrowsing":
		p.IsSafeBrowsingOff = val == "true"
	case "PasswordManagerEnabled":
		p.IsPasswordManagerOff = val == "false"
	case "OfferToSaveLogins":
		p.IsPasswordManagerOff = val == "false"
	case "Extensions":
		// Firefox: Extensions can be `{"Install": [...], "Locked": true}`
		// — presence of an Install array means force-install.
		if kind == KindObject && strings.Contains(val, `"Install"`) {
			p.IsExtensionForceInstalled = true
		}
	case "WebsiteFilter":
		// Firefox blocklist analog. Empty Block array = absent.
		if kind == KindObject && (strings.Contains(val, `"Block":[]`) ||
			!strings.Contains(val, `"Block"`)) {
			p.IsURLBlocklistEmpty = true
		}
	}
}

// SortPolicies returns a deterministic ordering by browser_kind,
// file path, then policy_name.
func SortPolicies(ps []Policy) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].BrowserKind != ps[j].BrowserKind {
			return ps[i].BrowserKind < ps[j].BrowserKind
		}
		if ps[i].FilePath != ps[j].FilePath {
			return ps[i].FilePath < ps[j].FilePath
		}
		return ps[i].PolicyName < ps[j].PolicyName
	})
}
