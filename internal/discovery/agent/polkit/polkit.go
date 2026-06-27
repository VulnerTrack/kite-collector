// Package polkit inventories PolicyKit (polkit) authorisation policy
// across action-policy XML files under /usr/share/polkit-1/actions/
// and JS rules under /etc/polkit-1/rules.d/ + /usr/share/polkit-1/
// rules.d/.
//
// polkit is the modern privilege-broker on Linux desktops and many
// servers — gnome-shell, NetworkManager, systemctl, mount, virsh,
// flatpak, and dozens of other utilities funnel privileged
// operations through it. Its policy answers the question "may this
// unprivileged user perform this privileged action without being
// prompted?". A misconfigured rule (`return polkit.Result.YES` for a
// systemd-manage-units action) is a one-line root-equivalent.
//
// MITRE ATT&CK maps the relevant techniques as:
//
//   - T1548 (Abuse Elevation Control Mechanism) — passwordless polkit
//     actions enable interactive escalation without sudo.
//   - T1068 (Exploitation for Privilege Escalation) — argument-handling
//     bugs like CVE-2021-4034 (pwnkit) live in the C bridge; rule-level
//     misconfig is the policy-side equivalent.
//   - CWE-269 (Improper Privilege Management) — `is_passwordless=1`
//     flags allow_* slots set to `yes` rather than auth_*.
//
// Every collector is **read-only by intent** — it parses .policy XML
// and .rules JS files (without executing them), never modifies any
// authorisation rule. Read-only is enforced by guideline 4.2 of the
// kite-collector project.
package polkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxRules bounds per-scan output. A typical desktop has ~200
// action-policy XML rows + ~20 JS rules; the 4096 ceiling covers
// heavyweight Cinnamon/KDE installs without bloating SQLite writes.
const MaxRules = 4096

// Source identifies which file kind produced the row. Pinned to the
// host_polkit_rules.source CHECK enum.
type Source string

const (
	SourceActionPolicy   Source = "action-policy"
	SourceLocalRules     Source = "local-rules"
	SourceVendorRules    Source = "vendor-rules"
	SourceAuthorityStore Source = "authority-store"
	SourceUnknown        Source = "unknown"
)

// Rule is the parsed record. Mirrors host_polkit_rules' column shape
// exactly.
type Rule struct {
	RuleSnippet       string `json:"rule_snippet,omitempty"`
	FilePath          string `json:"file_path,omitempty"`
	ActionDescription string `json:"action_description,omitempty"`
	AllowAny          string `json:"allow_any,omitempty"`
	AllowInactive     string `json:"allow_inactive,omitempty"`
	AllowActive       string `json:"allow_active,omitempty"`
	RawLine           string `json:"raw_line,omitempty"`
	FileHash          string `json:"file_hash,omitempty"`
	ActionID          string `json:"action_id,omitempty"`
	Source            Source `json:"source"`
	LineNo            int    `json:"line_no"`
	GrantsYES         bool   `json:"grants_yes"`
	IsCritical        bool   `json:"is_critical"`
	IsPasswordless    bool   `json:"is_passwordless"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Rule, error)
}

// HashContents returns the SHA-256 hex of a polkit file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CriticalActionPrefixes is the curated set of action-id prefixes
// the audit pipeline treats as privilege-escalation primitives. Any
// rule that mentions one of these in `action_id` or that explicitly
// matches it in a .rules JS file flips `is_critical=1`.
//
// Source: polkit upstream + Red Hat / GNOME / freedesktop documented
// pkexec wrappers.
func CriticalActionPrefixes() []string {
	return []string{
		"org.freedesktop.systemd1.manage-units",
		"org.freedesktop.systemd1.manage-unit-files",
		"org.freedesktop.systemd1.reload-daemon",
		"org.freedesktop.policykit.exec", // pkexec itself
		"org.freedesktop.policykit.lockdown",
		"org.freedesktop.udisks2.",        // disk mounts (any subaction)
		"org.freedesktop.NetworkManager.", // any NM modification
		"org.freedesktop.ModemManager1.",
		"org.freedesktop.locale1.set-locale",
		"org.freedesktop.timedate1.",
		"org.freedesktop.hostname1.",
		"org.freedesktop.login1.power-off",
		"org.freedesktop.login1.reboot",
		"org.libvirt.unix.manage", // virsh privileged actions
		"org.libvirt.unix.monitor",
		"org.fedoraproject.SetuidWrapper.",
	}
}

// IsCriticalAction reports whether the action id matches one of the
// curated critical prefixes.
func IsCriticalAction(actionID string) bool {
	id := strings.TrimSpace(actionID)
	if id == "" {
		return false
	}
	for _, p := range CriticalActionPrefixes() {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// IsPasswordlessSlot reports whether one of the `allow_any` /
// `allow_inactive` / `allow_active` slot values grants without
// authentication. The polkit grammar (per pklocalauthority(8)):
//
//	yes              — allow without auth
//	no               — deny outright
//	auth_self        — interactive password prompt (user's own pwd)
//	auth_self_keep   — like auth_self, cached
//	auth_admin       — interactive password prompt (admin pwd)
//	auth_admin_keep  — like auth_admin, cached
func IsPasswordlessSlot(slot string) bool {
	return strings.EqualFold(strings.TrimSpace(slot), "yes")
}

// AnnotateActionPolicy sets the indexed booleans on a Rule that came
// from a .policy XML file.
func AnnotateActionPolicy(r *Rule) {
	r.IsCritical = IsCriticalAction(r.ActionID)
	r.IsPasswordless = IsPasswordlessSlot(r.AllowAny) ||
		IsPasswordlessSlot(r.AllowInactive) ||
		IsPasswordlessSlot(r.AllowActive)
}

// AnnotateJSRule sets the indexed booleans on a Rule that came from
// a .rules JS file. The classification is heuristic — we can't fully
// evaluate JS — so we only flag obvious `return polkit.Result.YES`
// patterns and critical action mentions.
func AnnotateJSRule(r *Rule) {
	r.IsCritical = IsCriticalAction(r.ActionID)
	// `GrantsYES` is set by the parser when the rule body contains
	// `polkit.Result.YES`. A YES + critical action = T1548 finding.
	if r.GrantsYES {
		r.IsPasswordless = true
	}
}

// SortRules returns a deterministic ordering: file path, then line.
func SortRules(rs []Rule) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		return rs[i].LineNo < rs[j].LineNo
	})
}
