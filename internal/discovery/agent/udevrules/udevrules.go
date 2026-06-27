// Package udevrules inventories every udev rule the kernel will
// evaluate on device events. Sources covered:
//
//   - /etc/udev/rules.d/*.rules        — admin-set overrides
//   - /usr/lib/udev/rules.d/*.rules    — vendor (and /lib/udev/...)
//   - /run/udev/rules.d/*.rules        — runtime overlays
//
// udev sits between every hotplug event and userspace. A rule whose
// `RUN+=` invokes an attacker-controlled script fires whenever the
// matched device class appears — USB stick attach, network interface
// up, disk plug. This is one of the most reliable Linux persistence
// primitives precisely because admins rarely audit it.
//
// MITRE ATT&CK maps the relevant techniques as:
//
//   - T1547.010 (XDG Autostart class) — udev RUN+= is the device-tier
//     equivalent: trigger-on-attach without ever touching crontab,
//     systemd, or login shell init.
//   - T1546 (Event Triggered Execution) — the broader umbrella.
//
// Every collector is **read-only by intent** — it parses .rules
// files, never invokes udevadm trigger / reload-rules. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Rule rows feed the audit pipeline:
//
//   - `is_dangerous_run=1` flags RUN+= whose target lives under
//     /tmp, /var/tmp, /home, /dev/shm, or any unusual writable path.
//     Even a root-context invocation of a user-controlled binary is
//     CWE-426 (Untrusted Search Path).
//   - `is_world_writable_mode=1` flags MODE= values that open the
//     device node to non-root processes (MODE=0666 on /dev/sd*, etc.).
//   - `has_run=1 AND is_critical_subsystem=1` flags every device-attach
//     hook on block/net/input/usb (where unprivileged users can
//     trigger). The audit pipeline correlates against
//     host_scheduled_jobs + host_services to spot duplicate persistence
//     chains.
//   - File hash drift on any /etc/udev/rules.d file = the device-attach
//     policy changed.
package udevrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// MaxRules bounds per-scan output. A typical Linux host has 50-200
// active udev rules; the 4096 ceiling covers heavyweight vendor
// installs (NVIDIA, Bluetooth firmware, dozens of USB classes).
const MaxRules = 4096

// Scope identifies which file tree produced the row. Pinned to the
// host_udev_rules.scope CHECK enum.
type Scope string

const (
	ScopeAdmin   Scope = "admin"   // /etc/udev/rules.d/
	ScopeVendor  Scope = "vendor"  // /usr/lib/udev/rules.d/ + /lib/udev/rules.d/
	ScopeRuntime Scope = "runtime" // /run/udev/rules.d/
	ScopeUnknown Scope = "unknown"
)

// Rule is the parsed record produced per non-comment line. Mirrors
// host_udev_rules' column shape exactly.
type Rule struct {
	Owner               string   `json:"owner,omitempty"`
	ModeValue           string   `json:"mode_value,omitempty"`
	FileHash            string   `json:"file_hash,omitempty"`
	GroupName           string   `json:"group_name,omitempty"`
	Kernel              string   `json:"kernel,omitempty"`
	Action              string   `json:"action,omitempty"`
	RunCommand          string   `json:"run_command,omitempty"`
	FilePath            string   `json:"file_path,omitempty"`
	RawLine             string   `json:"raw_line,omitempty"`
	Scope               Scope    `json:"scope"`
	Subsystem           string   `json:"subsystem,omitempty"`
	MatchKeys           []string `json:"match_keys,omitempty"`
	ActionKeys          []string `json:"action_keys,omitempty"`
	LineNo              int      `json:"line_no"`
	HasRun              bool     `json:"has_run"`
	IsCriticalSubsystem bool     `json:"is_critical_subsystem"`
	IsDangerousRun      bool     `json:"is_dangerous_run"`
	IsWorldWritableMode bool     `json:"is_world_writable_mode"`
	HasImport           bool     `json:"has_import"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Rule, error)
}

// EncodeStringList returns a JSON array suitable for *_json columns.
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

// HashContents returns the SHA-256 hex of a .rules file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CriticalSubsystems is the curated set whose attached devices can be
// influenced by unprivileged users — a USB stick attach, a hot-plugged
// network adapter, an input device. RUN+= rules on these are the
// highest-leverage persistence surface.
func CriticalSubsystems() []string {
	return []string{
		"usb", "usb_device",
		"block",
		"net",
		"input",
		"tty",
		"bluetooth",
		"sound",
		"video4linux",
	}
}

// IsCriticalSubsystem reports whether the SUBSYSTEM== value is in the
// curated user-triggerable set.
func IsCriticalSubsystem(subsystem string) bool {
	want := strings.ToLower(strings.TrimSpace(subsystem))
	if want == "" {
		return false
	}
	for _, s := range CriticalSubsystems() {
		if s == want {
			return true
		}
	}
	return false
}

// DangerousRunPrefixes is the set of path prefixes that should never
// host a RUN+= target. Anything under /tmp, /var/tmp, /home, /dev/shm,
// /run/user is world-writable or user-writable; placing an executable
// there gives every local user a privilege-escalation primitive.
func DangerousRunPrefixes() []string {
	return []string{
		"/tmp/",
		"/var/tmp/",
		"/home/",
		"/dev/shm/",
		"/run/user/",
		"/root/.cache/", // unusual location for a system-context RUN
	}
}

// IsDangerousRunPath reports whether the RUN+= target lives in a
// path attackers can write to. The check is path-prefix only — we
// don't stat the file (would race; the file may be created on demand).
func IsDangerousRunPath(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return false
	}
	// RUN+= values can include shell, e.g. RUN+="/bin/sh -c '...'".
	// Strip the leading binary path.
	fields := strings.Fields(c)
	if len(fields) == 0 {
		return false
	}
	binary := fields[0]
	for _, prefix := range DangerousRunPrefixes() {
		if strings.HasPrefix(binary, prefix) {
			return true
		}
	}
	// Also flag when the shell -c body invokes a script in a sketchy path.
	if binary == "/bin/sh" || binary == "/bin/bash" || binary == "/usr/bin/env" {
		body := c
		for _, prefix := range DangerousRunPrefixes() {
			if strings.Contains(body, prefix) {
				return true
			}
		}
	}
	return false
}

// IsWorldWritableMode reports whether a MODE= value grants write
// access to "other" (the low octal digit ≥ 2 implies write).
func IsWorldWritableMode(mode string) bool {
	v := strings.TrimSpace(mode)
	if v == "" {
		return false
	}
	// Strip leading "0o" prefix for Go-style octal literals.
	v = strings.TrimPrefix(v, "0o")
	n, err := strconv.ParseInt(v, 8, 32)
	if err != nil {
		return false
	}
	// Bottom 3 bits = "other" permission. Bit 1 (value 2) = write.
	return n&0o2 != 0
}

// AnnotateSecurity sets the indexed booleans on a rule row from its
// already-parsed match/action keys.
func AnnotateSecurity(r *Rule) {
	r.IsCriticalSubsystem = IsCriticalSubsystem(r.Subsystem)
	r.IsWorldWritableMode = IsWorldWritableMode(r.ModeValue)
	r.IsDangerousRun = r.HasRun && IsDangerousRunPath(r.RunCommand)
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
