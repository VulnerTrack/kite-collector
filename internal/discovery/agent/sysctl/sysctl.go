// Package sysctl inventories Linux kernel tunables (sysctl). It
// reads every configuration file the sysctl(8) loader consumes
// (/etc/sysctl.conf, /etc/sysctl.d/*, /usr/lib/sysctl.d/*,
// /run/sysctl.d/*) and optionally the live /proc/sys/* tree so the
// audit pipeline can spot drift between the configured baseline and
// the running kernel.
//
// sysctl is the kernel-hardening surface. Most CIS Linux benchmark
// controls in section 3 (Network configuration) and section 1
// (Initial setup) are sysctl assertions: "kernel.kptr_restrict=2",
// "net.ipv4.conf.all.rp_filter=1", "fs.protected_symlinks=1", etc.
//
// MITRE ATT&CK maps relevant techniques as:
//
//   - T1562 (Impair Defenses) — flipping kernel.kptr_restrict=0 exposes
//     kernel pointers an exploit needs; kernel.dmesg_restrict=0 leaks
//     the same data through dmesg(1).
//   - T1014 (Rootkit) — kernel.yama.ptrace_scope=0 enables credential-
//     harvest via ptrace on running processes.
//   - CWE-1248 — kernel.core_pattern values that pipe to attacker-
//     controlled programs (CVE-2021-3492 family).
//
// Every collector is **read-only by intent** — it parses sysctl.d
// files and reads /proc/sys, never invokes `sysctl -w`. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
package sysctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxSettings bounds per-scan output. A typical Linux host has 200-
// 600 distinct sysctls when /proc/sys is fully harvested; the 8192
// ceiling covers heavyweight servers without bloating SQLite writes.
const MaxSettings = 8192

// Source identifies which file/subsystem produced the row. Pinned to
// the host_sysctl_settings.source CHECK enum.
type Source string

const (
	SourceEtcSysctlConf Source = "etc-sysctl-conf"
	SourceEtcSysctlD    Source = "etc-sysctl-d"
	SourceUsrLibSysctlD Source = "usr-lib-sysctl-d"
	SourceRunSysctlD    Source = "run-sysctl-d"
	SourceProcSys       Source = "proc-sys"
	SourceUnknown       Source = "unknown"
)

// Setting is the parsed record produced per non-comment sysctl line.
// Mirrors host_sysctl_settings' column shape exactly.
type Setting struct {
	Source              Source `json:"source"`
	Key                 string `json:"key"`
	CurrentValue        string `json:"current_value"`
	ExpectedValue       string `json:"expected_value,omitempty"`
	FilePath            string `json:"file_path,omitempty"`
	FileHash            string `json:"file_hash,omitempty"`
	RawLine             string `json:"raw_line,omitempty"`
	LineNo              int    `json:"line_no"`
	IsSecurityCritical  bool   `json:"is_security_critical"`
	IsBaselineViolation bool   `json:"is_baseline_violation"`
	IsDriftFromDisk     bool   `json:"is_drift_from_disk"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Setting, error)
}

// HashContents returns the SHA-256 hex of a sysctl config file.
// Drives drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SecurityBaseline maps every security-critical sysctl key to its
// CIS / kernel-hardening expected value. Keys not in this map are
// inventoried but not flagged as violations.
//
// Sources:
//   - CIS Debian Linux 12 Benchmark v2.0.0 (sections 3.2, 3.3, 3.4)
//   - CIS RHEL 9 Benchmark v2.0.0 (sections 3.2, 3.3, 3.4)
//   - kernel.org Documentation/admin-guide/sysctl/
//   - "Linux kernel-hardening checklist" by Alexander Popov
//
// Values stored as the canonical zero/one/string the kernel writes
// to /proc/sys/<key>; comparison is string-equal after trim.
func SecurityBaseline() map[string]string {
	return map[string]string{
		// Kernel hardening
		"kernel.dmesg_restrict":            "1",
		"kernel.kptr_restrict":             "2",
		"kernel.yama.ptrace_scope":         "1",
		"kernel.unprivileged_bpf_disabled": "1",
		"kernel.kexec_load_disabled":       "1",
		"kernel.sysrq":                     "0",
		"kernel.perf_event_paranoid":       "3",
		"kernel.randomize_va_space":        "2",
		// Filesystem hardening
		"fs.protected_hardlinks": "1",
		"fs.protected_symlinks":  "1",
		"fs.protected_fifos":     "2",
		"fs.protected_regular":   "2",
		"fs.suid_dumpable":       "0",
		// IPv4 network hardening
		"net.ipv4.conf.all.rp_filter":                "1",
		"net.ipv4.conf.default.rp_filter":            "1",
		"net.ipv4.conf.all.accept_source_route":      "0",
		"net.ipv4.conf.default.accept_source_route":  "0",
		"net.ipv4.conf.all.accept_redirects":         "0",
		"net.ipv4.conf.default.accept_redirects":     "0",
		"net.ipv4.conf.all.secure_redirects":         "0",
		"net.ipv4.conf.default.secure_redirects":     "0",
		"net.ipv4.conf.all.send_redirects":           "0",
		"net.ipv4.conf.default.send_redirects":       "0",
		"net.ipv4.conf.all.log_martians":             "1",
		"net.ipv4.conf.default.log_martians":         "1",
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
		"net.ipv4.tcp_syncookies":                    "1",
		// IPv6 network hardening
		"net.ipv6.conf.all.accept_ra":               "0",
		"net.ipv6.conf.default.accept_ra":           "0",
		"net.ipv6.conf.all.accept_redirects":        "0",
		"net.ipv6.conf.default.accept_redirects":    "0",
		"net.ipv6.conf.all.accept_source_route":     "0",
		"net.ipv6.conf.default.accept_source_route": "0",
	}
}

// ExpectedValue returns the baseline value for the given key, or
// ("", false) when the key isn't security-critical.
func ExpectedValue(key string) (string, bool) {
	v, ok := SecurityBaseline()[normalizeKey(key)]
	return v, ok
}

// IsSecurityCritical reports whether the key is in the baseline map.
func IsSecurityCritical(key string) bool {
	_, ok := SecurityBaseline()[normalizeKey(key)]
	return ok
}

// IsBaselineViolation reports whether the live value diverges from
// the baseline. Keys not in the baseline return false.
func IsBaselineViolation(key, value string) bool {
	want, ok := ExpectedValue(key)
	if !ok {
		return false
	}
	return strings.TrimSpace(value) != want
}

// normalizeKey converts the two sysctl spellings to one canonical form.
// sysctl accepts both `kernel.kptr_restrict` and `kernel/kptr_restrict`;
// /proc/sys exposes the slash form. We canonicalise to the dot form
// so the index unique constraint holds across sources.
func normalizeKey(key string) string {
	return strings.ReplaceAll(strings.TrimSpace(key), "/", ".")
}

// NormalizeKey is the exported wrapper. The collector uses it to
// emit consistent rows regardless of where the key was sourced from.
func NormalizeKey(key string) string {
	return normalizeKey(key)
}

// AnnotateSecurity sets the indexed booleans on a setting row from
// its already-populated key/value pair.
func AnnotateSecurity(s *Setting) {
	s.Key = NormalizeKey(s.Key)
	s.IsSecurityCritical = IsSecurityCritical(s.Key)
	if v, ok := ExpectedValue(s.Key); ok {
		s.ExpectedValue = v
		s.IsBaselineViolation = strings.TrimSpace(s.CurrentValue) != v
	}
}

// SortSettings returns a deterministic ordering: source, then key.
func SortSettings(ss []Setting) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Source != ss[j].Source {
			return ss[i].Source < ss[j].Source
		}
		return ss[i].Key < ss[j].Key
	})
}
