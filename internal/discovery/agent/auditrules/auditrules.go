// Package auditrules inventories the Linux audit subsystem's rule set
// — /etc/audit/audit.rules plus every drop-in under /etc/audit/rules.d/.
//
// auditd is the defender's primary observation tool on Linux. Whoever
// controls its rule set controls what the SOC sees. MITRE ATT&CK maps
// the relevant techniques as:
//
//   - T1562.006 (Impair Defenses: Indicator Blocking) — adding
//     `never` rules that exclude the audit subsystem from observation,
//     or flushing the rule set with `auditctl -D`.
//   - T1070.002 (Indicator Removal: Clear Linux/Mac System Logs) —
//     attacker pre-condition is "are the relevant file-watch rules
//     present?". The inventory makes the absence detectable.
//   - T1098 (Account Manipulation) — `-w /etc/passwd -w /etc/shadow`
//     watches are how account-tamper events surface in the audit log.
//     Missing watches = blind spot.
//
// Every collector is **read-only by intent** — it parses rule files,
// never invokes `auditctl` to load/clear/lock rules. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Rule rows feed the audit pipeline:
//
//   - is_immutable=1 (a single `-e 2` line) flags hosts whose rules
//     are locked until reboot. Security-positive. Drift to 0 = active
//     tamper attempt.
//   - is_self_destructive=1 flags rules that exclude audit-subsystem
//     syscalls or that target the auditd binary path itself.
//   - is_sensitive_path_watch=1 flags `-w` rules covering the canonical
//     sensitive-paths set (/etc/passwd, /etc/shadow, /etc/sudoers,
//     /var/log/wtmp, etc.). Missing watches are findings.
//   - Drift events — file_hash change on any rules.d file = the audit
//     rule set was modified.
package auditrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxRules bounds per-scan output. The Red Hat STIG audit rule set
// is ~120 lines; the 2048 ceiling covers heavyweight CIS baselines
// that watch every binary under /usr/sbin.
const MaxRules = 2048

// RuleKind is the top-level type of an auditctl directive. Pinned to
// the host_audit_rules.rule_kind CHECK enum.
type RuleKind string

const (
	RuleKindFileWatch RuleKind = "file-watch"
	RuleKindSyscall   RuleKind = "syscall"
	RuleKindControl   RuleKind = "control"
	RuleKindUnknown   RuleKind = "unknown"
)

// List is the auditctl filter list. Pinned to host_audit_rules.list.
type List string

const (
	ListExit    List = "exit"
	ListExclude List = "exclude"
	ListUser    List = "user"
	ListTask    List = "task"
	ListUnknown List = "unknown"
)

// Action is the auditctl action keyword. Pinned to host_audit_rules.action.
type Action string

const (
	ActionAlways  Action = "always"
	ActionNever   Action = "never"
	ActionUnknown Action = "unknown"
)

// Rule is the parsed record produced per non-comment line. Mirrors
// host_audit_rules' column shape exactly.
type Rule struct {
	Arch                 string   `json:"arch,omitempty"`
	FilePath             string   `json:"file_path,omitempty"`
	Action               Action   `json:"action,omitempty"`
	Path                 string   `json:"path,omitempty"`
	Perm                 string   `json:"perm,omitempty"`
	RuleKind             RuleKind `json:"rule_kind"`
	RawLine              string   `json:"raw_line,omitempty"`
	Key                  string   `json:"key,omitempty"`
	List                 List     `json:"list,omitempty"`
	ControlValue         string   `json:"control_value,omitempty"`
	ControlFlag          string   `json:"control_flag,omitempty"`
	FileHash             string   `json:"file_hash,omitempty"`
	Syscalls             []string `json:"syscalls,omitempty"`
	Filters              []string `json:"filters,omitempty"`
	LineNo               int      `json:"line_no"`
	IsSensitivePathWatch bool     `json:"is_sensitive_path_watch"`
	IsSelfDestructive    bool     `json:"is_self_destructive"`
	IsImmutable          bool     `json:"is_immutable"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Rule, error)
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

// HashContents returns the SHA-256 hex of a rules file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SensitivePaths is the curated set of file paths a credible audit
// baseline must cover. Drawn from the CIS / DISA STIG audit profiles
// — these are the files an attacker modifies during the canonical
// account-takeover / log-cleaning playbooks.
func SensitivePaths() []string {
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/group",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/ssh/sshd_config",
		"/etc/ssh",
		"/etc/pam.d",
		"/etc/audit",
		"/etc/audit/audit.rules",
		"/etc/audit/rules.d",
		"/var/log/wtmp",
		"/var/log/btmp",
		"/var/log/lastlog",
		"/var/log/faillog",
		"/etc/selinux/config",
		"/etc/login.defs",
		"/etc/securetty",
		"/sbin/auditctl",
		"/sbin/auditd",
		"/usr/sbin/auditctl",
		"/usr/sbin/auditd",
	}
}

// IsSensitivePathTarget reports whether the watched path matches the
// curated sensitive-path set. Comparison is path-prefix: a watch on
// `/etc/sudoers.d` covers every file underneath.
func IsSensitivePathTarget(path string) bool {
	p := strings.TrimSpace(path)
	if p == "" {
		return false
	}
	for _, want := range SensitivePaths() {
		if p == want {
			return true
		}
	}
	return false
}

// SelfDestructiveSyscalls is the set of syscall names that, when paired
// with `action=never` on the `exit` list, exclude the audit subsystem
// from being observed. Listed here as the canonical T1562.006
// indicator set.
func SelfDestructiveSyscalls() []string {
	return []string{
		"audit_control",
		"auditctl",
		"setrlimit",
		"prctl",
	}
}

// IsSelfDestructiveSyscallExclude reports whether a rule excludes any
// of the audit-relevant syscalls. The classic pattern is:
//
//	-a never,exit -F arch=b64 -S audit_control
//
// which silently kills observation of auditctl invocations.
func IsSelfDestructiveSyscallExclude(action Action, list List, syscalls []string) bool {
	if action != ActionNever {
		return false
	}
	if list != ListExit && list != ListExclude && list != ListTask {
		return false
	}
	for _, s := range syscalls {
		for _, want := range SelfDestructiveSyscalls() {
			if strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
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
