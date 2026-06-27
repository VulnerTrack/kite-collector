// Package kernelmod enumerates loaded kernel modules / kernel
// extensions across Linux (/proc/modules + /sys/module), macOS
// (kextstat), Windows (SCM kernel-mode drivers), and FreeBSD
// (kldstat).
//
// Kernel modules are the deepest persistence primitive in MITRE
// ATT&CK (T1547.006 — Boot or Logon Autostart Execution: Kernel
// Modules and Extensions; T1014 — Rootkit). A single .ko loaded
// at boot can subvert every subsequent userspace audit. This
// collector is the inventory side — the audit pipeline correlates
// what's loaded against the kernel's module signing policy and
// against the on-disk /lib/modules tree to flag out-of-tree
// modules.
//
// Every collector is **read-only by intent**: it parses /proc and
// /sys files, never `insmod`/`rmmod`/`kextload`. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Module rows feed the audit pipeline:
//
//   - T1547.006 / T1014 — `is_out_of_tree=1` flags any module
//     loaded from outside /lib/modules/$(uname -r). Standard
//     tactic for kernel-level persistence.
//   - CWE-345 (Insufficient Verification of Data Authenticity) —
//     `is_unsigned=1` flags modules whose signature didn't verify
//     under the running kernel's signing policy.
//   - Taint events — any module loaded with the `F` (force) or
//     `E` (unsigned) taint letter is a kernel-integrity event.
//   - Drift events — every `file_hash` change on a module's .ko
//     file = the code that owns ring-0 changed.
package kernelmod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxModules bounds per-scan output. A maximally loaded mainline
// Linux kernel has ~300 modules; the 2048 ceiling covers vendor
// kernels (Oracle UEK, RHEL) that load broader hardware support.
const MaxModules = 2048

// Source identifies which OS subsystem produced the row. Pinned to
// the host_kernel_modules.source CHECK enum.
type Source string

const (
	SourceLinuxProcModules Source = "linux-proc-modules"
	SourceLinuxSysfs       Source = "linux-sysfs"
	SourceMacOSKextstat    Source = "macos-kextstat"
	SourceWindowsSCM       Source = "windows-scm"
	SourceFreeBSDKldstat   Source = "freebsd-kldstat"
	SourceOpenBSDModstat   Source = "openbsd-modstat"
	SourceUnknown          Source = "unknown"
)

// State is the runtime state of the module. Pinned to the
// host_kernel_modules.state CHECK enum.
type State string

const (
	StateLive      State = "live"
	StateLoading   State = "loading"
	StateUnloading State = "unloading"
	StateUnknown   State = "unknown"
)

// Module is the cross-OS record produced per loaded module.
// Mirrors host_kernel_modules' column shape exactly.
type Module struct {
	FileHash    string   `json:"file_hash,omitempty"`
	Taints      string   `json:"taints,omitempty"`
	State       State    `json:"state"`
	Signer      string   `json:"signer,omitempty"`
	FilePath    string   `json:"file_path,omitempty"`
	Name        string   `json:"name"`
	Source      Source   `json:"source"`
	Version     string   `json:"version,omitempty"`
	LoadAddress string   `json:"load_address,omitempty"`
	UsedBy      []string `json:"used_by,omitempty"`
	Refcount    int      `json:"refcount"`
	SizeBytes   int64    `json:"size_bytes"`
	IsUnsigned  bool     `json:"is_unsigned"`
	IsOutOfTree bool     `json:"is_out_of_tree"`
	IsTainting  bool     `json:"is_tainting"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Module, error)
}

// EncodeStringList returns a JSON array suitable for used_by_json.
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

// HashContents returns the SHA-256 hex of a module binary. Used for
// drift detection — same module name with a different binary hash
// between scans is a tamper event.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TaintingLetters is the set of taint flags that signal a kernel-
// integrity event (as opposed to license-only flags). Drawn from
// `Documentation/admin-guide/tainted-kernels.rst` in the Linux
// source tree:
//
//   - E: unsigned module loaded into a kernel supporting signature checks
//   - F: module forcibly loaded with `insmod -f`
//   - O: out-of-tree module loaded
//   - R: forcibly unloaded module
//   - U: user requested taint via /proc/sys/kernel/tainted
func TaintingLetters() string {
	return "EFORU"
}

// IsTaintingFlag reports whether the taint letter belongs to the
// integrity-affecting subset.
func IsTaintingFlag(c byte) bool {
	for i := 0; i < len(TaintingLetters()); i++ {
		if TaintingLetters()[i] == c {
			return true
		}
	}
	return false
}

// HasTaintingFlag reports whether any of the letters in `taints`
// affects kernel integrity (as opposed to just licensing).
func HasTaintingFlag(taints string) bool {
	for i := 0; i < len(taints); i++ {
		if IsTaintingFlag(taints[i]) {
			return true
		}
	}
	return false
}

// IsInTreePath reports whether the module path lives under the
// canonical kernel module tree, /lib/modules/<kernel-release>/.
// Modules loaded from anywhere else are out-of-tree (CWE-829 +
// T1547.006).
func IsInTreePath(path string) bool {
	if path == "" {
		// Empty path means /proc/modules didn't expose a file —
		// the kernel resolves the module's text segment in-place.
		// Treat as in-tree (we can't claim out-of-tree without evidence).
		return true
	}
	return strings.HasPrefix(path, "/lib/modules/") ||
		strings.HasPrefix(path, "/usr/lib/modules/") ||
		strings.HasPrefix(path, "/run/booted-system/kernel-modules/") // NixOS
}

// IsOutOfTreePath is the negation, named affirmatively so callers
// don't have to invert at every call site.
func IsOutOfTreePath(path string) bool {
	return !IsInTreePath(path)
}

// SortModules returns a deterministic ordering: source then name.
// Useful for golden-file tests and stable diff output.
func SortModules(ms []Module) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Source != ms[j].Source {
			return ms[i].Source < ms[j].Source
		}
		return ms[i].Name < ms[j].Name
	})
}
