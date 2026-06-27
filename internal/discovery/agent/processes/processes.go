// Package processes enumerates running OS processes across Linux, macOS,
// Windows, and the BSDs. A single cross-platform collector is possible
// because gopsutil/v4 already abstracts every per-OS source (Linux /proc,
// macOS sysctl, Windows NtQuerySystemInformation/WMI, FreeBSD kvm). No
// per-OS build tags required — that's the whole reason gopsutil exists.
//
// Every collector is **read-only** — it queries process metadata, never
// kill(), nice(), ptrace(), or otherwise manipulates running processes.
// Read-only is enforced by guideline 4.2 of the kite-collector project.
//
// Process rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-250 (Execution with Unnecessary Privileges) — userspace processes
//     running as root / SYSTEM when they don't need to.
//   - CWE-732 (Incorrect Permission Assignment) — world-writable binaries
//     (rss_bytes > 0 + exe path joined with file permissions).
//   - CWE-693 (Protection Mechanism Failure) — security daemons in
//     `zombie` or `stopped` state (cross-referenced with HostService rows).
//
// Cap: MaxProcesses bounds per-scan output. On a typical desktop this is
// 300-500; on a busy server 2000-3000. The 4096 ceiling protects the
// SQLite write path from runaway forks.
package processes

import (
	"context"
	"sort"
	"strings"
	"time"
)

// MaxProcesses is the hard ceiling on rows emitted per scan. Exceeding
// this is a strong signal of fork-bomb / runaway workloads; truncating is
// safer than blowing the SQLite WAL.
const MaxProcesses = 4096

// MaxCmdlineBytes truncates extremely long command lines (some Java /
// Hadoop processes have 8KB+ classpath args). Forensic value plateaus
// after a few KB.
const MaxCmdlineBytes = 4096

// Status normalises gopsutil's per-OS process status strings into the
// SQLite host_processes.status CHECK enum. Values are pinned — renaming
// any constant breaks the migration.
type Status string

const (
	StatusRunning  Status = "running"
	StatusSleeping Status = "sleeping"
	StatusIdle     Status = "idle"
	StatusStopped  Status = "stopped"
	StatusZombie   Status = "zombie"
	StatusWait     Status = "wait"
	StatusLock     Status = "lock"
	StatusUnknown  Status = "unknown"
)

// Process is the cross-platform record produced by every collector. It
// mirrors the column shape of host_processes so the store layer can
// persist rows without a translation step.
type Process struct {
	StartedAt      time.Time `json:"started_at,omitempty"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	CollectedAt    time.Time `json:"collected_at"`
	Username       string    `json:"username,omitempty"`
	Exe            string    `json:"exe,omitempty"`
	Cmdline        string    `json:"cmdline,omitempty"`
	Name           string    `json:"name"`
	CWD            string    `json:"cwd,omitempty"`
	Status         Status    `json:"status"`
	RSSBytes       uint64    `json:"rss_bytes,omitempty"`
	VMSBytes       uint64    `json:"vms_bytes,omitempty"`
	PID            int32     `json:"pid"`
	PPID           int32     `json:"ppid"`
	NumThreads     int32     `json:"num_threads,omitempty"`
	IsKernelThread bool      `json:"is_kernel_thread"`
}

// Collector is the read-only contract every implementation satisfies. The
// returned slice is empty (not nil) when no processes can be enumerated
// (e.g. inside a restricted container) so callers can range without nil
// checks.
type Collector interface {
	// Name returns a stable identifier for telemetry.
	Name() string
	// Collect enumerates running processes. Read-only: never sends a
	// signal, never traces, never mutates kernel state. Partial results
	// are returned alongside the error when meaningful.
	Collect(ctx context.Context) ([]Process, error)
}

// NormalizeStatus maps gopsutil's per-OS status strings to our pinned
// enum. gopsutil emits Linux-style short forms ("S","R","Z") on Linux,
// human strings ("running","sleeping") on Windows and macOS, and the
// FreeBSD codes ("Run","Sleep","Stop","Zomb") elsewhere — handle all.
func NormalizeStatus(raw string) Status {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "r", "running", "run":
		return StatusRunning
	case "s", "sleep", "sleeping":
		return StatusSleeping
	case "i", "idle":
		return StatusIdle
	case "t", "stop", "stopped":
		return StatusStopped
	case "z", "zomb", "zombie":
		return StatusZombie
	case "w", "wait":
		return StatusWait
	case "l", "lock":
		return StatusLock
	case "":
		return StatusUnknown
	}
	return StatusUnknown
}

// IsKernelThread reports whether the (name, ppid) pair indicates a kernel
// thread on Linux. Kernel threads have ppid=2 (kthreadd) and their `comm`
// is wrapped in brackets (`[kworker/u:0]`). Returns false on platforms
// where the distinction doesn't apply.
func IsKernelThread(name string, ppid int32) bool {
	if ppid != 2 {
		return false
	}
	return strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]")
}

// TruncateCmdline caps a command line at MaxCmdlineBytes and appends a
// trailing marker so downstream consumers can tell truncation from
// completion. Multi-byte UTF-8 sequences are preserved — the cut happens
// on a rune boundary.
func TruncateCmdline(s string) string {
	if len(s) <= MaxCmdlineBytes {
		return s
	}
	// Walk runes until we exceed the limit, then cut at the last good rune.
	var consumed int
	for i := range s {
		if i > MaxCmdlineBytes-3 { // reserve 3 bytes for the "..." marker
			return s[:consumed] + "..."
		}
		consumed = i
	}
	return s[:consumed] + "..."
}

// SortProcesses returns a deterministic ordering: by PID ascending.
// Useful for golden-file tests and stable diff output across scans.
func SortProcesses(ps []Process) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].PID < ps[j].PID })
}
