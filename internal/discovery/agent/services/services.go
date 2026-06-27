// Package services enumerates managed OS services across Linux (systemd),
// macOS (launchd), and Windows (Service Control Manager). It mirrors the
// design of the `driver` package: a single cross-platform domain type
// (Service) plus per-OS build-tagged collectors that fill it.
//
// Every collector is **read-only** — none start, stop, mask, or otherwise
// manipulate the service-manager state. Read-only is enforced by guideline
// 4.2 of the kite-collector project. The host_services SQLite table is the
// durable sink (migration 20260623120000_host_services.sql).
//
// HostService rows feed the CWE/CAPEC audit pipeline directly:
//
//   - CWE-693 (Protection Mechanism Failure) — a service in `failed` state
//     when start_mode = `auto` is a signal the security control is offline.
//   - CWE-732 (Incorrect Permission Assignment) — a service running as a
//     privileged account (root / LocalSystem / NetworkService) when its
//     unit file is world-writable.
//   - CWE-319 (Cleartext Transmission) — well-known plaintext services
//     (telnet.service, rsh.socket) running on a host.
package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Manager is the source-of-record that produced a Service row. The string
// values are pinned (must match the host_services.manager CHECK enum in
// the SQLite migration).
type Manager string

const (
	ManagerSystemd    Manager = "systemd"
	ManagerLaunchd    Manager = "launchd"
	ManagerWindowsSCM Manager = "windows-scm"
	ManagerOpenRC     Manager = "openrc"
	ManagerSysV       Manager = "sysv"
	ManagerUnknown    Manager = "unknown"
)

// State is the normalised runtime state of a service. Strings are pinned
// to the host_services.state CHECK enum.
type State string

const (
	StateRunning      State = "running"
	StateStopped      State = "stopped"
	StateFailed       State = "failed"
	StateActivating   State = "activating"
	StateDeactivating State = "deactivating"
	StateMasked       State = "masked"
	StateNotFound     State = "not-found"
	StateUnknown      State = "unknown"
)

// StartMode classifies when the service-manager intends to start the unit.
// Strings are pinned to the host_services.start_mode CHECK enum.
type StartMode string

const (
	StartAuto     StartMode = "auto"     // systemd "enabled", SCM "auto"
	StartManual   StartMode = "manual"   // systemd "disabled" but startable, SCM "manual"
	StartDisabled StartMode = "disabled" // explicitly disabled
	StartBoot     StartMode = "boot"     // SCM boot-time driver
	StartSystem   StartMode = "system"   // SCM kernel-load driver
	StartStatic   StartMode = "static"   // systemd "static" (no [Install] section)
	StartMasked   StartMode = "masked"   // systemd "masked"
	StartOnDemand StartMode = "on-demand"
	StartUnknown  StartMode = "unknown"
)

// Service is the cross-platform record produced by every collector. It
// mirrors the column shape of host_services so the store layer can persist
// rows without a translation step.
type Service struct {
	LastSeenAt  time.Time `json:"last_seen_at"`
	CollectedAt time.Time `json:"collected_at"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	Description string    `json:"description,omitempty"`
	RunAs       string    `json:"run_as,omitempty"`
	BinaryPath  string    `json:"binary_path,omitempty"`
	ConfigPath  string    `json:"config_path,omitempty"`
	ConfigHash  string    `json:"config_hash,omitempty"`
	Manager     Manager   `json:"manager"`
	State       State     `json:"state"`
	StartMode   StartMode `json:"start_mode"`
	PID         int       `json:"pid,omitempty"`
	ExitCode    int       `json:"exit_code,omitempty"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
// Implementations live in build-tagged files: linux.go, darwin.go,
// windows.go. The returned slice is empty (not nil) when the platform has
// no service manager available, so callers can range without nil checks.
type Collector interface {
	// Name returns a stable identifier for telemetry (e.g. "systemd").
	Name() string
	// Collect enumerates managed services. Read-only: never starts, stops,
	// masks, or mutates any unit. Errors are surfaced to the caller; partial
	// results are returned alongside the error when meaningful.
	Collect(ctx context.Context) ([]Service, error)
}

// FingerprintConfig returns a deterministic content hash for a config blob
// (unit file body, plist XML, SCM registry export). Two services with equal
// fingerprints are functionally identical from the manager's perspective —
// changes here drive drift detection in the audit pipeline.
func FingerprintConfig(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SortServices returns a deterministic ordering: by manager then by name.
// Useful for golden-file tests and stable diff output.
func SortServices(svcs []Service) {
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].Manager != svcs[j].Manager {
			return svcs[i].Manager < svcs[j].Manager
		}
		return svcs[i].Name < svcs[j].Name
	})
}

// NormalizeName trims well-known suffixes so two managers reporting the
// "same" logical service (e.g. systemd's `sshd.service` vs SCM's `sshd`)
// collapse to one identity across hosts in cross-cluster reports.
func NormalizeName(name string) string {
	n := strings.TrimSpace(name)
	for _, suffix := range []string{".service", ".socket", ".timer", ".plist"} {
		n = strings.TrimSuffix(n, suffix)
	}
	return n
}
