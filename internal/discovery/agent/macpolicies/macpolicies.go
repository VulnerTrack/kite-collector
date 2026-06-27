// Package macpolicies inventories Linux Mandatory Access Control
// (MAC) state across SELinux, AppArmor, and the kernel's loaded LSM
// list.
//
// MAC is the "second authentication" layer between userspace
// privilege and kernel-mediated operations: even root can't violate
// a SELinux-enforced policy without subsystem-wide disablement.
// Whoever flips SELinux from enforcing to permissive (or unloads an
// AppArmor profile for a service) is preparing the host for an
// escalation that the discretionary permission model wouldn't allow.
//
// MITRE ATT&CK maps the relevant techniques as:
//
//   - T1562.001 (Disable or Modify Tools) — `setenforce 0`, removing
//     /etc/selinux/config's SELINUX=enforcing line, or
//     `aa-complain /path/to/profile` are all evasion primitives.
//   - T1014 (Rootkit) — kernel rootkits frequently disable LSMs as
//     a prerequisite; the /sys/kernel/security/lsm list flags
//     missing LSMs the host shipped with.
//
// Every collector is **read-only by intent** — it parses
// /etc/selinux/config, the /etc/apparmor.d/* profile files, and
// reads /sys/kernel/security/lsm. It never invokes setenforce,
// aa-enforce, or aa-complain. Read-only is enforced by guideline 4.2
// of the kite-collector project.
//
// Policy rows feed the audit pipeline:
//
//   - is_enforcing=0 on SELinux = T1562.001 finding.
//   - mode='complain' on an AppArmor profile = the profile logs but
//     no longer blocks. Same severity for that profile's scope.
//   - Drift between the configured SELINUX= value and the live LSM
//     reading exposes runtime tampers (config says enforcing; kernel
//     says permissive).
//   - file_hash drift on /etc/selinux/config or /etc/apparmor.d/*
//     = the policy was modified.
package macpolicies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxPolicies bounds per-scan output. An Ubuntu host running the
// full default AppArmor profile set has ~120 profiles; the 4096
// ceiling covers heavyweight server installs that also load custom
// profiles for every container.
const MaxPolicies = 4096

// Subsystem identifies which MAC produced the row. Pinned to the
// host_mac_policies.subsystem CHECK enum.
type Subsystem string

const (
	SubsystemSELinux  Subsystem = "selinux"
	SubsystemAppArmor Subsystem = "apparmor"
	SubsystemTomoyo   Subsystem = "tomoyo"
	SubsystemSmack    Subsystem = "smack"
	SubsystemYama     Subsystem = "yama"
	SubsystemLandlock Subsystem = "landlock"
	SubsystemBPFLSM   Subsystem = "bpf-lsm"
	SubsystemLSMList  Subsystem = "lsm-list"
	SubsystemUnknown  Subsystem = "unknown"
)

// Mode is the runtime/configured mode of a policy row. Pinned to
// host_mac_policies.mode.
type Mode string

const (
	ModeEnforcing  Mode = "enforcing"
	ModePermissive Mode = "permissive"
	ModeDisabled   Mode = "disabled"
	ModeComplain   Mode = "complain"
	ModeKill       Mode = "kill"
	ModeEnabled    Mode = "enabled"
	ModeAudit      Mode = "audit"
	ModeUnknown    Mode = "unknown"
)

// Policy is the parsed record produced per MAC source. Mirrors
// host_mac_policies' column shape exactly.
type Policy struct {
	Subsystem   Subsystem `json:"subsystem"`
	ProfileName string    `json:"profile_name"`
	Mode        Mode      `json:"mode"`
	PolicyType  string    `json:"policy_type,omitempty"`
	TargetPath  string    `json:"target_path,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	FileHash    string    `json:"file_hash,omitempty"`
	RawLine     string    `json:"raw_line,omitempty"`
	LineNo      int       `json:"line_no"`
	IsEnforcing bool      `json:"is_enforcing"`
	IsLoaded    bool      `json:"is_loaded"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Policy, error)
}

// HashContents returns the SHA-256 hex of a MAC config file. Drives
// drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeSELinuxMode maps the SELINUX= keyword to our Mode enum.
func NormalizeSELinuxMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enforcing":
		return ModeEnforcing
	case "permissive":
		return ModePermissive
	case "disabled":
		return ModeDisabled
	}
	return ModeUnknown
}

// NormalizeAppArmorMode maps the AppArmor `flags=(...)` keyword set
// to our Mode enum. AppArmor profiles default to enforce when
// `flags=` is absent. Precedence: kill > complain > audit (the more
// restrictive mode wins on a multi-flag profile so the audit
// pipeline doesn't soften a kill profile to audit-only).
func NormalizeAppArmorMode(flags []string) Mode {
	var sawComplain, sawAudit, sawKill bool
	for _, f := range flags {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "kill":
			sawKill = true
		case "complain":
			sawComplain = true
		case "audit":
			sawAudit = true
		}
	}
	switch {
	case sawKill:
		return ModeKill
	case sawComplain:
		return ModeComplain
	case sawAudit:
		return ModeAudit
	}
	return ModeEnforcing
}

// IsEnforcingMode reports whether the mode actively blocks operations
// (as opposed to merely logging them or being disabled). Both `kill`
// and `enforcing` count as enforcing for audit purposes.
func IsEnforcingMode(m Mode) bool {
	return m == ModeEnforcing || m == ModeKill
}

// AnnotateSecurity sets the indexed booleans on a policy row from its
// already-populated fields.
func AnnotateSecurity(p *Policy) {
	p.IsEnforcing = IsEnforcingMode(p.Mode)
	switch p.Mode {
	case ModeDisabled, ModeUnknown:
		p.IsLoaded = false
	case ModeEnforcing, ModePermissive, ModeComplain, ModeKill,
		ModeEnabled, ModeAudit:
		p.IsLoaded = true
	}
}

// SortPolicies returns a deterministic ordering: subsystem, then
// profile name. Useful for golden-file tests and stable diff output.
func SortPolicies(ps []Policy) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Subsystem != ps[j].Subsystem {
			return ps[i].Subsystem < ps[j].Subsystem
		}
		return ps[i].ProfileName < ps[j].ProfileName
	})
}
