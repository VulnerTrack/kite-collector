// Package kernelcmdline inventories every parameter the Linux kernel
// saw at boot time, drawn from the live /proc/cmdline and the
// configured /etc/default/grub.
//
// The boot command line is one of the highest-leverage tampering
// surfaces on a Linux host: a single token can replace /sbin/init
// with an attacker-controlled binary (T1547), disable kernel
// signature verification (T1542), or silently turn off SELinux /
// AppArmor / auditd before userspace even starts (T1562.001).
//
// Every collector is **read-only by intent** — it parses /proc and
// /etc files, never invokes `grub-mkconfig` or `grub-set-default`.
// Read-only is enforced by guideline 4.2 of the kite-collector
// project.
//
// Parameter rows feed the audit pipeline:
//
//   - is_baseline_violation=1 + finding_category='cpu-mitigation-disabled'
//     flags mitigations=off / nopti / nospectre_v2 / noibrs.
//   - finding_category='init-override' is a maximum-severity event:
//     init= replaces PID 1.
//   - finding_category='module-signing-off' precedes unsigned-module
//     rootkit installation.
//   - finding_category='mac-disabled' flags selinux=0 / apparmor=0
//     boot-time bypasses (regardless of /etc/selinux/config state).
//   - is_drift_from_disk=1 flags rows where /proc/cmdline differs
//     from /etc/default/grub — either a missing update-grub re-run
//     or a manually-edited boot.
package kernelcmdline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxParams bounds per-scan output. A typical /proc/cmdline has 8-20
// tokens; the 256 ceiling covers heavyweight kernels (Oracle UEK with
// every tunable explicitly set).
const MaxParams = 256

// Source identifies which file produced the row. Pinned to the
// host_kernel_cmdline.source CHECK enum.
type Source string

const (
	SourceProcCmdline Source = "proc-cmdline"
	SourceGrubDefault Source = "grub-default"
	SourceUnknown     Source = "unknown"
)

// FindingCategory classifies why a parameter is flagged. Pinned to
// the host_kernel_cmdline.finding_category CHECK enum.
type FindingCategory string

const (
	FindingKASLRDisabled         FindingCategory = "kaslr-disabled"
	FindingCPUMitigationDisabled FindingCategory = "cpu-mitigation-disabled"
	FindingMACDisabled           FindingCategory = "mac-disabled"
	FindingAuditDisabled         FindingCategory = "audit-disabled"
	FindingModuleSigningOff      FindingCategory = "module-signing-off"
	FindingInitOverride          FindingCategory = "init-override"
	FindingLSMDisabled           FindingCategory = "lsm-disabled"
	FindingUnknown               FindingCategory = "unknown"
)

// Param is the parsed record produced per cmdline token. Mirrors
// host_kernel_cmdline's column shape exactly.
type Param struct {
	Source              Source          `json:"source"`
	Key                 string          `json:"key"`
	Value               string          `json:"value"`
	FindingCategory     FindingCategory `json:"finding_category,omitempty"`
	FilePath            string          `json:"file_path,omitempty"`
	FileHash            string          `json:"file_hash,omitempty"`
	RawLine             string          `json:"raw_line,omitempty"`
	LineNo              int             `json:"line_no"`
	HasValue            bool            `json:"has_value"`
	IsSecurityCritical  bool            `json:"is_security_critical"`
	IsBaselineViolation bool            `json:"is_baseline_violation"`
	IsDriftFromDisk     bool            `json:"is_drift_from_disk"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Param, error)
}

// HashContents returns the SHA-256 hex of a config file. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ClassifyParameter returns the finding category + whether the parameter
// represents a baseline violation, or ("", false, false) when the key
// isn't in the curated security list.
//
// The classification rules deliberately err on the side of flagging:
// any token whose presence weakens kernel hardening is reported, even
// when the operator may have explicit (legitimate) reasons. The audit
// pipeline decides allow/deny.
func ClassifyParameter(key, value string) (FindingCategory, bool, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.ToLower(strings.TrimSpace(value))
	switch k {
	// KASLR
	case "nokaslr":
		return FindingKASLRDisabled, true, true
	case "kaslr":
		// `kaslr` is the default-enabled form; not a finding.
		return "", true, false
	// CPU mitigation off-switches
	case "mitigations":
		if v == "off" {
			return FindingCPUMitigationDisabled, true, true
		}
		return "", true, false
	case "nopti", "pti":
		if k == "nopti" {
			return FindingCPUMitigationDisabled, true, true
		}
		return "", true, false
	case "nospectre_v1", "nospectre_v2", "nospec",
		"noibrs", "noibpb", "no_stf_barrier",
		"nospec_store_bypass_disable":
		return FindingCPUMitigationDisabled, true, true
	case "spectre_v2":
		if v == "off" {
			return FindingCPUMitigationDisabled, true, true
		}
		return "", true, false
	case "l1tf", "mds", "tsx_async_abort", "srbds", "mmio_stale_data":
		if v == "off" || v == "full,nosmt" {
			return FindingCPUMitigationDisabled, true, true
		}
		return "", true, false
	// MAC disablement at boot
	case "selinux":
		if v == "0" {
			return FindingMACDisabled, true, true
		}
		return "", true, false
	case "enforcing":
		if v == "0" {
			return FindingMACDisabled, true, true
		}
		return "", true, false
	case "apparmor":
		if v == "0" {
			return FindingMACDisabled, true, true
		}
		return "", true, false
	// LSM list
	case "lsm":
		// Any value at all is "user explicitly set the LSM list" — we
		// surface it for review but only flag when known-critical LSMs
		// are missing (apparmor / yama / lockdown).
		missing := []string{"apparmor", "yama", "lockdown", "capability"}
		set := strings.Split(v, ",")
		seen := make(map[string]bool, len(set))
		for _, s := range set {
			seen[strings.TrimSpace(s)] = true
		}
		for _, want := range missing {
			if !seen[want] {
				return FindingLSMDisabled, true, true
			}
		}
		return "", true, false
	// Audit
	case "audit":
		if v == "0" {
			return FindingAuditDisabled, true, true
		}
		return "", true, false
	// Module signing
	case "module.sig_enforce":
		if v == "0" {
			return FindingModuleSigningOff, true, true
		}
		return "", true, false
	// Init override
	case "init":
		// Any non-empty value is suspicious — the default init
		// resolution is /sbin/init with no explicit cmdline arg.
		if v != "" {
			return FindingInitOverride, true, true
		}
		return "", true, false
	}
	return "", false, false
}

// AnnotateSecurity sets the indexed booleans on a param row from its
// already-populated key/value pair.
func AnnotateSecurity(p *Param) {
	cat, critical, violation := ClassifyParameter(p.Key, p.Value)
	p.IsSecurityCritical = critical
	p.IsBaselineViolation = violation
	p.FindingCategory = cat
}

// SortParams returns a deterministic ordering: source, then key, then value.
func SortParams(ps []Param) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Source != ps[j].Source {
			return ps[i].Source < ps[j].Source
		}
		if ps[i].Key != ps[j].Key {
			return ps[i].Key < ps[j].Key
		}
		return ps[i].Value < ps[j].Value
	})
}
