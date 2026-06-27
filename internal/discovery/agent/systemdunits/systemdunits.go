// Package systemdunits inventories systemd unit files from the
// standard search directories and extracts the hardening directives
// the audit pipeline alerts on.
//
// systemd ships a deep defense-in-depth toolkit — NoNewPrivileges,
// PrivateTmp, ProtectSystem, SystemCallFilter, CapabilityBoundingSet,
// RestrictAddressFamilies, RestrictNamespaces — but the burden of
// turning each one on falls on the unit author. Long-tail vendor
// units that predate systemd 232 (mid-2016) typically opt into none
// of them and run as root with full capabilities.
//
// Finding shape map:
//
//   - User= unset or =root + service unit = runs as root (CWE-269).
//   - NoNewPrivileges= unset or =false = setuid binaries inside the
//     service regain dropped privileges (CWE-269 + T1068).
//   - ProtectSystem= unset or =false = the service can rewrite
//     /usr and /boot — textbook implant path (CWE-732 + T1543.002).
//   - SystemCallFilter= unset = arbitrary syscalls reachable (CWE-749).
//   - CapabilityBoundingSet= unset = CAP_SYS_ADMIN etc all available
//     (CWE-269); a buggy ioctl handler ≈ root.
//
// Read-only by intent — we parse unit files only, never invoke
// systemctl. (Project guideline 4.2.)
package systemdunits

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxUnits bounds per-scan output. A loaded Linux box carries
// 200-600 active units; the 4096 ceiling covers heavily-customised
// container hosts without bloating SQLite writes.
const MaxUnits = 4096

// UnitKind tags the systemd object type. Pinned to the
// host_systemd_units.unit_kind CHECK enum.
type UnitKind string

const (
	KindService UnitKind = "service"
	KindSocket  UnitKind = "socket"
	KindTimer   UnitKind = "timer"
	KindMount   UnitKind = "mount"
	KindPath    UnitKind = "path"
	KindTarget  UnitKind = "target"
	KindUnknown UnitKind = "unknown"
)

// SourceDir tags the search directory the unit was found under.
// Pinned to the host_systemd_units.source_dir CHECK enum.
type SourceDir string

const (
	SourceEtc     SourceDir = "etc"    // /etc/systemd/system — sysadmin overrides
	SourceLib     SourceDir = "lib"    // /lib/systemd/system — package-managed
	SourceUsrLib  SourceDir = "usrlib" // /usr/lib/systemd/system — package-managed
	SourceRun     SourceDir = "run"    // /run/systemd/system — transient
	SourceUnknown SourceDir = "unknown"
)

// Unit mirrors host_systemd_units' column shape exactly. Hardening
// fields are stored as the raw directive value (or "" when unset) so
// the audit pipeline can distinguish "off" from "absent".
type Unit struct {
	FilePath                    string    `json:"file_path"`
	FileHash                    string    `json:"file_hash"`
	UnitName                    string    `json:"unit_name"`
	UnitKind                    UnitKind  `json:"unit_kind"`
	SourceDir                   SourceDir `json:"source_dir"`
	Description                 string    `json:"description,omitempty"`
	ServiceType                 string    `json:"service_type,omitempty"`
	ExecStart                   string    `json:"exec_start,omitempty"`
	UserName                    string    `json:"user_name,omitempty"`
	GroupName                   string    `json:"group_name,omitempty"`
	WorkingDirectory            string    `json:"working_directory,omitempty"`
	CapabilityBoundingSet       string    `json:"capability_bounding_set,omitempty"`
	AmbientCapabilities         string    `json:"ambient_capabilities,omitempty"`
	SystemCallFilter            string    `json:"system_call_filter,omitempty"`
	RestrictAddressFamilies     string    `json:"restrict_address_families,omitempty"`
	NoNewPrivileges             string    `json:"no_new_privileges,omitempty"`
	PrivateTmp                  string    `json:"private_tmp,omitempty"`
	PrivateDevices              string    `json:"private_devices,omitempty"`
	PrivateNetwork              string    `json:"private_network,omitempty"`
	ProtectSystem               string    `json:"protect_system,omitempty"`
	ProtectHome                 string    `json:"protect_home,omitempty"`
	ProtectKernelTunables       string    `json:"protect_kernel_tunables,omitempty"`
	ProtectKernelModules        string    `json:"protect_kernel_modules,omitempty"`
	ProtectControlGroups        string    `json:"protect_control_groups,omitempty"`
	RestrictNamespaces          string    `json:"restrict_namespaces,omitempty"`
	LockPersonality             string    `json:"lock_personality,omitempty"`
	MemoryDenyWriteExecute      string    `json:"memory_deny_write_execute,omitempty"`
	RunsAsRoot                  bool      `json:"runs_as_root"`
	IsNoNewPrivilegesOff        bool      `json:"is_no_new_privileges_off"`
	IsPrivateTmpOff             bool      `json:"is_private_tmp_off"`
	IsWritableSystem            bool      `json:"is_writable_system"`
	IsWritableHome              bool      `json:"is_writable_home"`
	HasNoSeccompFilter          bool      `json:"has_no_seccomp_filter"`
	HasUnrestrictedCapabilities bool      `json:"has_unrestricted_capabilities"`
	HasDangerousAmbientCaps     bool      `json:"has_dangerous_ambient_caps"`
	IsHardenedBaseline          bool      `json:"is_hardened_baseline"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Unit, error)
}

// HashContents returns the SHA-256 hex of a unit-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeUnitKind maps a unit-file extension to our enum.
func NormalizeUnitKind(name string) UnitKind {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".service":
		return KindService
	case ".socket":
		return KindSocket
	case ".timer":
		return KindTimer
	case ".mount":
		return KindMount
	case ".path":
		return KindPath
	case ".target":
		return KindTarget
	}
	return KindUnknown
}

// NormalizeSourceDir maps a unit's parent directory to our enum.
func NormalizeSourceDir(dir string) SourceDir {
	d := filepath.Clean(dir)
	switch {
	case strings.HasPrefix(d, "/etc/systemd/"):
		return SourceEtc
	case strings.HasPrefix(d, "/usr/lib/systemd/"):
		return SourceUsrLib
	case strings.HasPrefix(d, "/lib/systemd/"):
		return SourceLib
	case strings.HasPrefix(d, "/run/systemd/"):
		return SourceRun
	}
	return SourceUnknown
}

// IsBoolFalse reports whether a directive value reads as
// systemd's "false" — "no" / "false" / "off" / "0" / "" (unset).
func IsBoolFalse(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no", "false", "off", "0", "":
		return true
	}
	return false
}

// IsBoolTrue is the inverse — only the canonical "yes" variants.
func IsBoolTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// IsRootUser reports whether a User= value resolves to local root —
// either `root`, uid `0`, or unset (the systemd default).
func IsRootUser(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	return t == "" || t == "root" || t == "0"
}

// ProtectSystemIsWritable reports whether the ProtectSystem value
// leaves /usr and /boot writable. systemd accepts:
//
//	"" / "false" / "no" / "off" / "0" → writable
//	"true" / "yes" → /usr and /boot read-only
//	"full" → also /etc read-only
//	"strict" → entire filesystem read-only except /dev /proc /sys
func ProtectSystemIsWritable(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "", "false", "no", "off", "0":
		return true
	}
	return false
}

// ProtectHomeIsWritable mirrors ProtectSystemIsWritable for /home.
func ProtectHomeIsWritable(s string) bool {
	return ProtectSystemIsWritable(s)
}

// DangerousAmbientCaps is the curated set of ambient capabilities
// that grant root-equivalent power. systemd's AmbientCapabilities=
// directive grants them to every child process unconditionally.
func DangerousAmbientCaps() []string {
	return []string{
		"cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
		"cap_sys_rawio", "cap_dac_override", "cap_dac_read_search",
		"cap_setuid", "cap_setgid",
	}
}

// HasDangerousAmbientCaps reports whether AmbientCapabilities=
// grants any of the curated dangerous capabilities. Empty input is
// safe by definition.
func HasDangerousAmbientCaps(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	lower := strings.ToLower(s)
	for _, c := range DangerousAmbientCaps() {
		if strings.Contains(lower, c) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Unit that has its
// raw fields populated. Only `service` units get the full set —
// `target`/`socket`/`timer` don't carry meaningful hardening of
// their own.
func AnnotateSecurity(u *Unit) {
	if u.UnitKind != KindService {
		return
	}
	u.RunsAsRoot = IsRootUser(u.UserName)
	u.IsNoNewPrivilegesOff = !IsBoolTrue(u.NoNewPrivileges)
	u.IsPrivateTmpOff = !IsBoolTrue(u.PrivateTmp)
	u.IsWritableSystem = ProtectSystemIsWritable(u.ProtectSystem)
	u.IsWritableHome = ProtectHomeIsWritable(u.ProtectHome)
	u.HasNoSeccompFilter = strings.TrimSpace(u.SystemCallFilter) == ""
	u.HasUnrestrictedCapabilities = strings.TrimSpace(u.CapabilityBoundingSet) == ""
	u.HasDangerousAmbientCaps = HasDangerousAmbientCaps(u.AmbientCapabilities)
	u.IsHardenedBaseline = IsBoolTrue(u.NoNewPrivileges) &&
		IsBoolTrue(u.PrivateTmp) &&
		!u.IsWritableSystem &&
		!u.HasNoSeccompFilter
}

// SortUnits returns a deterministic ordering by file path.
func SortUnits(us []Unit) {
	sort.Slice(us, func(i, j int) bool {
		return us[i].FilePath < us[j].FilePath
	})
}
