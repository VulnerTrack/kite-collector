// Package mounts inventories every filesystem mount the kernel is
// aware of, sourced from /etc/fstab (declared) and /proc/self/mountinfo
// (live). macOS draws from the same fstab file plus a (future) mount(8)
// invocation; Windows volume mounts will be addressed in a separate
// iteration.
//
// Filesystem partitioning is a CIS section 1.1 cornerstone:
//
//   - /tmp, /var/tmp, /home, /dev/shm should each be a separate
//     mount with `nodev,nosuid,noexec` (CIS 1.1.2-1.1.21).
//   - /var/log + /var/log/audit each on their own partition keeps a
//     log-flooding attacker from exhausting the system root.
//
// Mount rows feed the audit pipeline:
//
//   - is_critical_path=1 + has_recommended_options=0 = CIS finding.
//   - is_remote=1 flags NFS/CIFS/SSHFS — credential surface in scope.
//   - is_removable=1 flags /media/* + /run/media/* — USB activity.
//   - File hash drift on /etc/fstab + option-set drift between fstab
//     and live = the boot config or the runtime overlay was modified.
//
// Every collector is **read-only by intent** — it parses fstab + /proc,
// never `mount` or `umount` anything. Read-only is enforced by
// guideline 4.2 of the kite-collector project.
package mounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxMounts bounds per-scan output. A typical workstation has 30-80
// live mounts when cgroup v2 + every overlay is counted; the 1024
// ceiling covers heavyweight container hosts.
const MaxMounts = 1024

// Source identifies which file/subsystem produced the row. Pinned to
// the host_mounts.source CHECK enum.
type Source string

const (
	SourceFstab          Source = "fstab"
	SourceProcMounts     Source = "proc-mounts"
	SourceMacOSMount     Source = "macos-mount"
	SourceWindowsVolumes Source = "windows-volumes"
	SourceUnknown        Source = "unknown"
)

// Mount is the parsed record produced per non-comment line. Mirrors
// host_mounts' column shape exactly.
type Mount struct {
	FilePath              string   `json:"file_path,omitempty"`
	Device                string   `json:"device"`
	Mountpoint            string   `json:"mountpoint"`
	FSType                string   `json:"fstype"`
	RawLine               string   `json:"raw_line,omitempty"`
	FileHash              string   `json:"file_hash,omitempty"`
	Source                Source   `json:"source"`
	Options               []string `json:"options"`
	Dump                  int      `json:"dump"`
	FsckPass              int      `json:"fsck_pass"`
	LineNo                int      `json:"line_no"`
	IsCriticalPath        bool     `json:"is_critical_path"`
	HasNosuid             bool     `json:"has_nosuid"`
	HasNoexec             bool     `json:"has_noexec"`
	IsReadOnly            bool     `json:"is_read_only"`
	HasRecommendedOptions bool     `json:"has_recommended_options"`
	HasNodev              bool     `json:"has_nodev"`
	IsEncrypted           bool     `json:"is_encrypted"`
	IsRemovable           bool     `json:"is_removable"`
	IsRemote              bool     `json:"is_remote"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Mount, error)
}

// EncodeStringList returns a JSON array suitable for options_json.
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

// HashContents returns the SHA-256 hex of a fstab body. Drives drift
// detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CIS-derived configuration. CriticalMountpoints are the paths that
// the CIS Distribution-Independent Linux Benchmark v2.0.0 demands be
// separate mounts. RecommendedOptions is the option-set we expect on
// each (mountpoint -> required options).
//
// We treat "missing from this map" as "not security-critical" rather
// than "no requirement", so the absence of an entry never triggers a
// finding.
func CriticalMountOptions() map[string][]string {
	return map[string][]string{
		"/tmp":           {"nodev", "nosuid", "noexec"},
		"/var/tmp":       {"nodev", "nosuid", "noexec"},
		"/home":          {"nodev", "nosuid"},
		"/dev/shm":       {"nodev", "nosuid", "noexec"},
		"/var":           {"nodev"},
		"/var/log":       {"nodev", "nosuid", "noexec"},
		"/var/log/audit": {"nodev", "nosuid", "noexec"},
		"/boot":          {"nodev", "nosuid"},
	}
}

// IsCriticalMountpoint reports whether the path is in the CIS
// sensitive-paths set.
func IsCriticalMountpoint(path string) bool {
	_, ok := CriticalMountOptions()[strings.TrimSpace(path)]
	return ok
}

// MeetsRecommendedOptions reports whether the supplied options set
// covers every recommended option for the mountpoint. Returns
// (false, false) when the mountpoint isn't in the critical set —
// callers should pair the return values via:
//
//	required, ok := MeetsRecommendedOptions(mp, opts)
//	if ok && !required { /* CIS finding */ }
func MeetsRecommendedOptions(mountpoint string, opts []string) (bool, bool) {
	required, ok := CriticalMountOptions()[strings.TrimSpace(mountpoint)]
	if !ok {
		return false, false
	}
	have := make(map[string]bool, len(opts))
	for _, o := range opts {
		have[strings.ToLower(o)] = true
	}
	for _, want := range required {
		if !have[strings.ToLower(want)] {
			return false, true
		}
	}
	return true, true
}

// RemoteFSTypes is the set of filesystem types that traverse the
// network. Hosts with one or more mounted are in cred-surface scope.
func RemoteFSTypes() []string {
	return []string{
		"nfs", "nfs4", "nfs3", "cifs", "smb", "smb3", "smbfs",
		"sshfs", "fuse.sshfs", "glusterfs", "ceph", "9p", "afs",
		"vmhgfs", "vboxsf",
	}
}

// IsRemoteFSType reports whether the fstype traverses the network.
func IsRemoteFSType(fstype string) bool {
	want := strings.ToLower(strings.TrimSpace(fstype))
	for _, f := range RemoteFSTypes() {
		if f == want {
			return true
		}
	}
	return false
}

// EncryptedDeviceMarkers is the set of substrings whose presence in
// the device path indicates the filesystem rests on a LUKS / dm-crypt
// volume.
func EncryptedDeviceMarkers() []string {
	return []string{"/dev/mapper/", "/dev/dm-", "luks-", "crypt-"}
}

// LooksEncryptedDevice reports whether the device path appears to be
// a dm-crypt / LUKS volume. False negatives are possible (e.g. fs-level
// encryption like fscrypt) but the path-shape heuristic catches the
// common case.
func LooksEncryptedDevice(device string) bool {
	d := strings.ToLower(strings.TrimSpace(device))
	for _, m := range EncryptedDeviceMarkers() {
		if strings.Contains(d, m) {
			return true
		}
	}
	return false
}

// RemovableMountRoots is the set of path prefixes the auto-mount
// machinery uses for removable media (USB sticks, CDs, SD cards).
func RemovableMountRoots() []string {
	return []string{"/media/", "/run/media/", "/mnt/usb"}
}

// IsRemovableMountpoint reports whether the mountpoint sits under an
// auto-mount root.
func IsRemovableMountpoint(mountpoint string) bool {
	mp := strings.TrimSpace(mountpoint)
	for _, root := range RemovableMountRoots() {
		if strings.HasPrefix(mp, root) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on a mount row from
// its already-populated fields. Centralised so the flags don't drift
// between sources.
func AnnotateSecurity(m *Mount) {
	have := make(map[string]bool, len(m.Options))
	for _, o := range m.Options {
		have[strings.ToLower(o)] = true
	}
	m.HasNodev = have["nodev"]
	m.HasNosuid = have["nosuid"]
	m.HasNoexec = have["noexec"]
	m.IsReadOnly = have["ro"]
	m.IsRemote = IsRemoteFSType(m.FSType)
	m.IsRemovable = IsRemovableMountpoint(m.Mountpoint)
	m.IsEncrypted = LooksEncryptedDevice(m.Device)
	m.IsCriticalPath = IsCriticalMountpoint(m.Mountpoint)
	if m.IsCriticalPath {
		met, _ := MeetsRecommendedOptions(m.Mountpoint, m.Options)
		m.HasRecommendedOptions = met
	}
}

// SortMounts returns a deterministic ordering: source, then mountpoint.
func SortMounts(ms []Mount) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Source != ms[j].Source {
			return ms[i].Source < ms[j].Source
		}
		return ms[i].Mountpoint < ms[j].Mountpoint
	})
}
