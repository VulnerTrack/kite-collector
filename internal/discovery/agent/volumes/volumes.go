// Package volumes enumerates mounted filesystems and disk volumes across
// Linux, macOS, Windows, and the BSDs. Capacity metadata comes from
// gopsutil/v4/disk (single cross-platform code path); encryption posture
// requires per-OS probes (LUKS via /proc/crypto on Linux, BitLocker via
// WMI on Windows, FileVault via fdesetup on macOS) and lives in
// build-tagged files: encryption_linux.go, encryption_windows.go,
// encryption_darwin.go.
//
// Every collector is **read-only** — it queries mount tables and metadata,
// never mounts, unmounts, formats, or modifies any volume. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Volume rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-311 (Missing Encryption of Sensitive Data) — bootable=1 +
//     encryption=none on a portable device is a finding.
//   - CWE-312 (Cleartext Storage of Sensitive Information) — unencrypted
//     /home or /var/lib volume on a multi-user host.
//   - CWE-732 (Incorrect Permission Assignment) — read_only=0 on a volume
//     that should be ro (e.g. /boot/efi on a hardened system).
package volumes

import (
	"context"
	"sort"
	"strings"
	"time"
)

// MaxVolumes bounds per-scan output. A typical host has 5-15 mounts; a
// container host or storage server might have hundreds. The 1024 ceiling
// protects the SQLite write path from pathological mount-bombs.
const MaxVolumes = 1024

// Encryption classifies a volume's at-rest encryption scheme. Strings are
// pinned to the host_volumes.encryption CHECK enum.
type Encryption string

const (
	EncNone          Encryption = "none"
	EncLUKS          Encryption = "luks"
	EncLUKS2         Encryption = "luks2"
	EncBitLocker     Encryption = "bitlocker"
	EncFileVault2    Encryption = "filevault2"
	EncAPFSEncrypted Encryption = "apfs-encrypted"
	EncUnknown       Encryption = "unknown"
)

// EncryptionState describes whether an encrypted volume is currently
// readable. Strings are pinned to the host_volumes.encryption_state CHECK
// enum.
type EncryptionState string

const (
	EncStateLocked   EncryptionState = "locked"
	EncStateUnlocked EncryptionState = "unlocked"
	EncStateUnknown  EncryptionState = "unknown"
)

// Volume is the cross-platform record produced by every collector. It
// mirrors the column shape of host_volumes so the store layer can persist
// rows without a translation step.
type Volume struct {
	LastSeenAt      time.Time       `json:"last_seen_at"`
	CollectedAt     time.Time       `json:"collected_at"`
	MountPoint      string          `json:"mount_point"`
	Device          string          `json:"device,omitempty"`
	Filesystem      string          `json:"filesystem,omitempty"`
	Label           string          `json:"label,omitempty"`
	FSUUID          string          `json:"fs_uuid,omitempty"`
	MountOpts       string          `json:"mount_opts,omitempty"`
	Encryption      Encryption      `json:"encryption"`
	EncryptionState EncryptionState `json:"encryption_state"`
	SizeBytes       uint64          `json:"size_bytes,omitempty"`
	UsedBytes       uint64          `json:"used_bytes,omitempty"`
	InodesTotal     uint64          `json:"inodes_total,omitempty"`
	InodesUsed      uint64          `json:"inodes_used,omitempty"`
	ReadOnly        bool            `json:"read_only"`
	Removable       bool            `json:"removable"`
	Bootable        bool            `json:"bootable"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry.
	Name() string
	// Collect enumerates mounted volumes. Read-only: never mounts,
	// unmounts, formats, or modifies any volume. Partial results are
	// returned alongside the error when meaningful.
	Collect(ctx context.Context) ([]Volume, error)
}

// EncryptionProbe is the per-OS hook for detecting at-rest encryption.
// Implementations live in build-tagged files. The default (no-op) probe
// is used when no per-OS implementation is registered for the build.
type EncryptionProbe interface {
	// Probe returns the encryption scheme and state for the given
	// (mountPoint, device) pair. It must not error for "I don't know" —
	// it returns EncUnknown / EncStateUnknown instead.
	Probe(ctx context.Context, mountPoint, device, filesystem string) (Encryption, EncryptionState)
}

// noopProbe is the default EncryptionProbe returned when no per-OS file
// registers a real one (e.g. on FreeBSD/OpenBSD). Marks every volume as
// EncUnknown so downstream queries can treat "we didn't look" distinctly
// from "we looked and found nothing".
type noopProbe struct{}

func (noopProbe) Probe(_ context.Context, _, _, _ string) (Encryption, EncryptionState) {
	return EncUnknown, EncStateUnknown
}

// IsRemovableMount applies a heuristic to a mount path to decide whether
// the volume is on removable media. Used as a fallback when the OS-native
// probe doesn't expose `removable` (e.g. Linux without /sys/block walks).
//
// True for: /media/*, /run/media/*, /Volumes/* (when not the root volume),
// drive letters > C: on Windows (D:, E:, ... typically removable).
func IsRemovableMount(mountPoint string) bool {
	mp := strings.TrimRight(mountPoint, "/")
	switch {
	case strings.HasPrefix(mp, "/media/"),
		strings.HasPrefix(mp, "/run/media/"),
		strings.HasPrefix(mp, "/mnt/usb"):
		return true
	case strings.HasPrefix(mp, "/Volumes/") && mp != "/Volumes/Macintosh HD":
		// On macOS / is the boot volume; /Volumes/Foo is typically external.
		return true
	case len(mp) >= 2 && mp[1] == ':' && len(mp) <= 3:
		// Windows drive letter root: A:, B:, D:, ... (but not C:)
		letter := mp[0]
		if letter >= 'D' && letter <= 'Z' {
			return true
		}
	}
	return false
}

// IsBootable reports whether the mount point looks like the OS boot volume.
// Conservative — false-negative is preferred over false-positive (a
// non-boot volume flagged bootable would skew the CWE-311 query).
func IsBootable(mountPoint, filesystem string) bool {
	mp := strings.TrimRight(mountPoint, "/")
	switch mp {
	case "", "/":
		// Unix root.
		return true
	case "/boot", "/boot/efi":
		return true
	case `C:`, `C:\`:
		return true
	}
	if strings.HasPrefix(mp, "/System/Volumes/Data") {
		return true // macOS APFS root since 10.15
	}
	_ = filesystem // reserved for future fs-specific heuristics (e.g. apfs role probing)
	return false
}

// SortVolumes returns a deterministic ordering: by mount point lexically.
func SortVolumes(vs []Volume) {
	sort.Slice(vs, func(i, j int) bool { return vs[i].MountPoint < vs[j].MountPoint })
}
