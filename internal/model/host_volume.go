package model

import (
	"time"

	"github.com/google/uuid"
)

// HostVolume is one mounted filesystem observed on a machine, mirroring the
// host_volumes table. It carries both inventory (device, filesystem, mount
// options, encryption posture) and the capacity metrics sampled at collection
// time (SizeBytes / UsedBytes / inodes), so a single row answers "how big is
// it, how full is it, and is it encrypted".
//
// Capacity fields are best-effort: a mount the agent cannot stat (permission
// denied on some macOS system volumes, a wedged network mount) still yields a
// row with the inventory fields set and the metrics left at zero, which reads
// as "unknown" rather than "empty disk".
type HostVolume struct {
	LastSeenAt      time.Time
	CollectedAt     time.Time
	ID              uuid.UUID
	MachineID       uuid.UUID
	MountPoint      string
	Device          string
	Filesystem      string
	Label           string
	FSUUID          string
	MountOpts       string
	Encryption      string // none | luks | luks2 | bitlocker | filevault2 | apfs-encrypted | unknown
	EncryptionState string // locked | unlocked | unknown
	SizeBytes       uint64
	UsedBytes       uint64
	InodesTotal     uint64
	InodesUsed      uint64
	ReadOnly        bool
	Removable       bool
	Bootable        bool
}

// UsedPercent returns how full the volume is, 0-100. It returns 0 when the
// size is unknown (an unstattable mount), so callers must treat a zero size as
// "no measurement" rather than "empty".
func (v HostVolume) UsedPercent() float64 {
	if v.SizeBytes == 0 {
		return 0
	}
	return float64(v.UsedBytes) / float64(v.SizeBytes) * 100
}

// FreeBytes returns the unused capacity, clamped at zero. Used can exceed the
// non-root-reserved total on some filesystems, which would otherwise underflow
// the unsigned subtraction into a nonsensical exabyte figure.
func (v HostVolume) FreeBytes() uint64 {
	if v.UsedBytes >= v.SizeBytes {
		return 0
	}
	return v.SizeBytes - v.UsedBytes
}
