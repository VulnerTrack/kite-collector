// Package windowsbitlocker inventories the Windows BitLocker
// volume-encryption posture via a PowerShell shim — Get-BitLockerVolume
// for the per-volume rows.
//
// One row per managed volume. Volumes BitLocker cannot manage
// (network shares, some ReFS configurations) don't appear in the
// output; the audit pipeline pairs this table with host_volumes to
// catch "should be encrypted but isn't enumerated" cases.
//
// MITRE T1486 (Data Encrypted for Impact) — defender side. The
// audit pipeline alerts on `is_system_drive_unencrypted=1` and on
// `is_weak_cipher=1` / `has_no_recovery_protector=1` regressions.
package windowsbitlocker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxVolumes bounds per-scan output. A laptop has 1-3 volumes; a
// workstation 3-12. The 256 ceiling covers heavy-tier multi-disk
// servers without bloating SQLite writes.
const MaxVolumes = 256

// Source identifies which probe path produced the row. Pinned to the
// host_bitlocker_volumes.source CHECK enum.
type Source string

const (
	SourcePowerShellBitLocker Source = "powershell-bitlocker"
	SourceNoProbe             Source = "no-probe"
	SourceUnknown             Source = "unknown"
)

// Volume mirrors host_bitlocker_volumes' column shape exactly.
type Volume struct {
	MountPoint               string   `json:"mount_point"`
	VolumeType               string   `json:"volume_type,omitempty"`
	ProtectionStatus         string   `json:"protection_status,omitempty"`
	LockStatus               string   `json:"lock_status,omitempty"`
	VolumeStatus             string   `json:"volume_status,omitempty"`
	EncryptionMethod         string   `json:"encryption_method,omitempty"`
	Source                   Source   `json:"source"`
	KeyProtectors            []string `json:"key_protectors,omitempty"`
	EncryptionPercentage     int      `json:"encryption_percentage,omitempty"`
	IsProtectionOff          bool     `json:"is_protection_off"`
	AutoUnlockEnabled        bool     `json:"auto_unlock_enabled"`
	IsFullyEncrypted         bool     `json:"is_fully_encrypted"`
	IsSystemDrive            bool     `json:"is_system_drive"`
	IsSystemDriveUnencrypted bool     `json:"is_system_drive_unencrypted"`
	IsRemovableUnencrypted   bool     `json:"is_removable_unencrypted"`
	IsWeakCipher             bool     `json:"is_weak_cipher"`
	HasTPMProtector          bool     `json:"has_tpm_protector"`
	HasRecoveryProtector     bool     `json:"has_recovery_protector"`
	HasNoTPMProtector        bool     `json:"has_no_tpm_protector"`
	HasNoRecoveryProtector   bool     `json:"has_no_recovery_protector"`
	IsHardened               bool     `json:"is_hardened"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty slice.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Volume, error)
}

// HashContents returns the sha256 hex of any payload — handy for
// callers that want to drive drift detection on the raw shim output.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WeakEncryptionMethods is the curated set of cipher names we
// consider "weak" relative to the modern XtsAes256 default. The
// "None" case is treated separately via IsProtectionOff.
func WeakEncryptionMethods() []string {
	return []string{"aes128", "aes128_diffuser", "xtsaes128"}
}

// IsWeakCipher reports whether an EncryptionMethod string belongs to
// the weak set. Case-insensitive.
func IsWeakCipher(method string) bool {
	m := strings.ToLower(strings.TrimSpace(method))
	for _, w := range WeakEncryptionMethods() {
		if m == w {
			return true
		}
	}
	return false
}

// IsProtectionOff reports whether ProtectionStatus reads as "Off" or
// is absent. "Unknown" also flags — it usually means BitLocker
// couldn't query the volume at all.
func IsProtectionOff(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s != "on"
}

// IsFullyEncryptedStatus reports whether VolumeStatus indicates the
// disk is end-to-end encrypted (vs. mid-conversion or decrypted).
func IsFullyEncryptedStatus(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "FullyEncrypted")
}

// IsSystemVolumeType reports whether VolumeType identifies the OS
// drive. Get-BitLockerVolume returns "OperatingSystem" for C:.
func IsSystemVolumeType(vt string) bool {
	return strings.EqualFold(strings.TrimSpace(vt), "OperatingSystem")
}

// IsRemovableVolumeType reports whether VolumeType identifies a
// removable / USB drive (BitLocker To Go scope).
func IsRemovableVolumeType(vt string) bool {
	return strings.EqualFold(strings.TrimSpace(vt), "Removable")
}

// HasProtectorKind reports whether a key-protector list contains a
// given kind (case-insensitive).
func HasProtectorKind(list []string, kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	for _, p := range list {
		if strings.ToLower(strings.TrimSpace(p)) == k {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Volume that has
// its raw fields populated.
func AnnotateSecurity(v *Volume) {
	v.IsProtectionOff = IsProtectionOff(v.ProtectionStatus)
	v.IsFullyEncrypted = IsFullyEncryptedStatus(v.VolumeStatus)
	v.IsSystemDrive = IsSystemVolumeType(v.VolumeType)
	v.IsWeakCipher = !v.IsProtectionOff && IsWeakCipher(v.EncryptionMethod)
	v.IsSystemDriveUnencrypted = v.IsSystemDrive && v.IsProtectionOff
	v.IsRemovableUnencrypted = IsRemovableVolumeType(v.VolumeType) && v.IsProtectionOff
	v.HasTPMProtector = HasProtectorKind(v.KeyProtectors, "Tpm") ||
		HasProtectorKind(v.KeyProtectors, "TpmPin") ||
		HasProtectorKind(v.KeyProtectors, "TpmPinStartupKey") ||
		HasProtectorKind(v.KeyProtectors, "TpmStartupKey")
	v.HasRecoveryProtector = HasProtectorKind(v.KeyProtectors, "RecoveryPassword") ||
		HasProtectorKind(v.KeyProtectors, "RecoveryKey")
	v.HasNoTPMProtector = !v.IsProtectionOff && v.IsSystemDrive && !v.HasTPMProtector
	v.HasNoRecoveryProtector = !v.IsProtectionOff && !v.HasRecoveryProtector
	v.IsHardened = !v.IsProtectionOff && v.IsFullyEncrypted &&
		!v.IsWeakCipher && !v.HasNoRecoveryProtector &&
		(!v.IsSystemDrive || v.HasTPMProtector)
}

// SortVolumes returns a deterministic ordering by mount point.
func SortVolumes(vs []Volume) {
	sort.Slice(vs, func(i, j int) bool {
		return vs[i].MountPoint < vs[j].MountPoint
	})
}

// SortKeyProtectors normalises the protector list on each volume —
// gives the audit pipeline stable diffs between scans.
func SortKeyProtectors(v *Volume) {
	sort.Strings(v.KeyProtectors)
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
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
