// Package windowsstorage inventories Windows physical disks +
// logical volumes (plus BitLocker protection status) via a
// PowerShell shim. Fifth table-set of the MID Server-aligned
// Windows track.
//
// Returns an Inventory bundle (Disks + Volumes) from a single
// PowerShell round-trip. The PowerShell side joins Win32_DiskDrive
// against MSFT_Disk (bus type, health) and Win32_LogicalDisk
// against Win32_Volume + Get-BitLockerVolume so each row arrives
// flat to the Go decoder.
//
// MITRE T1082 (System Information Discovery — defender side) +
// CWE-311 (Cleartext Storage) + T1052.001 (Exfil over USB) all
// surface from the indexed booleans.
package windowsstorage

import (
	"context"
	"sort"
	"strings"
)

// Source identifies which probe produced the rows. Pinned to the
// host_windows_disks.source + host_windows_volumes.source CHECK enums.
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// Win32_LogicalDisk.DriveType enum values, exposed as named consts
// because every audit query uses them.
const (
	DriveTypeUnknown   = 0
	DriveTypeNoRoot    = 1
	DriveTypeRemovable = 2
	DriveTypeLocal     = 3 // fixed local drive
	DriveTypeNetwork   = 4
	DriveTypeCDROM     = 5
	DriveTypeRAMDisk   = 6
)

// Disk mirrors host_windows_disks' column shape.
type Disk struct {
	OperationalStatus string `json:"operational_status,omitempty"`
	BusType           string `json:"bus_type,omitempty"`
	Model             string `json:"model,omitempty"`
	Manufacturer      string `json:"manufacturer,omitempty"`
	InterfaceType     string `json:"interface_type,omitempty"`
	SerialNumber      string `json:"serial_number,omitempty"`
	FirmwareRevision  string `json:"firmware_revision,omitempty"`
	MediaType         string `json:"media_type,omitempty"`
	DeviceID          string `json:"device_id"`
	Source            Source `json:"source"`
	HealthStatus      string `json:"health_status,omitempty"`
	PartitionCount    int    `json:"partition_count,omitempty"`
	SizeBytes         int64  `json:"size_bytes"`
	IsBoot            bool   `json:"is_boot"`
	IsSystem          bool   `json:"is_system"`
	IsOffline         bool   `json:"is_offline"`
	IsReadOnly        bool   `json:"is_read_only"`
	IsRemovable       bool   `json:"is_removable"`
}

// Volume mirrors host_windows_volumes' column shape.
type Volume struct {
	BitLockerProtectionStatus string `json:"bitlocker_protection_status,omitempty"`
	DeviceID                  string `json:"device_id"`
	DriveLetter               string `json:"drive_letter,omitempty"`
	Label                     string `json:"label,omitempty"`
	FileSystem                string `json:"file_system,omitempty"`
	BitLockerVolumeStatus     string `json:"bitlocker_volume_status,omitempty"`
	BitLockerEncryptionMethod string `json:"bitlocker_encryption_method,omitempty"`
	SerialNumber              string `json:"serial_number,omitempty"`
	Source                    Source `json:"source"`
	DriveType                 int    `json:"drive_type"`
	FreeSpaceBytes            int64  `json:"free_space_bytes"`
	CapacityBytes             int64  `json:"capacity_bytes"`
	IsBootVolume              bool   `json:"is_boot_volume"`
	IsSystemVolume            bool   `json:"is_system_volume"`
	IsCompressed              bool   `json:"is_compressed"`
	IsDirty                   bool   `json:"is_dirty"`
	IsUnencryptedFixedDrive   bool   `json:"is_unencrypted_fixed_drive"`
}

// Inventory bundles both entity slices.
type Inventory struct {
	Disks   []Disk   `json:"disks"`
	Volumes []Volume `json:"volumes"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// IsFixedLocalDrive reports whether a volume sits on a built-in
// hard disk / SSD (DriveType=3). The audit pipeline uses this to
// gate BitLocker-required findings.
func IsFixedLocalDrive(driveType int) bool {
	return driveType == DriveTypeLocal
}

// IsRemovableDrive reports whether a volume is a USB stick / SD card.
func IsRemovableDrive(driveType int) bool {
	return driveType == DriveTypeRemovable
}

// IsNetworkDrive reports whether a volume is a mounted SMB/CIFS share.
func IsNetworkDrive(driveType int) bool {
	return driveType == DriveTypeNetwork
}

// IsBitLockerProtected reports whether a volume has BitLocker active.
// We accept "On" (protection on AND encryption complete) as the only
// passing state — partial encryption, suspended, decrypting all fail.
func IsBitLockerProtected(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "On")
}

// AnnotateVolume sets the derived `IsUnencryptedFixedDrive` flag.
// A fixed local drive without BitLocker fully enabled is the
// canonical CWE-311 finding for laptop fleets.
func AnnotateVolume(v *Volume) {
	if IsFixedLocalDrive(v.DriveType) && !IsBitLockerProtected(v.BitLockerProtectionStatus) {
		v.IsUnencryptedFixedDrive = true
	} else {
		v.IsUnencryptedFixedDrive = false
	}
}

// SortDisks returns a deterministic ordering: device_id.
func SortDisks(ds []Disk) {
	sort.Slice(ds, func(i, j int) bool {
		return ds[i].DeviceID < ds[j].DeviceID
	})
}

// SortVolumes returns a deterministic ordering: drive_letter, device_id.
func SortVolumes(vs []Volume) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].DriveLetter != vs[j].DriveLetter {
			return vs[i].DriveLetter < vs[j].DriveLetter
		}
		return vs[i].DeviceID < vs[j].DeviceID
	})
}

// SortInventory normalises both slices in place.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortDisks(inv.Disks)
	SortVolumes(inv.Volumes)
}
