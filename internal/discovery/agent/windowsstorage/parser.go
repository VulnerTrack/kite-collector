package windowsstorage

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PowerShellScript captures disks + volumes + BitLocker in one
// round-trip. Server-side joins:
//   - Win32_DiskDrive left-joined with MSFT_Disk by SerialNumber when
//     both are available. MSFT_Disk lives in the Storage module which
//     is shipped with Windows 8+/Server 2012+; older hosts skip the
//     MSFT_Disk side and just get the Win32_DiskDrive fields.
//   - Win32_LogicalDisk left-joined with Win32_Volume by DeviceID
//     (drive letter) and with Get-BitLockerVolume by MountPoint.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$drives  = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue)
$msftBy  = @{}
try {
    $msft = @(Get-CimInstance -Namespace 'Root\Microsoft\Windows\Storage' -ClassName MSFT_Disk -ErrorAction SilentlyContinue)
    foreach ($d in $msft) {
        if ($d.SerialNumber) { $msftBy[[string]$d.SerialNumber.Trim()] = $d }
    }
} catch {}

$logical = @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue)
$vols    = @(Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue)
$volByID = @{}
foreach ($v in $vols) {
    if ($v.DriveLetter) { $volByID[[string]$v.DriveLetter] = $v }
}

$blBy = @{}
try {
    $bl = @(Get-BitLockerVolume -ErrorAction SilentlyContinue)
    foreach ($b in $bl) {
        if ($b.MountPoint) { $blBy[[string]$b.MountPoint] = $b }
    }
} catch {}

function BusTypeName($n) {
    switch ($n) {
        0  { 'Unknown' }
        1  { 'SCSI' }
        2  { 'ATAPI' }
        3  { 'ATA' }
        4  { '1394' }
        5  { 'SSA' }
        6  { 'FibreChannel' }
        7  { 'USB' }
        8  { 'RAID' }
        9  { 'iSCSI' }
        10 { 'SAS' }
        11 { 'SATA' }
        12 { 'SD' }
        13 { 'MMC' }
        14 { 'MAX' }
        15 { 'FileBackedVirtual' }
        16 { 'StorageSpaces' }
        17 { 'NVMe' }
        default { [string]$n }
    }
}

function HealthName($n) {
    switch ($n) {
        0 { 'Healthy' }
        1 { 'Warning' }
        2 { 'Unhealthy' }
        default { [string]$n }
    }
}

function OpStatusName($a) {
    if ($null -eq $a -or $a.Count -eq 0) { return $null }
    switch ($a[0]) {
        1 { 'Other' }
        2 { 'Unknown' }
        3 { 'Online' }
        4 { 'NotReady' }
        5 { 'NoMedia' }
        6 { 'Offline' }
        7 { 'Failed' }
        default { [string]$a[0] }
    }
}

$diskRows = @($drives | ForEach-Object {
    $msftMatch = $null
    if ($_.SerialNumber) {
        $key = [string]$_.SerialNumber.Trim()
        if ($msftBy.ContainsKey($key)) { $msftMatch = $msftBy[$key] }
    }
    [pscustomobject]@{
        device_id          = [string]$_.DeviceID
        model              = [string]$_.Model
        manufacturer       = [string]$_.Manufacturer
        interface_type     = [string]$_.InterfaceType
        serial_number      = if ($_.SerialNumber) { [string]$_.SerialNumber.Trim() } else { $null }
        firmware_revision  = [string]$_.FirmwareRevision
        media_type         = [string]$_.MediaType
        size_bytes         = if ($_.Size -ne $null) { [int64]$_.Size } else { 0 }
        partition_count    = if ($_.Partitions -ne $null) { [int]$_.Partitions } else { 0 }
        bus_type           = if ($msftMatch) { BusTypeName($msftMatch.BusType) } else { $null }
        health_status      = if ($msftMatch) { HealthName($msftMatch.HealthStatus) } else { $null }
        operational_status = if ($msftMatch) { OpStatusName($msftMatch.OperationalStatus) } else { $null }
        is_boot            = if ($msftMatch) { [bool]$msftMatch.IsBoot } else { $false }
        is_system          = if ($msftMatch) { [bool]$msftMatch.IsSystem } else { $false }
        is_offline         = if ($msftMatch) { [bool]$msftMatch.IsOffline } else { $false }
        is_read_only       = if ($msftMatch) { [bool]$msftMatch.IsReadOnly } else { $false }
        is_removable       = ([string]$_.MediaType -like '*Removable*')
    }
})

$volRows = @($logical | ForEach-Object {
    $vol = $null
    if ($_.DeviceID -and $volByID.ContainsKey([string]$_.DeviceID)) { $vol = $volByID[[string]$_.DeviceID] }
    $blVol = $null
    if ($_.DeviceID -and $blBy.ContainsKey([string]$_.DeviceID)) { $blVol = $blBy[[string]$_.DeviceID] }
    [pscustomobject]@{
        device_id                     = [string]$_.DeviceID
        drive_letter                  = [string]$_.DeviceID
        label                         = if ($vol) { [string]$vol.Label } else { [string]$_.VolumeName }
        file_system                   = [string]$_.FileSystem
        capacity_bytes                = if ($_.Size -ne $null) { [int64]$_.Size } else { 0 }
        free_space_bytes              = if ($_.FreeSpace -ne $null) { [int64]$_.FreeSpace } else { 0 }
        serial_number                 = if ($vol -and $vol.SerialNumber -ne $null) { [string]$vol.SerialNumber } else { [string]$_.VolumeSerialNumber }
        drive_type                    = if ($_.DriveType -ne $null) { [int]$_.DriveType } else { 0 }
        is_dirty                      = if ($vol) { [bool]$vol.DirtyBitSet } else { $false }
        is_boot_volume                = if ($vol) { [bool]$vol.BootVolume } else { $false }
        is_system_volume              = if ($vol) { [bool]$vol.SystemVolume } else { $false }
        is_compressed                 = if ($vol -ne $null -and $vol.Compressed -ne $null) { [bool]$vol.Compressed } elseif ($_.Compressed -ne $null) { [bool]$_.Compressed } else { $false }
        bitlocker_protection_status   = if ($blVol) { [string]$blVol.ProtectionStatus } else { $null }
        bitlocker_encryption_method   = if ($blVol) { [string]$blVol.EncryptionMethod } else { $null }
        bitlocker_volume_status       = if ($blVol) { [string]$blVol.VolumeStatus } else { $null }
    }
})

[pscustomobject]@{
    disks   = $diskRows
    volumes = $volRows
} | ConvertTo-Json -Depth 5 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	Disks   []rawDisk   `json:"disks"`
	Volumes []rawVolume `json:"volumes"`
}

type rawDisk struct {
	SerialNumber      *string     `json:"serial_number"`
	OperationalStatus *string     `json:"operational_status"`
	HealthStatus      *string     `json:"health_status"`
	BusType           *string     `json:"bus_type"`
	PartitionCount    json.Number `json:"partition_count"`
	FirmwareRevision  string      `json:"firmware_revision"`
	MediaType         string      `json:"media_type"`
	SizeBytes         json.Number `json:"size_bytes"`
	DeviceID          string      `json:"device_id"`
	InterfaceType     string      `json:"interface_type"`
	Manufacturer      string      `json:"manufacturer"`
	Model             string      `json:"model"`
	IsBoot            bool        `json:"is_boot"`
	IsSystem          bool        `json:"is_system"`
	IsOffline         bool        `json:"is_offline"`
	IsReadOnly        bool        `json:"is_read_only"`
	IsRemovable       bool        `json:"is_removable"`
}

type rawVolume struct {
	BitLockerProtectionStatus *string     `json:"bitlocker_protection_status"`
	BitLockerVolumeStatus     *string     `json:"bitlocker_volume_status"`
	BitLockerEncryptionMethod *string     `json:"bitlocker_encryption_method"`
	SerialNumber              string      `json:"serial_number"`
	CapacityBytes             json.Number `json:"capacity_bytes"`
	FreeSpaceBytes            json.Number `json:"free_space_bytes"`
	DeviceID                  string      `json:"device_id"`
	DriveType                 json.Number `json:"drive_type"`
	FileSystem                string      `json:"file_system"`
	Label                     string      `json:"label"`
	DriveLetter               string      `json:"drive_letter"`
	IsDirty                   bool        `json:"is_dirty"`
	IsBootVolume              bool        `json:"is_boot_volume"`
	IsSystemVolume            bool        `json:"is_system_volume"`
	IsCompressed              bool        `json:"is_compressed"`
}

// ParsePowerShellOutput converts the JSON payload into an Inventory.
// Singleton-object unwrap mirrors the windowscpumem / windowsnetwork
// pattern.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	normalised := unwrapSingletonArrays(trimmed)

	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-storage json: %w", err)
	}

	inv := Inventory{
		Disks:   make([]Disk, 0, len(raw.Disks)),
		Volumes: make([]Volume, 0, len(raw.Volumes)),
	}
	for _, r := range raw.Disks {
		inv.Disks = append(inv.Disks, Disk{
			Source:            SourcePowerShellCIM,
			DeviceID:          strings.TrimSpace(r.DeviceID),
			Model:             strings.TrimSpace(r.Model),
			Manufacturer:      strings.TrimSpace(r.Manufacturer),
			InterfaceType:     strings.TrimSpace(r.InterfaceType),
			SerialNumber:      deref(r.SerialNumber),
			FirmwareRevision:  strings.TrimSpace(r.FirmwareRevision),
			MediaType:         strings.TrimSpace(r.MediaType),
			SizeBytes:         atoi64(r.SizeBytes),
			PartitionCount:    atoi(r.PartitionCount),
			BusType:           deref(r.BusType),
			HealthStatus:      deref(r.HealthStatus),
			OperationalStatus: deref(r.OperationalStatus),
			IsBoot:            r.IsBoot,
			IsSystem:          r.IsSystem,
			IsOffline:         r.IsOffline,
			IsReadOnly:        r.IsReadOnly,
			IsRemovable:       r.IsRemovable,
		})
	}
	for _, r := range raw.Volumes {
		v := Volume{
			Source:                    SourcePowerShellCIM,
			DeviceID:                  strings.TrimSpace(r.DeviceID),
			DriveLetter:               strings.TrimSpace(r.DriveLetter),
			Label:                     strings.TrimSpace(r.Label),
			FileSystem:                strings.TrimSpace(r.FileSystem),
			CapacityBytes:             atoi64(r.CapacityBytes),
			FreeSpaceBytes:            atoi64(r.FreeSpaceBytes),
			SerialNumber:              strings.TrimSpace(r.SerialNumber),
			DriveType:                 atoi(r.DriveType),
			IsDirty:                   r.IsDirty,
			IsBootVolume:              r.IsBootVolume,
			IsSystemVolume:            r.IsSystemVolume,
			IsCompressed:              r.IsCompressed,
			BitLockerProtectionStatus: deref(r.BitLockerProtectionStatus),
			BitLockerEncryptionMethod: deref(r.BitLockerEncryptionMethod),
			BitLockerVolumeStatus:     deref(r.BitLockerVolumeStatus),
		}
		AnnotateVolume(&v)
		inv.Volumes = append(inv.Volumes, v)
	}
	return inv, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if f, err := n.Float64(); err == nil {
		return int(f)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func atoi64(n json.Number) int64 {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return v
	}
	if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
		if u > 1<<62 {
			return 1 << 62
		}
		return int64(u)
	}
	return 0
}

func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"disks":`, `"volumes":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

func wrapSingletonValue(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '{' {
		return s
	}
	depth, inStr, escaped := 0, false, false
	end := -1
	for j := i; j < len(rest); j++ {
		c := rest[j]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case c == '{' && !inStr:
			depth++
		case c == '}' && !inStr:
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= i {
		return s
	}
	wrapped := "[" + rest[i:end] + "]" + rest[end:]
	return s[:idx+len(key)] + wrapped
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
