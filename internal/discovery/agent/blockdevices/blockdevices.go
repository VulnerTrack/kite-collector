// Package blockdevices enumerates block devices on the host
// (disks, removable media, virtio-blk, loop devices, RAID
// arrays, LVM logical volumes, dm-crypt mappings) across
// Linux, macOS, Windows, and FreeBSD. Per-OS Sources live in
// build-tagged files. Tests inject a fakeSource.
//
// PII discipline: device serial numbers are SHA-256 hashed
// before persistence — a raw drive serial uniquely identifies
// the host across vendor support portals.
//
// Read-only by intent.
package blockdevices

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 2048
	RecentlyWindow = 24 * time.Hour
)

// Bus pinned to host_block_devices.bus.
type Bus string

const (
	BusUnknown    Bus = "unknown"
	BusSATA       Bus = "sata"
	BusSAS        Bus = "sas"
	BusSCSI       Bus = "scsi"
	BusNVMe       Bus = "nvme"
	BusUSB        Bus = "usb"
	BusVirtio     Bus = "virtio"
	BusMMC        Bus = "mmc"
	BusSD         Bus = "sd"
	BusXenBlk     Bus = "xen-blk"
	BusFloppy     Bus = "floppy"
	BusISCSI      Bus = "iscsi"
	BusNBD        Bus = "nbd"
	BusLoop       Bus = "loop"
	BusDM         Bus = "dm"
	BusMD         Bus = "md"
	BusZram       Bus = "zram"
	BusRBD        Bus = "rbd"
	BusATA        Bus = "ata"
	BusPCIeDirect Bus = "pcie-direct"
	BusOther      Bus = "other"
)

// MediaType pinned to host_block_devices.media_type.
type MediaType string

const (
	MediaUnknown   MediaType = "unknown"
	MediaHDD       MediaType = "hdd"
	MediaSSD       MediaType = "ssd"
	MediaNVMeSSD   MediaType = "nvme-ssd"
	MediaRemovable MediaType = "removable"
	MediaOptical   MediaType = "optical"
	MediaVirtual   MediaType = "virtual"
	MediaLoop      MediaType = "loop"
	MediaRamdisk   MediaType = "ramdisk"
	MediaTape      MediaType = "tape"
	MediaOther     MediaType = "other"
)

// Device mirrors host_block_devices columns.
type Device struct {
	Name                       string    `json:"name"`
	DevicePath                 string    `json:"device_path,omitempty"`
	Bus                        Bus       `json:"bus"`
	MediaType                  MediaType `json:"media_type"`
	Model                      string    `json:"model,omitempty"`
	Vendor                     string    `json:"vendor,omitempty"`
	Firmware                   string    `json:"firmware,omitempty"`
	SerialHash                 string    `json:"serial_hash,omitempty"`
	WWN                        string    `json:"wwn,omitempty"`
	rawSerial                  string
	QueueDepth                 int   `json:"queue_depth"`
	PhysicalSector             int   `json:"physical_sector"`
	LogicalSector              int   `json:"logical_sector"`
	RotationRPM                int   `json:"rotation_rpm"`
	SizeBytes                  int64 `json:"size_bytes"`
	HolderCount                int   `json:"holder_count"`
	HasSMART                   bool  `json:"has_smart"`
	IsReadOnly                 bool  `json:"is_read_only"`
	IsEncrypted                bool  `json:"is_encrypted"`
	IsRemovable                bool  `json:"is_removable"`
	IsHolderOfLVM              bool  `json:"is_holder_of_lvm"`
	IsHolderOfRAID             bool  `json:"is_holder_of_raid"`
	IsUnencryptedRemovableRisk bool  `json:"is_unencrypted_removable_risk"`
	IsNoSMARTRisk              bool  `json:"is_no_smart_risk"`
	IsRecent                   bool  `json:"is_recent"`
	IsRotational               bool  `json:"is_rotational"`
}

// SetRawSerial lets a Source feed the unhashed serial.
func (d *Device) SetRawSerial(s string) { d.rawSerial = s }

// Source enumerates raw per-OS records.
type Source interface {
	Enumerate(ctx context.Context) ([]Device, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Device, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "blockdevices" }

func (c *collector) Collect(ctx context.Context) ([]Device, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("blockdevices enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortDevices(rows)
	return rows, nil
}

// Normalize derives media_type from the (bus, is_rotational)
// pair and validates enum defaults.
func Normalize(d *Device) {
	if d.Bus == "" {
		d.Bus = BusUnknown
	}
	if d.MediaType == "" || d.MediaType == MediaUnknown {
		d.MediaType = DeriveMediaType(d.Bus, d.IsRotational, d.IsRemovable)
	}
}

// Annotate hashes the raw serial and sets security rollups.
func Annotate(d *Device) {
	d.SerialHash = hashIfNonempty(d.rawSerial)
	d.rawSerial = ""
	d.IsRecent = true
	if d.IsRemovable && !d.IsEncrypted &&
		(d.MediaType == MediaRemovable || d.MediaType == MediaSSD ||
			d.MediaType == MediaHDD || d.MediaType == MediaNVMeSSD) {
		d.IsUnencryptedRemovableRisk = true
	}
	if !d.HasSMART &&
		(d.MediaType == MediaHDD || d.MediaType == MediaSSD || d.MediaType == MediaNVMeSSD) {
		d.IsNoSMARTRisk = true
	}
}

// DeriveMediaType infers a media type from the bus + rotation
// + removable flags. Heuristic is conservative — falls back to
// MediaUnknown rather than guessing.
func DeriveMediaType(bus Bus, rotational, removable bool) MediaType {
	switch bus {
	case BusNVMe:
		return MediaNVMeSSD
	case BusLoop:
		return MediaLoop
	case BusZram, BusDM, BusMD:
		return MediaVirtual
	case BusUSB, BusMMC, BusSD:
		return MediaRemovable
	case BusFloppy:
		return MediaRemovable
	case BusSATA, BusSAS, BusSCSI, BusATA, BusVirtio, BusXenBlk, BusISCSI, BusNBD, BusRBD:
		if removable {
			return MediaRemovable
		}
		if rotational {
			return MediaHDD
		}
		return MediaSSD
	case BusPCIeDirect, BusOther, BusUnknown:
		return MediaUnknown
	}
	return MediaUnknown
}

// BusFromName maps a Linux device basename to its bus enum.
func BusFromName(name string) Bus {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "nvme"):
		return BusNVMe
	case strings.HasPrefix(n, "loop"):
		return BusLoop
	case strings.HasPrefix(n, "dm-"):
		return BusDM
	case strings.HasPrefix(n, "md"):
		return BusMD
	case strings.HasPrefix(n, "zram"):
		return BusZram
	case strings.HasPrefix(n, "rbd"):
		return BusRBD
	case strings.HasPrefix(n, "vd") || strings.HasPrefix(n, "virtblk"):
		return BusVirtio
	case strings.HasPrefix(n, "xvd"):
		return BusXenBlk
	case strings.HasPrefix(n, "mmcblk"):
		return BusMMC
	case strings.HasPrefix(n, "fd"):
		return BusFloppy
	case strings.HasPrefix(n, "nbd"):
		return BusNBD
	case strings.HasPrefix(n, "sd") || strings.HasPrefix(n, "sr") || strings.HasPrefix(n, "st"):
		// sdX = generic SCSI-class. Caller may refine to SATA /
		// SAS / USB later from sysfs subsystem hint.
		return BusSCSI
	}
	return BusUnknown
}

// SortDevices returns deterministic ordering by name.
func SortDevices(rs []Device) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
}

func hashIfNonempty(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
