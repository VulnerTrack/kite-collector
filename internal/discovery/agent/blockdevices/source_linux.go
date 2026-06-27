//go:build linux

package blockdevices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SysfsRoot is the canonical sysfs block-device directory.
const SysfsRoot = "/sys/block"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

// NewLinuxSource lets callers (and tests) inject a sysfs root.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Device, error) {
	entries, err := s.readDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read block root %q: %w", s.root, err)
	}
	out := make([]Device, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		out = append(out, s.read(e.Name()))
	}
	return out, nil
}

func (s *linuxSource) read(name string) Device {
	dir := filepath.Join(s.root, name)
	d := Device{Name: name, DevicePath: "/dev/" + name}
	d.Bus = BusFromName(name)

	// size is in 512-byte sectors per sysfs convention.
	if v, err := strconv.ParseInt(strings.TrimSpace(s.field(dir, "size")), 10, 64); err == nil {
		d.SizeBytes = v * 512
	}
	d.IsRemovable = s.field(dir, "removable") == "1"
	d.IsReadOnly = s.field(dir, "ro") == "1"

	queueDir := filepath.Join(dir, "queue")
	d.IsRotational = s.field(queueDir, "rotational") == "1"
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(queueDir, "logical_block_size"))); err == nil {
		d.LogicalSector = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(queueDir, "physical_block_size"))); err == nil {
		d.PhysicalSector = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s.field(queueDir, "nr_requests"))); err == nil {
		d.QueueDepth = v
	}

	// device/{model,vendor,firmware_rev,serial} apply to SCSI /
	// SATA / SAS; NVMe exposes them at the controller level.
	devDir := filepath.Join(dir, "device")
	d.Model = s.field(devDir, "model")
	d.Vendor = s.field(devDir, "vendor")
	d.Firmware = s.field(devDir, "firmware_rev")
	d.SetRawSerial(s.field(devDir, "serial"))
	d.WWN = s.field(devDir, "wwid")
	if d.WWN == "" {
		// NVMe namespaces expose wwid at /sys/block/nvme0n1/wwid.
		d.WWN = s.field(dir, "wwid")
	}

	// Holders are downstream consumers of this block device.
	holdersDir := filepath.Join(dir, "holders")
	if hs, err := s.readDir(holdersDir); err == nil {
		d.HolderCount = len(hs)
		for _, h := range hs {
			hn := h.Name()
			if strings.HasPrefix(hn, "dm-") {
				d.IsHolderOfLVM = true
			}
			if strings.HasPrefix(hn, "md") {
				d.IsHolderOfRAID = true
			}
		}
	}

	// dm-crypt / LUKS detection: the dm UUID is prefixed with
	// "CRYPT-LUKS2-..." or "CRYPT-PLAIN-..." for encrypted maps.
	if d.Bus == BusDM {
		if uuid := s.field(filepath.Join(dir, "dm"), "uuid"); strings.HasPrefix(uuid, "CRYPT-") {
			d.IsEncrypted = true
		}
	}

	// Heuristic for HasSMART: traditional disks (not loop / dm /
	// md / zram / virtual) typically support SMART. We don't probe
	// directly — that'd require root and ioctl — so the rule is
	// "real physical disk = SMART-capable" subject to override.
	switch d.Bus {
	case BusSATA, BusSAS, BusSCSI, BusATA, BusNVMe, BusUSB, BusMMC, BusSD:
		d.HasSMART = true
	case BusLoop, BusDM, BusMD, BusZram, BusRBD, BusVirtio, BusXenBlk,
		BusISCSI, BusNBD, BusFloppy, BusPCIeDirect, BusOther, BusUnknown:
		// No SMART.
	}
	return d
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
