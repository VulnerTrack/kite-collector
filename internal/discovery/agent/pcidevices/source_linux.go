//go:build linux

package pcidevices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SysfsRoot is the canonical sysfs PCI root. Tests override via
// NewLinuxSource.
const SysfsRoot = "/sys/bus/pci/devices"

// linuxSource enumerates devices by reading the sysfs PCI tree.
// Per-attribute reads are best-effort: missing files yield empty
// strings rather than errors, since older kernels (and unsigned
// device builds) omit some attributes.
type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	readLink func(string) (string, error)
	root     string
}

// newSource returns the linux production Source.
func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

// NewLinuxSource lets callers (and tests) point at a synthetic
// sysfs root or substitute readers.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Device, error) {
	entries, err := s.readDir(s.root)
	if err != nil {
		// Missing /sys/bus/pci → not a Linux kernel with PCI
		// support enabled. Treat as empty, not an error: lets
		// containers without /sys mounted yield an empty
		// inventory instead of failing the whole probe run.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sysfs root %q: %w", s.root, err)
	}
	out := make([]Device, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		name := e.Name()
		if !isBDF(name) {
			continue
		}
		d := s.read(name)
		out = append(out, d)
	}
	return out, nil
}

// read populates a Device from the sysfs directory for one BDF.
func (s *linuxSource) read(bdf string) Device {
	dir := filepath.Join(s.root, bdf)
	d := Device{BDF: bdf, NumaNode: -1, IOMMUGroup: -1}
	d.Domain, d.Bus, d.DeviceSlot, d.Function = parseBDF(bdf)

	d.VendorID = stripHexPrefix(s.readField(dir, "vendor"))
	d.DeviceID = stripHexPrefix(s.readField(dir, "device"))
	d.SubsystemVendorID = stripHexPrefix(s.readField(dir, "subsystem_vendor"))
	d.SubsystemDeviceID = stripHexPrefix(s.readField(dir, "subsystem_device"))
	d.ClassCode = stripHexPrefix(s.readField(dir, "class"))
	d.Revision = stripHexPrefix(s.readField(dir, "revision"))
	d.LinkSpeedGTs = parseLinkSpeed(s.readField(dir, "current_link_speed"))
	d.LinkWidth = parseLinkWidth(s.readField(dir, "current_link_width"))
	d.NumaNode = atoiOrDefault(s.readField(dir, "numa_node"), -1)
	d.IOMMUGroup = parseIOMMUGroup(s.readLinkSafe(filepath.Join(dir, "iommu_group")))
	d.Driver = s.driverName(dir)
	d.HasSRIOV = s.hasField(dir, "sriov_numvfs")
	d.NumVFs = atoiOrDefault(s.readField(dir, "sriov_numvfs"), 0)
	d.HasMSI = parseEnableField(s.readField(dir, "msi_irqs"))
	d.HasMSIX = s.hasFieldNonEmpty(dir, "msix_cap")
	d.AEREnabled = s.hasFieldNonEmpty(dir, "aer_dev_correctable")
	if v := s.readField(dir, "removable"); v != "" {
		d.IsRemovable = v == "removable" || v == "1"
	}
	return d
}

// readField returns the trimmed content of dir/name, or "" if
// the file is missing or unreadable.
func (s *linuxSource) readField(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hasField reports whether dir/name exists.
func (s *linuxSource) hasField(dir, name string) bool {
	_, err := s.readFile(filepath.Join(dir, name))
	return err == nil
}

// hasFieldNonEmpty reports whether dir/name exists with non-zero
// payload.
func (s *linuxSource) hasFieldNonEmpty(dir, name string) bool {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(data))) > 0
}

// readLinkSafe returns "" on error so callers can compose.
func (s *linuxSource) readLinkSafe(path string) string {
	t, err := s.readLink(path)
	if err != nil {
		return ""
	}
	return t
}

// driverName resolves the kernel driver bound to the device by
// reading the `driver` symlink's basename. Empty string means
// no driver is bound.
func (s *linuxSource) driverName(dir string) string {
	t, err := s.readLink(filepath.Join(dir, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// isBDF reports whether name matches dddd:bb:dd.f. We accept
// only the canonical sysfs form to skip stray files.
func isBDF(name string) bool {
	if len(name) != 12 {
		return false
	}
	if name[4] != ':' || name[7] != ':' || name[10] != '.' {
		return false
	}
	return isHex(name[:4]) && isHex(name[5:7]) && isHex(name[8:10]) && isHex(name[11:])
}

// isHex reports whether s contains only [0-9a-f]+ (lower or upper).
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseBDF splits a sysfs BDF into its 4 numeric components.
// On parse failure each component falls back to 0.
func parseBDF(bdf string) (domain, bus, dev, fn int) {
	if len(bdf) != 12 {
		return
	}
	domain = parseHex(bdf[:4])
	bus = parseHex(bdf[5:7])
	dev = parseHex(bdf[8:10])
	fn = parseHex(bdf[11:])
	return
}

// parseHex returns the integer value of a short hex literal, or
// 0 on parse failure (so the BDF never returns a partial error
// to the caller).
func parseHex(s string) int {
	v, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		return 0
	}
	return int(v)
}

// stripHexPrefix drops a leading "0x" if present and lowercases
// the remainder. PCI vendor/device IDs in sysfs come prefixed.
func stripHexPrefix(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToLower(s)
}

// parseLinkSpeed maps the sysfs `current_link_speed` (forms like
// "2.5 GT/s", "8.0 GT/s") to the pinned LinkSpeedGTs enum.
func parseLinkSpeed(raw string) LinkSpeedGTs {
	if raw == "" {
		return LinkSpeedNone
	}
	t := strings.ToLower(raw)
	// Strip "GT/s" suffix and ".0" decimal for canonical match.
	t = strings.TrimSuffix(t, "gt/s")
	t = strings.TrimSpace(t)
	t = strings.TrimSuffix(t, ".0")
	switch t {
	case "2.5":
		return LinkSpeed2_5
	case "5":
		return LinkSpeed5
	case "8":
		return LinkSpeed8
	case "16":
		return LinkSpeed16
	case "32":
		return LinkSpeed32
	case "64":
		return LinkSpeed64
	}
	return LinkSpeedUnknown
}

// parseLinkWidth maps the sysfs `current_link_width` integer to
// the pinned enum (1/2/4/8/12/16/32). Unrecognised widths → 0.
func parseLinkWidth(raw string) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	switch v {
	case 1, 2, 4, 8, 12, 16, 32:
		return v
	}
	return 0
}

// parseIOMMUGroup extracts the trailing numeric basename of an
// iommu_group symlink (target like ".../kernel/iommu_groups/12").
func parseIOMMUGroup(target string) int {
	if target == "" {
		return -1
	}
	base := filepath.Base(target)
	v, err := strconv.Atoi(base)
	if err != nil {
		return -1
	}
	return v
}

// parseEnableField returns true for a non-empty msi_irqs dir
// listing (presence of any allocated MSI vector implies MSI is
// supported and active).
func parseEnableField(s string) bool {
	return strings.TrimSpace(s) != ""
}

// atoiOrDefault returns the parsed int or `def` on error.
func atoiOrDefault(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return v
}
