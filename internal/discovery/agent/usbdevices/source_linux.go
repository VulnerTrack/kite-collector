//go:build linux

package usbdevices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SysfsRoot is the canonical sysfs USB device directory. Each
// USB function (including hubs and root hubs) appears as a
// subdirectory whose name encodes the bus + port path
// (e.g. "1-2.1.4:1.0"). Tests inject a synthetic root via
// NewLinuxSource.
const SysfsRoot = "/sys/bus/usb/devices"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	readLink func(string) (string, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		readLink: os.Readlink,
	}
}

// NewLinuxSource lets callers inject a root path for tests.
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
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read usb root %q: %w", s.root, err)
	}
	out := make([]Device, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		name := e.Name()
		// Skip interface-level dirs (contain `:N.M`) and stray
		// non-device entries. Function/device dirs have names
		// like "1-2.4" or "usb1".
		if strings.Contains(name, ":") {
			continue
		}
		out = append(out, s.read(name))
	}
	return out, nil
}

func (s *linuxSource) read(name string) Device {
	dir := filepath.Join(s.root, name)
	d := Device{BusPath: name}
	d.VendorID = strings.TrimSpace(s.field(dir, "idVendor"))
	d.ProductID = strings.TrimSpace(s.field(dir, "idProduct"))
	d.BCDDevice = strings.TrimSpace(s.field(dir, "bcdDevice"))
	d.VendorName = strings.TrimSpace(s.field(dir, "manufacturer"))
	d.ProductName = strings.TrimSpace(s.field(dir, "product"))
	d.Serial = strings.TrimSpace(s.field(dir, "serial"))
	d.ClassCode = padHex2(s.field(dir, "bDeviceClass"))
	d.SubclassCode = padHex2(s.field(dir, "bDeviceSubClass"))
	d.ProtocolCode = padHex2(s.field(dir, "bDeviceProtocol"))
	d.SpeedMbps = parseSpeed(s.field(dir, "speed"))
	d.MaxPowerMA = parseMaxPower(s.field(dir, "bMaxPower"))
	d.InterfaceCount = atoi(s.field(dir, "bNumInterfaces"))
	d.BusNum = atoi(s.field(dir, "busnum"))
	d.DevNum = atoi(s.field(dir, "devnum"))
	d.PortPath = strings.TrimSpace(s.field(dir, "devpath"))
	if v := strings.TrimSpace(s.field(dir, "removable")); v != "" {
		d.IsRemovable = v == "removable" || v == "1"
	}
	d.Driver = s.driverName(dir)
	// Walk sibling interface dirs (`<name>:c.i`) to flag class
	// composition for composite devices.
	s.markInterfaceClasses(&d, name)
	return d
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}

// driverName returns the bound USB driver basename (often
// "usbfs", "hub", "usb-storage", "btusb", "rtl8xxxu", etc.) or
// "" if no driver is bound.
func (s *linuxSource) driverName(dir string) string {
	target, err := s.readLink(filepath.Join(dir, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// markInterfaceClasses scans sibling interface dirs
// (`<name>:c.i`) under SysfsRoot to flag HID / mass-storage /
// network composite device interfaces. Per-class flags are
// additive: a single device can carry several interfaces.
func (s *linuxSource) markInterfaceClasses(d *Device, name string) {
	entries, err := s.readDir(s.root)
	if err != nil {
		return
	}
	prefix := name + ":"
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) {
			continue
		}
		ifaceClass := padHex2(s.field(filepath.Join(s.root, n), "bInterfaceClass"))
		switch ClassNameFromCode(ifaceClass) {
		case ClassHID:
			d.HasHIDInterface = true
		case ClassMassStorage:
			d.HasMassStorageInterface = true
		case ClassCommunications, ClassCDCData:
			d.HasNetworkInterface = true
		case ClassInterfaceSpecific, ClassAudio, ClassPhysical,
			ClassImage, ClassPrinter, ClassHub, ClassSmartCard,
			ClassContentSecurity, ClassVideo, ClassPersonalHealthcare,
			ClassAudioVideo, ClassBillboard, ClassUSBTypeCBridge,
			ClassDiagnostic, ClassWireless, ClassMiscellaneous,
			ClassApplicationSpec, ClassVendorSpecific, ClassUnknown:
			// Not a composite-device flag we track.
		}
	}
}

// padHex2 turns "9" / "09" / " 9 " into "09".
func padHex2(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return ""
	}
	if len(t) == 1 {
		return "0" + strings.ToLower(t)
	}
	return strings.ToLower(t)
}

// atoi returns the integer value of a trimmed decimal field, or
// 0 on parse failure.
func atoi(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return v
}

// parseSpeed maps the sysfs `speed` field (decimal mbps as a
// string, e.g. "480", "5000") to an int.
func parseSpeed(s string) int { return atoi(s) }

// parseMaxPower maps a value like "500mA" / "500 mA" to its
// numeric mA quantity.
func parseMaxPower(s string) int {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimSuffix(t, "ma")
	t = strings.TrimSpace(t)
	return atoi(t)
}
