package driver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

// SysfsBindings walks /sys/bus/{pci,usb}/devices/* to enumerate PnP
// hardware-to-driver bindings. Read-only and Linux-only.
type SysfsBindings struct {
	pciRoot string
	usbRoot string
}

// NewSysfsBindings constructs a SysfsBindings with the kernel-default roots.
func NewSysfsBindings() *SysfsBindings {
	return &SysfsBindings{
		pciRoot: "/sys/bus/pci/devices",
		usbRoot: "/sys/bus/usb/devices",
	}
}

// Name returns the registry identifier.
func (s *SysfsBindings) Name() string { return "linux-sysfs-bindings" }

// Available returns true when at least one of the two sysfs roots exists.
func (s *SysfsBindings) Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat(s.pciRoot); err == nil {
		return true
	}
	if _, err := os.Stat(s.usbRoot); err == nil {
		return true
	}
	return false
}

// Collect enumerates every device under the configured sysfs roots.
func (s *SysfsBindings) Collect(ctx context.Context) (*Result, error) {
	_ = ctx
	res := &Result{}

	pci, errs := readPCIBindings(s.pciRoot)
	res.Bindings = append(res.Bindings, pci...)
	res.Errs = append(res.Errs, errs...)

	usb, errs := readUSBBindings(s.usbRoot)
	res.Bindings = append(res.Bindings, usb...)
	res.Errs = append(res.Errs, errs...)

	res.Sort()
	return res, nil
}

// readPCIBindings walks /sys/bus/pci/devices/* and parses each leaf.
//
// Each device directory exposes:
//
//	vendor            0x10de
//	device            0x2208
//	subsystem_vendor  0x1043
//	subsystem_device  0x8744
//	class             0x030000
//	driver -> ../../../bus/pci/drivers/nvidia
func readPCIBindings(root string) ([]DeviceBinding, []CollectError) {
	entries, err := os.ReadDir(root)
	if err != nil {
		// missing root is "no PCI bus" — not an error worth surfacing.
		return nil, nil
	}

	var out []DeviceBinding
	var errs []CollectError
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		bind, perr := readPCIDevice(dir, e.Name())
		if perr != nil {
			errs = append(errs, CollectError{
				Collector: "linux-sysfs-bindings",
				RawLine:   e.Name(),
				Err:       perr,
			})
			continue
		}
		out = append(out, bind)
	}
	return out, errs
}

func readPCIDevice(dir, address string) (DeviceBinding, error) {
	vendor, err := readSysfsHex(filepath.Join(dir, "vendor"))
	if err != nil {
		return DeviceBinding{}, fmt.Errorf("vendor: %w", err)
	}
	device, err := readSysfsHex(filepath.Join(dir, "device"))
	if err != nil {
		return DeviceBinding{}, fmt.Errorf("device: %w", err)
	}
	subVendor, _ := readSysfsHex(filepath.Join(dir, "subsystem_vendor"))
	subDevice, _ := readSysfsHex(filepath.Join(dir, "subsystem_device"))
	class, _ := readSysfsHex(filepath.Join(dir, "class"))
	driver := readDriverSymlink(filepath.Join(dir, "driver"))

	return DeviceBinding{
		ID:           uuid.Must(uuid.NewV7()),
		Bus:          "pci",
		Address:      address,
		VendorID:     vendor,
		DeviceID:     device,
		SubsystemVID: subVendor,
		SubsystemDID: subDevice,
		Class:        class,
		DriverName:   driver,
		HardwareID:   fmt.Sprintf("PCI\\VEN_%s&DEV_%s", strings.ToUpper(vendor), strings.ToUpper(device)),
	}, nil
}

// readUSBBindings walks /sys/bus/usb/devices/* and parses each leaf.
//
// Each USB device exposes:
//
//	idVendor          1d6b
//	idProduct         0002
//	bDeviceClass      09
//	driver -> ../../../bus/usb/drivers/usb
//
// The bus exposes hubs as e.g. "usb1", "1-0:1.0" — only the device-shaped
// directories (containing idVendor) yield bindings; the rest are skipped.
func readUSBBindings(root string) ([]DeviceBinding, []CollectError) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil
	}

	var out []DeviceBinding
	var errs []CollectError
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		vendor, err := readSysfsHex(filepath.Join(dir, "idVendor"))
		if err != nil {
			// Most USB sysfs entries are interfaces / hubs without idVendor —
			// silently skip them, surface only the ones that exist but fail.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, CollectError{
				Collector: "linux-sysfs-bindings",
				RawLine:   e.Name(),
				Err:       fmt.Errorf("idVendor: %w", err),
			})
			continue
		}
		device, err := readSysfsHex(filepath.Join(dir, "idProduct"))
		if err != nil {
			errs = append(errs, CollectError{
				Collector: "linux-sysfs-bindings",
				RawLine:   e.Name(),
				Err:       fmt.Errorf("idProduct: %w", err),
			})
			continue
		}
		class, _ := readSysfsHex(filepath.Join(dir, "bDeviceClass"))
		driver := readDriverSymlink(filepath.Join(dir, "driver"))

		out = append(out, DeviceBinding{
			ID:         uuid.Must(uuid.NewV7()),
			Bus:        "usb",
			Address:    e.Name(),
			VendorID:   vendor,
			DeviceID:   device,
			Class:      class,
			DriverName: driver,
			HardwareID: fmt.Sprintf("USB\\VID_%s&PID_%s", strings.ToUpper(vendor), strings.ToUpper(device)),
		})
	}
	return out, errs
}

// readSysfsHex reads a sysfs file containing "0xNNNN" and returns the
// hex digits without the "0x" prefix, lowercased and zero-padded to 4.
func readSysfsHex(path string) (string, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- caller-resolved sysfs path
	if err != nil {
		return "", fmt.Errorf("read sysfs %s: %w", path, err)
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	return strings.ToLower(s), nil
}

// readDriverSymlink returns the basename of the "driver" symlink target,
// which the kernel sets to the bound driver module's name. Empty string
// when no driver is bound (device claimed by userspace or unbound).
func readDriverSymlink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}
