package driver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSysfsBindings_PCI_Fixture(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("sysfs is unix-only; symlinks behave differently on windows")
	}

	root := t.TempDir()
	dev := filepath.Join(root, "0000:01:00.0")
	require.NoError(t, os.MkdirAll(dev, 0o755))
	writeSysfs(t, filepath.Join(dev, "vendor"), "0x10de\n")
	writeSysfs(t, filepath.Join(dev, "device"), "0x2208\n")
	writeSysfs(t, filepath.Join(dev, "subsystem_vendor"), "0x1043\n")
	writeSysfs(t, filepath.Join(dev, "subsystem_device"), "0x8744\n")
	writeSysfs(t, filepath.Join(dev, "class"), "0x030000\n")

	driverDir := filepath.Join(root, "..", "drivers", "nvidia")
	require.NoError(t, os.MkdirAll(driverDir, 0o755))
	require.NoError(t, os.Symlink(driverDir, filepath.Join(dev, "driver")))

	bindings, errs := readPCIBindings(root)
	require.Empty(t, errs)
	require.Len(t, bindings, 1)

	got := bindings[0]
	assert.Equal(t, "pci", got.Bus)
	assert.Equal(t, "0000:01:00.0", got.Address)
	assert.Equal(t, "10de", got.VendorID)
	assert.Equal(t, "2208", got.DeviceID)
	assert.Equal(t, "1043", got.SubsystemVID)
	assert.Equal(t, "8744", got.SubsystemDID)
	assert.Equal(t, "030000", got.Class)
	assert.Equal(t, "nvidia", got.DriverName)
	assert.Equal(t, "PCI\\VEN_10DE&DEV_2208", got.HardwareID)
}

func TestSysfsBindings_PCI_MissingDriverSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dev := filepath.Join(root, "0000:00:1f.0")
	require.NoError(t, os.MkdirAll(dev, 0o755))
	writeSysfs(t, filepath.Join(dev, "vendor"), "0x8086")
	writeSysfs(t, filepath.Join(dev, "device"), "0x9d23")

	bindings, errs := readPCIBindings(root)
	require.Empty(t, errs)
	require.Len(t, bindings, 1)
	assert.Empty(t, bindings[0].DriverName, "no driver symlink yields empty DriverName")
}

func TestSysfsBindings_PCI_MissingVendorIsError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dev := filepath.Join(root, "0000:00:00.0")
	require.NoError(t, os.MkdirAll(dev, 0o755))
	// no vendor file
	bindings, errs := readPCIBindings(root)
	assert.Empty(t, bindings)
	require.Len(t, errs, 1)
}

func TestSysfsBindings_USB_Fixture(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("sysfs is unix-only")
	}

	root := t.TempDir()
	device := filepath.Join(root, "1-1")
	require.NoError(t, os.MkdirAll(device, 0o755))
	writeSysfs(t, filepath.Join(device, "idVendor"), "1d6b\n")
	writeSysfs(t, filepath.Join(device, "idProduct"), "0002\n")
	writeSysfs(t, filepath.Join(device, "bDeviceClass"), "09\n")

	driverDir := filepath.Join(root, "..", "drivers", "usb")
	require.NoError(t, os.MkdirAll(driverDir, 0o755))
	require.NoError(t, os.Symlink(driverDir, filepath.Join(device, "driver")))

	// Add an interface-shaped entry with no idVendor — should be silently
	// skipped, not surfaced as an error.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "1-0:1.0"), 0o755))

	bindings, errs := readUSBBindings(root)
	require.Empty(t, errs)
	require.Len(t, bindings, 1)
	got := bindings[0]
	assert.Equal(t, "usb", got.Bus)
	assert.Equal(t, "1-1", got.Address)
	assert.Equal(t, "1d6b", got.VendorID)
	assert.Equal(t, "0002", got.DeviceID)
	assert.Equal(t, "09", got.Class)
	assert.Equal(t, "usb", got.DriverName)
	assert.Equal(t, "USB\\VID_1D6B&PID_0002", got.HardwareID)
}

func TestSysfsBindings_NotAvailableOnNonLinux(t *testing.T) {
	t.Parallel()
	c := &SysfsBindings{
		pciRoot: filepath.Join(t.TempDir(), "absent"),
		usbRoot: filepath.Join(t.TempDir(), "absent"),
	}
	assert.False(t, c.Available(), "missing both roots = not available")
}

func TestSysfsBindings_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "linux-sysfs-bindings", NewSysfsBindings().Name())
}

func TestSysfsBindings_Collect_EmptyRoots(t *testing.T) {
	t.Parallel()
	c := &SysfsBindings{
		pciRoot: filepath.Join(t.TempDir(), "no-pci"),
		usbRoot: filepath.Join(t.TempDir(), "no-usb"),
	}
	res, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Bindings)
	assert.Empty(t, res.Errs)
}

func writeSysfs(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
