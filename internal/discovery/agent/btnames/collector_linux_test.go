//go:build linux

package btnames

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxCollectorWalksBlueZTree(t *testing.T) {
	root := t.TempDir()
	adapter := "AA:BB:CC:DD:EE:FF"
	device := "11:22:33:44:55:66"
	devDir := filepath.Join(root, adapter, device)
	mustMk(t, os.MkdirAll(devDir, 0o755))

	info := []byte(`[General]
Name=Logitech MX Keys
Alias=Alice's Keyboard
Class=0x000540
AddressType=public
Trusted=true
Connected=true

[DeviceID]
Source=2
Vendor=1133
Manufacturer=Logitech
`)
	mustMk(t, os.WriteFile(filepath.Join(devDir, "info"), info, 0o644))

	// Non-MAC dir name: skipped.
	mustMk(t, os.MkdirAll(filepath.Join(root, "settings"), 0o755))
	// Adapter MAC but device dir missing info: skipped.
	mustMk(t, os.MkdirAll(filepath.Join(root, adapter, "AA:11:22:33:44:55"), 0o755))

	c := &fileCollector{
		roots:    []string{root},
		now:      func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		getenv:   func(string) string { return "" },
	}
	rows, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Source != SourceLinuxBlueZ {
		t.Fatalf("source=%q", r.Source)
	}
	if r.AdapterMAC != adapter {
		t.Fatalf("adapter=%q", r.AdapterMAC)
	}
	if r.DeviceMAC != device {
		t.Fatalf("device=%q", r.DeviceMAC)
	}
	if r.DeviceName != "Alice's Keyboard" {
		t.Fatalf("name=%q", r.DeviceName)
	}
	if r.DeviceClass != DeviceClassPeripheral {
		t.Fatalf("class=%q", r.DeviceClass)
	}
	if !r.IsTrusted {
		t.Fatal("trusted must flag")
	}
	if r.Manufacturer != "Logitech" {
		t.Fatalf("manuf=%q", r.Manufacturer)
	}
	if r.DeviceNameHash == "" {
		t.Fatal("hash must be set")
	}
}

func TestLinuxCollectorMissingRoot(t *testing.T) {
	c := &fileCollector{
		roots:    []string{"/nope-bluez"},
		now:      func() time.Time { return time.Now() },
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		getenv:   func(string) string { return "" },
	}
	rows, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("want empty, got %d", len(rows))
	}
}

func TestLinuxCollectorRespectsEnv(t *testing.T) {
	custom := t.TempDir()
	adapter := "AA:BB:CC:DD:EE:FF"
	device := "11:22:33:44:55:66"
	mustMk(t, os.MkdirAll(filepath.Join(custom, adapter, device), 0o755))
	mustMk(t, os.WriteFile(filepath.Join(custom, adapter, device, "info"),
		[]byte(`[General]
Name=Custom Device
Class=0x000200
`), 0o644))

	c := &fileCollector{
		roots:    []string{"/nope-default"},
		now:      func() time.Time { return time.Now() },
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		getenv: func(k string) string {
			if k == "BTNAMES_BLUEZ_ROOT" {
				return custom
			}
			return ""
		},
	}
	rows, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rows) != 1 || rows[0].DeviceName != "Custom Device" {
		t.Fatalf("env: %+v", rows)
	}
}

func mustMk(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
