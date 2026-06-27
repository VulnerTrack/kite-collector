//go:build linux

package usbdevices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeDev(t *testing.T, root, name string, attrs map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range attrs {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceEnumeratesSysfs(t *testing.T) {
	root := t.TempDir()

	// Root hub.
	writeDev(t, root, "usb1", map[string]string{
		"idVendor":        "1d6b",
		"idProduct":       "0003",
		"bDeviceClass":    "9",
		"bDeviceSubClass": "0",
		"bDeviceProtocol": "3",
		"speed":           "5000",
		"busnum":          "1",
		"devnum":          "1",
		"manufacturer":    "Linux Foundation",
		"product":         "3.0 root hub",
	})

	// USB stick on port 1-2 with mass-storage interface.
	writeDev(t, root, "1-2", map[string]string{
		"idVendor":        "0951",
		"idProduct":       "1666",
		"bDeviceClass":    "0",
		"bDeviceSubClass": "0",
		"bDeviceProtocol": "0",
		"speed":           "480",
		"busnum":          "1",
		"devnum":          "5",
		"manufacturer":    "Kingston",
		"product":         "DataTraveler",
		"serial":          "ABC123",
		"removable":       "removable\n",
		"bNumInterfaces":  "1",
		"bMaxPower":       "200mA",
	})
	// Interface child describing mass-storage class.
	writeDev(t, root, "1-2:1.0", map[string]string{
		"bInterfaceClass": "08",
	})

	// USB keyboard on port 1-3 (HID + removable).
	writeDev(t, root, "1-3", map[string]string{
		"idVendor":       "046d",
		"idProduct":      "c52b",
		"bDeviceClass":   "0",
		"speed":          "12",
		"busnum":         "1",
		"devnum":         "6",
		"removable":      "removable",
		"bNumInterfaces": "2",
	})
	writeDev(t, root, "1-3:1.0", map[string]string{
		"bInterfaceClass": "03", // HID
	})
	writeDev(t, root, "1-3:1.1", map[string]string{
		"bInterfaceClass": "03",
	})

	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 devices, got %d: %+v", len(got), got)
	}

	byPath := map[string]Device{}
	for _, d := range got {
		byPath[d.BusPath] = d
	}

	hub := byPath["usb1"]
	if hub.ClassCode != "09" {
		t.Fatalf("hub class=%q", hub.ClassCode)
	}
	if hub.VendorID != "1d6b" {
		t.Fatalf("hub vendor=%q", hub.VendorID)
	}

	stick := byPath["1-2"]
	if !stick.HasMassStorageInterface {
		t.Fatalf("stick must flag mass-storage interface: %+v", stick)
	}
	if !stick.IsRemovable {
		t.Fatalf("stick must flag removable: %+v", stick)
	}
	if stick.Serial != "ABC123" {
		t.Fatalf("stick serial=%q", stick.Serial)
	}

	kb := byPath["1-3"]
	if !kb.HasHIDInterface {
		t.Fatalf("keyboard must flag HID: %+v", kb)
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	got, err := NewLinuxSource(filepath.Join(t.TempDir(), "nope")).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing root must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestPadHex2(t *testing.T) {
	cases := map[string]string{"9": "09", "09": "09", "FF": "ff", "  3 ": "03", "": ""}
	for in, want := range cases {
		if got := padHex2(in); got != want {
			t.Fatalf("padHex2(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseMaxPower(t *testing.T) {
	cases := map[string]int{"500mA": 500, "500 mA": 500, "200": 200, "": 0, "junk": 0}
	for in, want := range cases {
		if got := parseMaxPower(in); got != want {
			t.Fatalf("parseMaxPower(%q)=%d want %d", in, got, want)
		}
	}
}
