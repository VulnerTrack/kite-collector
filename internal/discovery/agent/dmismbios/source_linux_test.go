//go:build linux

package dmismbios

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeDMI(t *testing.T, root string, kv map[string]string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if err := os.WriteFile(filepath.Join(root, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceReadsSysfsDMI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "id")
	efiRoot := filepath.Join(t.TempDir(), "efi")
	sbVar := filepath.Join(t.TempDir(), "sb")

	writeDMI(t, root, map[string]string{
		"bios_vendor":       "American Megatrends",
		"bios_version":      "F.42",
		"bios_date":         "06/24/2024\n",
		"sys_vendor":        "Dell Inc.",
		"product_name":      "PowerEdge R750",
		"product_serial":    "ABC-123-XYZ\n",
		"product_uuid":      "11111111-2222-3333-4444-555555555555\n",
		"board_vendor":      "Dell Inc.",
		"board_name":        "0WCJNT",
		"board_serial":      "BOARD-S",
		"chassis_vendor":    "Dell Inc.",
		"chassis_type":      "23",
		"chassis_serial":    "CHASSIS-S",
		"chassis_asset_tag": "ASSET-99",
	})

	// EFI present, Secure Boot enabled.
	if err := os.MkdirAll(efiRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbVar, []byte{0x06, 0x00, 0x00, 0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewLinuxSource(root, efiRoot, sbVar)
	got, err := src.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.BIOSVendor != "American Megatrends" {
		t.Fatalf("bios vendor=%q", got.BIOSVendor)
	}
	if got.SystemProductName != "PowerEdge R750" {
		t.Fatalf("product=%q", got.SystemProductName)
	}
	if got.ChassisType != ChassisRackMount {
		t.Fatalf("chassis=%q want rack-mount", got.ChassisType)
	}
	if got.ChassisAssetTag != "ASSET-99" {
		t.Fatalf("asset=%q", got.ChassisAssetTag)
	}
	if !got.IsUEFI {
		t.Fatal("UEFI missing")
	}
	if !got.IsSecureBoot {
		t.Fatal("secure boot missing")
	}
	// rawSerials should be populated; collector pipeline hashes them.
	if got.rawSystemSerial == "" || got.rawBoardSerial == "" || got.rawChassisSerial == "" {
		t.Fatalf("raw serials missing: %+v", got)
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	got, err := NewLinuxSource(filepath.Join(t.TempDir(), "nope"), "", "").
		Read(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if got.ChassisType != ChassisUnknown {
		t.Fatalf("chassis=%q", got.ChassisType)
	}
}

func TestCollectorEndToEndOnLinuxSource(t *testing.T) {
	root := filepath.Join(t.TempDir(), "id")
	writeDMI(t, root, map[string]string{
		"sys_vendor":     "QEMU",
		"product_name":   "Standard PC (i440FX + PIIX, 1996)",
		"bios_date":      "01/01/2022",
		"product_serial": "vm-001",
		"chassis_type":   "1",
	})
	got, err := NewCollectorWith(NewLinuxSource(root, "/nope", "/nope")).
		Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !got.IsVirtualized || got.HypervisorHint != "qemu" {
		t.Fatalf("hypervisor missed: %+v", got)
	}
	if got.SystemSerialHash == "" {
		t.Fatal("serial not hashed")
	}
	if !got.IsBIOSStaleRisk {
		t.Fatal("2022-dated BIOS must flag stale risk")
	}
}
