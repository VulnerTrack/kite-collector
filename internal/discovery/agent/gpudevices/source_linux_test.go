//go:build linux

package gpudevices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeCard(t *testing.T, root, card, vendorID, deviceID, driver string) {
	t.Helper()
	devDir := filepath.Join(root, card, "device")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devDir, "vendor"), []byte("0x"+vendorID), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devDir, "device"), []byte("0x"+deviceID), 0o644); err != nil {
		t.Fatal(err)
	}
	if driver != "" {
		if err := os.Symlink("../../../bus/pci/drivers/"+driver,
			filepath.Join(devDir, "driver")); err != nil {
			t.Fatal(err)
		}
	}
}

func writeConnector(t *testing.T, root, card, kind string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, card+"-"+kind), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeRenderNode(t *testing.T, root, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxSourceEnumerates(t *testing.T) {
	root := t.TempDir()

	// NVIDIA discrete with HDMI connector + render node.
	writeCard(t, root, "card0", "10de", "2684", "nvidia")
	writeConnector(t, root, "card0", "HDMI-A-1")
	writeRenderNode(t, root, "renderD128")

	// Render-only AI accelerator (no display connector).
	writeCard(t, root, "card1", "10de", "2330", "nvidia")
	writeRenderNode(t, root, "renderD129")

	// VFIO-passthrough'd GPU.
	writeCard(t, root, "card2", "10de", "2204", "vfio-pci")

	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	by := map[string]Device{}
	for _, d := range got {
		by[d.CardName] = d
	}
	if by["card0"].VendorID != "10de" {
		t.Fatalf("card0 vendor=%q", by["card0"].VendorID)
	}
	if by["card0"].Driver != "nvidia" {
		t.Fatalf("card0 driver=%q", by["card0"].Driver)
	}
	if !by["card0"].HasDisplay {
		t.Fatalf("card0 must have display: %+v", by["card0"])
	}
	if !by["card1"].HasCompute || by["card1"].HasDisplay {
		t.Fatalf("card1 must be compute-only: %+v", by["card1"])
	}
	if by["card2"].Driver != "vfio-pci" {
		t.Fatalf("card2 driver=%q", by["card2"].Driver)
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	got, err := NewLinuxSource(filepath.Join(t.TempDir(), "nope")).
		Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestCollectorEndToEndAnnotates(t *testing.T) {
	root := t.TempDir()
	writeCard(t, root, "card0", "10de", "2204", "vfio-pci")
	got, err := NewCollectorWith(NewLinuxSource(root)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !got[0].IsVFIOPassthroughRisk {
		t.Fatalf("vfio risk missing: %+v", got[0])
	}
}
