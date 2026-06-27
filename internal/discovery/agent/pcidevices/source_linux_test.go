//go:build linux

package pcidevices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeSysfsDevice lays out a single PCI device under root.
func writeSysfsDevice(t *testing.T, root, bdf string, attrs map[string]string) {
	t.Helper()
	dir := filepath.Join(root, bdf)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range attrs {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// linkSysfs creates a symlink (e.g. driver, iommu_group).
func linkSysfs(t *testing.T, root, bdf, name, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(root, bdf, name)); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxSourceEnumeratesSysfsTree(t *testing.T) {
	root := t.TempDir()

	// Host bridge (root complex).
	writeSysfsDevice(t, root, "0000:00:00.0", map[string]string{
		"vendor":             "0x1022",
		"device":             "0x1480",
		"class":              "0x060000",
		"revision":           "0x00",
		"numa_node":          "-1",
		"current_link_speed": "16.0 GT/s",
		"current_link_width": "16",
	})

	// NVMe controller bound to nvme driver.
	writeSysfsDevice(t, root, "0000:03:00.0", map[string]string{
		"vendor":             "0x144d",
		"device":             "0xa80a",
		"subsystem_vendor":   "0x144d",
		"subsystem_device":   "0xa801",
		"class":              "0x010802",
		"revision":           "0x00",
		"numa_node":          "0",
		"current_link_speed": "8.0 GT/s",
		"current_link_width": "4",
		"msi_irqs":           "32\n", // presence implies MSI enabled
		"msix_cap":           "msix\n",
	})
	linkSysfs(t, root, "0000:03:00.0", "driver",
		"../../../../bus/pci/drivers/nvme")
	linkSysfs(t, root, "0000:03:00.0", "iommu_group",
		"../../../kernel/iommu_groups/12")

	// GPU passthrough'd to a VM via vfio-pci.
	writeSysfsDevice(t, root, "0000:05:00.0", map[string]string{
		"vendor":             "0x10de",
		"device":             "0x2484",
		"class":              "0x030000",
		"revision":           "0xa1",
		"current_link_speed": "16.0 GT/s",
		"current_link_width": "16",
		"sriov_numvfs":       "0\n",
	})
	linkSysfs(t, root, "0000:05:00.0", "driver",
		"../../../../bus/pci/drivers/vfio-pci")

	// SR-IOV PF with VFs spun up.
	writeSysfsDevice(t, root, "0000:09:00.0", map[string]string{
		"vendor":             "0x8086",
		"device":             "0x1592",
		"class":              "0x020000",
		"revision":           "0x02",
		"current_link_speed": "16.0 GT/s",
		"current_link_width": "16",
		"sriov_numvfs":       "4\n",
	})
	linkSysfs(t, root, "0000:09:00.0", "driver",
		"../../../../bus/pci/drivers/ice")

	// Unbound endpoint (no driver symlink).
	writeSysfsDevice(t, root, "0000:0a:00.0", map[string]string{
		"vendor": "0x14e4",
		"device": "0x1657",
		"class":  "0x020000",
	})

	// Stray non-BDF entry — should be ignored.
	if err := os.MkdirAll(filepath.Join(root, "not-a-bdf"), 0o755); err != nil {
		t.Fatal(err)
	}

	src := NewLinuxSource(root)
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 devices, got %d: %+v", len(got), got)
	}

	byBDF := map[string]Device{}
	for _, d := range got {
		byBDF[d.BDF] = d
	}

	// Host bridge.
	hb := byBDF["0000:00:00.0"]
	if hb.VendorID != "1022" || hb.DeviceID != "1480" {
		t.Fatalf("host bridge id wrong: %+v", hb)
	}
	if hb.ClassCode != "060000" {
		t.Fatalf("host bridge class wrong: %+v", hb)
	}

	// NVMe.
	nv := byBDF["0000:03:00.0"]
	if nv.Driver != "nvme" {
		t.Fatalf("nvme driver=%q", nv.Driver)
	}
	if nv.IOMMUGroup != 12 {
		t.Fatalf("nvme iommu_group=%d", nv.IOMMUGroup)
	}
	if nv.LinkSpeedGTs != LinkSpeed8 || nv.LinkWidth != 4 {
		t.Fatalf("nvme link=%+v", nv)
	}
	if !nv.HasMSI || !nv.HasMSIX {
		t.Fatalf("nvme MSI flags wrong: %+v", nv)
	}

	// vfio-pci GPU.
	gpu := byBDF["0000:05:00.0"]
	if gpu.Driver != "vfio-pci" {
		t.Fatalf("gpu driver=%q", gpu.Driver)
	}

	// SR-IOV PF.
	pf := byBDF["0000:09:00.0"]
	if !pf.HasSRIOV || pf.NumVFs != 4 {
		t.Fatalf("PF SR-IOV state wrong: %+v", pf)
	}

	// Unbound endpoint.
	ub := byBDF["0000:0a:00.0"]
	if ub.Driver != "" {
		t.Fatalf("unbound endpoint should have empty driver: %q", ub.Driver)
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	src := NewLinuxSource(filepath.Join(t.TempDir(), "does-not-exist"))
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing root must NOT error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestCollectorOnLinuxSourceAnnotates(t *testing.T) {
	root := t.TempDir()

	writeSysfsDevice(t, root, "0000:0a:00.0", map[string]string{
		"vendor": "0x14e4",
		"device": "0x1657",
		"class":  "0x020000",
	})
	writeSysfsDevice(t, root, "0000:05:00.0", map[string]string{
		"vendor": "0x10de",
		"device": "0x2484",
		"class":  "0x030000",
	})
	linkSysfs(t, root, "0000:05:00.0", "driver",
		"../../../../bus/pci/drivers/vfio-pci")

	c := NewCollectorWith(NewLinuxSource(root))
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}

	// First (lexically smallest) is the vfio GPU at 05:00.0.
	gpu := got[0]
	if gpu.BDF != "0000:05:00.0" {
		t.Fatalf("sort drift: %+v", got)
	}
	if !gpu.IsVFIOPassthroughRisk {
		t.Fatalf("vfio risk missing: %+v", gpu)
	}

	ub := got[1]
	if !ub.IsUnboundEndpointRisk {
		t.Fatalf("unbound risk missing: %+v", ub)
	}
}

func TestParseLinkSpeedVariants(t *testing.T) {
	cases := map[string]LinkSpeedGTs{
		"2.5 GT/s":  LinkSpeed2_5,
		"5.0 GT/s":  LinkSpeed5,
		"8.0 GT/s":  LinkSpeed8,
		"16.0 GT/s": LinkSpeed16,
		"32.0 GT/s": LinkSpeed32,
		"64.0 GT/s": LinkSpeed64,
		"":          LinkSpeedNone,
		"unknown":   LinkSpeedUnknown,
		"24 GT/s":   LinkSpeedUnknown,
	}
	for in, want := range cases {
		if got := parseLinkSpeed(in); got != want {
			t.Fatalf("parseLinkSpeed(%q)=%q want %q", in, got, want)
		}
	}
}

func TestStripHexPrefix(t *testing.T) {
	cases := map[string]string{
		"0x1022":  "1022",
		"0X1022":  "1022",
		"  1022 ": "1022",
		"":        "",
	}
	for in, want := range cases {
		if got := stripHexPrefix(in); got != want {
			t.Fatalf("stripHexPrefix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsBDFAcceptsCanonical(t *testing.T) {
	good := []string{"0000:00:00.0", "0001:ff:1f.7"}
	bad := []string{"not-a-bdf", "00:00:00.0", "0000:00:00", "0000:zz:00.0"}
	for _, s := range good {
		if !isBDF(s) {
			t.Fatalf("isBDF(%q) should be true", s)
		}
	}
	for _, s := range bad {
		if isBDF(s) {
			t.Fatalf("isBDF(%q) should be false", s)
		}
	}
}
