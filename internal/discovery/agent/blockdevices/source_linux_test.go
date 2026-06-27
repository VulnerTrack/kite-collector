//go:build linux

package blockdevices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeBlk(t *testing.T, root, name string, top map[string]string,
	queue map[string]string, device map[string]string, dm map[string]string,
) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, "queue"), 0o755); err != nil {
		t.Fatal(err)
	}
	if device != nil {
		if err := os.MkdirAll(filepath.Join(dir, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if dm != nil {
		if err := os.MkdirAll(filepath.Join(dir, "dm"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range top {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range queue {
		if err := os.WriteFile(filepath.Join(dir, "queue", k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range device {
		if err := os.WriteFile(filepath.Join(dir, "device", k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range dm {
		if err := os.WriteFile(filepath.Join(dir, "dm", k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceEnumeratesBlock(t *testing.T) {
	root := t.TempDir()

	// SATA SSD.
	writeBlk(t, root, "sda",
		map[string]string{"size": "1953525168", "removable": "0", "ro": "0"},
		map[string]string{"rotational": "0", "logical_block_size": "512", "physical_block_size": "4096", "nr_requests": "256"},
		map[string]string{"model": "Samsung SSD 870", "vendor": "ATA", "firmware_rev": "SVT0", "serial": "S5XYZ1"},
		nil,
	)

	// USB stick (removable).
	writeBlk(t, root, "sdb",
		map[string]string{"size": "30965760", "removable": "1", "ro": "0"},
		map[string]string{"rotational": "0", "logical_block_size": "512", "physical_block_size": "512"},
		map[string]string{"model": "DataTraveler 3.0", "vendor": "Kingston"},
		nil,
	)

	// NVMe SSD.
	writeBlk(t, root, "nvme0n1",
		map[string]string{"size": "1000215216", "removable": "0", "ro": "0", "wwid": "eui.abc"},
		map[string]string{"rotational": "0", "logical_block_size": "512", "physical_block_size": "512"},
		nil, nil,
	)

	// LUKS-encrypted dm volume.
	writeBlk(t, root, "dm-0",
		map[string]string{"size": "1000000000", "removable": "0", "ro": "0"},
		map[string]string{"rotational": "0", "logical_block_size": "512", "physical_block_size": "512"},
		nil,
		map[string]string{"uuid": "CRYPT-LUKS2-abc123-rootdisk"},
	)

	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 devices, got %d: %+v", len(got), got)
	}

	by := map[string]Device{}
	for _, d := range got {
		by[d.Name] = d
	}

	if by["sda"].Bus != BusSCSI {
		t.Fatalf("sda bus=%q (sysfs alone can't distinguish SATA from SAS — heuristic is SCSI)", by["sda"].Bus)
	}
	if by["sda"].SizeBytes != 1953525168*512 {
		t.Fatalf("sda size=%d", by["sda"].SizeBytes)
	}
	if by["sdb"].Bus != BusSCSI || !by["sdb"].IsRemovable {
		t.Fatalf("sdb wrong: %+v", by["sdb"])
	}
	if by["nvme0n1"].Bus != BusNVMe || by["nvme0n1"].WWN != "eui.abc" {
		t.Fatalf("nvme wrong: %+v", by["nvme0n1"])
	}
	if by["dm-0"].Bus != BusDM || !by["dm-0"].IsEncrypted {
		t.Fatalf("dm-0 encryption missing: %+v", by["dm-0"])
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

func TestCollectorOnLinuxRiskAnnotations(t *testing.T) {
	root := t.TempDir()
	writeBlk(t, root, "sdb",
		map[string]string{"size": "100", "removable": "1", "ro": "0"},
		map[string]string{"rotational": "0", "logical_block_size": "512", "physical_block_size": "512"},
		map[string]string{"serial": "USB-STICK-1"},
		nil,
	)
	got, err := NewCollectorWith(NewLinuxSource(root)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	d := got[0]
	if !d.IsUnencryptedRemovableRisk {
		t.Fatalf("removable risk missing: %+v", d)
	}
	if d.SerialHash == "" {
		t.Fatalf("serial hash missing: %+v", d)
	}
}
