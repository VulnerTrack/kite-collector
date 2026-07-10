//go:build linux

package tpmdevices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeTPM(t *testing.T, root, name string, attrs map[string]string, banks []string) {
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
	for _, b := range banks {
		bdir := filepath.Join(dir, b)
		if err := os.MkdirAll(bdir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Sysfs exposes 24 PCR entries per bank; one placeholder
		// child is enough to make our presence check succeed.
		if err := os.WriteFile(filepath.Join(bdir, "0"), []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceReadsTPM(t *testing.T) {
	root := t.TempDir()
	writeTPM(
		t, root, "tpm0",
		map[string]string{
			"tpm_version_major":    "2\n",
			"tpm_mfr_id":           "INTC\n",
			"tpm_vendor_id":        "Intel\n",
			"tpm_firmware_version": "5.81.2.0\n",
			"tpm_owned":            "1\n",
		},
		[]string{"pcr-sha1", "pcr-sha256", "pcr-sha384"},
	)
	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	d := got[0]
	if d.SpecVersion != SpecTPM20 {
		t.Fatalf("spec=%q", d.SpecVersion)
	}
	if d.ManufacturerID != "INTC" {
		t.Fatalf("mfg id=%q", d.ManufacturerID)
	}
	if !d.HasSHA256Bank || !d.HasSHA1Bank || !d.HasSHA384Bank {
		t.Fatalf("bank flags wrong: %+v", d)
	}
	if d.HasSHA512Bank || d.HasSM3_256Bank {
		t.Fatalf("absent banks must be false: %+v", d)
	}
	if !d.IsActive || !d.IsOwned {
		t.Fatalf("active/owned wrong: %+v", d)
	}
	if !d.IsFirmwareTPM {
		t.Fatalf("Intel vendor must flag firmware TPM: %+v", d)
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

func TestCollectorEndToEndOnLinuxSource(t *testing.T) {
	root := t.TempDir()
	writeTPM(
		t, root, "tpm0",
		map[string]string{
			"tpm_version_major": "1\n",
			"tpm_mfr_id":        "IFX\n",
		},
		nil,
	)
	got, err := NewCollectorWith(NewLinuxSource(root)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	d := got[0]
	if !d.IsLegacyTPM12Risk {
		t.Fatal("TPM 1.2 must flag legacy risk")
	}
	if d.ManufacturerName != MfgInfineon {
		t.Fatalf("mfg=%q", d.ManufacturerName)
	}
}
