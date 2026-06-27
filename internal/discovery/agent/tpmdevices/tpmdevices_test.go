package tpmdevices

import (
	"context"
	"errors"
	"testing"
)

func TestManufacturerNameFromID(t *testing.T) {
	cases := []struct {
		id, vendor string
		want       ManufacturerName
	}{
		{id: "IFX", want: MfgInfineon},
		{id: "STM", want: MfgSTMicro},
		{id: "NTC", want: MfgNuvoton},
		{id: "ATML", want: MfgAtmel},
		{id: "INTC", want: MfgIntelPTT},
		{id: "AMD", want: MfgAMDFTPM},
		{id: "GOOG", want: MfgGoogle},
		{id: "APPL", want: MfgApple},
		{id: "QEMU", want: MfgQEMUSwtpm},
		{id: "", vendor: "Intel Corp", want: MfgIntelPTT},
		{id: "", vendor: "Nuvoton Technology", want: MfgNuvoton},
		{id: "", vendor: "Apple Inc.", want: MfgApple},
		{id: "", vendor: "swtpm 0.8", want: MfgQEMUSwtpm},
		{id: "FOO", vendor: "", want: MfgOther},
		{id: "", vendor: "", want: MfgUnknown},
	}
	for _, c := range cases {
		got := ManufacturerNameFromID(c.id, c.vendor)
		if got != c.want {
			t.Fatalf("ManufacturerNameFromID(%q,%q)=%q want %q", c.id, c.vendor, got, c.want)
		}
	}
}

func TestNormalizeFillsDefaults(t *testing.T) {
	d := Device{ManufacturerID: "IFX"}
	Normalize(&d)
	if d.SpecVersion != SpecUnknown {
		t.Fatalf("spec=%q", d.SpecVersion)
	}
	if d.ManufacturerName != MfgInfineon {
		t.Fatalf("mfg=%q", d.ManufacturerName)
	}
}

func TestAnnotateLegacyTPM12Risk(t *testing.T) {
	d := Device{SpecVersion: SpecTPM12, IsActive: true, IsOwned: true}
	Annotate(&d)
	if !d.IsLegacyTPM12Risk {
		t.Fatal("TPM 1.2 must flag legacy risk")
	}
}

func TestAnnotateDisabledRisk(t *testing.T) {
	d := Device{SpecVersion: SpecTPM20}
	Annotate(&d)
	if !d.IsDisabledRisk {
		t.Fatal("inactive TPM must flag disabled risk")
	}
}

func TestAnnotateUnownedRisk(t *testing.T) {
	d := Device{SpecVersion: SpecTPM20, IsActive: true}
	Annotate(&d)
	if !d.IsUnownedRisk {
		t.Fatal("TPM 2.0 without owner must flag unowned risk")
	}
}

func TestSortDevicesDeterministic(t *testing.T) {
	rs := []Device{{Name: "tpm1"}, {Name: "tpm0"}}
	SortDevices(rs)
	if rs[0].Name != "tpm0" || rs[1].Name != "tpm1" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Device
}

func (f fakeSource) Enumerate(_ context.Context) ([]Device, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	rows := []Device{{Name: "tpm0", SpecVersion: SpecTPM20, IsActive: true, ManufacturerID: "INTC"}}
	got, err := NewCollectorWith(fakeSource{rows: rows}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got[0].ManufacturerName != MfgIntelPTT {
		t.Fatalf("mfg=%q", got[0].ManufacturerName)
	}
	if !got[0].IsUnownedRisk {
		t.Fatal("unowned risk missing")
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("tpm fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "tpmdevices" {
		t.Fatal("name drift")
	}
}
