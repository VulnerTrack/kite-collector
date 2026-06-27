package gpudevices

import (
	"context"
	"errors"
	"testing"
)

func TestVendorFromPCIVendorID(t *testing.T) {
	cases := map[string]Vendor{
		"10de": VendorNVIDIA,
		"1002": VendorAMD,
		"1022": VendorAMD,
		"8086": VendorIntel,
		"106b": VendorApple,
		"15ad": VendorVMware,
		"1234": VendorQEMU,
		"19e5": VendorHuawei,
		"1da3": VendorHabana,
		"":     VendorUnknown,
		"ffff": VendorOther,
	}
	for in, want := range cases {
		if got := VendorFromPCIVendorID(in); got != want {
			t.Fatalf("VendorFromPCIVendorID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDeriveAcceleratorType(t *testing.T) {
	cases := []struct {
		v             Vendor
		driver, model string
		want          AcceleratorType
	}{
		{v: VendorNVIDIA, model: "GeForce RTX 4090", want: TypeDiscreteGPU},
		{v: VendorNVIDIA, model: "NVIDIA H100 80GB HBM3", want: TypeAIAccelerator},
		{v: VendorNVIDIA, model: "Tesla V100", want: TypeAIAccelerator},
		{v: VendorAMD, model: "Radeon RX 7900 XTX", want: TypeDiscreteGPU},
		{v: VendorAMD, model: "AMD Instinct MI300X", want: TypeAIAccelerator},
		{v: VendorIntel, model: "UHD Graphics 770", want: TypeIntegratedGPU},
		{v: VendorIntel, model: "Arc A770", want: TypeDiscreteGPU},
		{v: VendorApple, model: "Apple M2 Max", want: TypeIntegratedGPU},
		{v: VendorVMware, want: TypeVirtualGPU},
		{v: VendorQEMU, want: TypeVirtualGPU},
		{v: VendorHabana, want: TypeAIAccelerator},
		{v: VendorGoogle, model: "TPU v5", want: TypeTPU},
		{v: VendorGoogle, want: TypeAIAccelerator},
		{v: VendorUnknown, want: TypeUnknown},
	}
	for _, c := range cases {
		got := DeriveAcceleratorType(c.v, c.driver, c.model)
		if got != c.want {
			t.Fatalf("DeriveAcceleratorType(%q,%q,%q)=%q want %q",
				c.v, c.driver, c.model, got, c.want)
		}
	}
}

func TestAnnotateVFIOPassthroughRisk(t *testing.T) {
	d := Device{Driver: "vfio-pci"}
	Normalize(&d)
	Annotate(&d)
	if !d.IsPassthrough || !d.IsVFIOPassthroughRisk {
		t.Fatalf("vfio annotation missing: %+v", d)
	}
}

func TestAnnotateAIAcceleratorRisk(t *testing.T) {
	d := Device{Vendor: VendorNVIDIA, Model: "H100 80GB"}
	Normalize(&d)
	Annotate(&d)
	if d.AcceleratorType != TypeAIAccelerator {
		t.Fatalf("type=%q", d.AcceleratorType)
	}
	if !d.IsAIAcceleratorRisk {
		t.Fatal("AI accelerator must flag risk")
	}
}

func TestSortDevicesDeterministic(t *testing.T) {
	rs := []Device{{CardName: "card1"}, {CardName: "card0"}}
	SortDevices(rs)
	if rs[0].CardName != "card0" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Device
}

func (f fakeSource) Enumerate(_ context.Context) ([]Device, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	rows := []Device{{CardName: "card0", VendorID: "10de", Model: "RTX 4090"}}
	got, err := NewCollectorWith(fakeSource{rows: rows}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got[0].Vendor != VendorNVIDIA {
		t.Fatalf("vendor=%q", got[0].Vendor)
	}
	if got[0].AcceleratorType != TypeDiscreteGPU {
		t.Fatalf("type=%q", got[0].AcceleratorType)
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("gpu fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "gpudevices" {
		t.Fatal("name drift")
	}
}
