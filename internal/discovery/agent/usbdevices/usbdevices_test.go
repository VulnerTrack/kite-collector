package usbdevices

import (
	"context"
	"errors"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ClassHID), "hid"},
		{string(ClassMassStorage), "mass-storage"},
		{string(ClassHub), "hub"},
		{string(ClassSmartCard), "smart-card"},
		{string(ClassVendorSpecific), "vendor-specific"},
		{string(SpeedHigh), "high"},
		{string(SpeedSuperPlus20), "super-plus-20"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: %q want %q", p.got, p.want)
		}
	}
}

func TestClassNameFromCode(t *testing.T) {
	cases := map[string]ClassName{
		"03": ClassHID,
		"08": ClassMassStorage,
		"09": ClassHub,
		"0b": ClassSmartCard,
		"0B": ClassSmartCard,
		"ff": ClassVendorSpecific,
		"":   ClassUnknown,
		"zz": ClassUnknown,
	}
	for in, want := range cases {
		if got := ClassNameFromCode(in); got != want {
			t.Fatalf("ClassNameFromCode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSpeedNameFromMbps(t *testing.T) {
	cases := map[int]SpeedName{
		0:     SpeedNone,
		1:     SpeedLow,
		12:    SpeedFull,
		480:   SpeedHigh,
		5000:  SpeedSuper,
		10000: SpeedSuperPlus,
		20000: SpeedSuperPlus20,
		40000: SpeedUSB4Gen3x2,
		99999: SpeedUnknown,
	}
	for in, want := range cases {
		if got := SpeedNameFromMbps(in); got != want {
			t.Fatalf("SpeedNameFromMbps(%d)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeHubFlag(t *testing.T) {
	d := Device{ClassCode: "09"}
	Normalize(&d)
	if !d.IsHub {
		t.Fatal("class 09 must flag IsHub")
	}
	if !d.IsRootHub {
		t.Fatal("empty PortPath must flag IsRootHub")
	}
	if d.ClassName != ClassHub {
		t.Fatalf("class=%q", d.ClassName)
	}
}

func TestNormalizeHIDInterface(t *testing.T) {
	d := Device{ClassCode: "03"}
	Normalize(&d)
	if !d.HasHIDInterface {
		t.Fatal("HID class must flag interface")
	}
}

func TestAnnotateBadUSBRisk(t *testing.T) {
	d := Device{ClassCode: "03", IsRemovable: true, VendorID: "abcd"}
	Normalize(&d)
	Annotate(&d)
	if !d.IsBadUSBRisk {
		t.Fatal("removable HID = BadUSB risk")
	}
	if d.IsUnknownVendorRisk {
		t.Fatalf("known vendor must NOT flag unknown: %+v", d)
	}
}

func TestAnnotateUnsanctionedStorageRisk(t *testing.T) {
	d := Device{ClassCode: "08", IsRemovable: true, VendorID: "abcd"}
	Normalize(&d)
	Annotate(&d)
	if !d.IsUnsanctionedStorageRisk {
		t.Fatal("removable mass-storage = unsanctioned risk")
	}
}

func TestAnnotateUnknownVendor(t *testing.T) {
	d := Device{ClassCode: "08", VendorID: "0000"}
	Normalize(&d)
	Annotate(&d)
	if !d.IsUnknownVendorRisk {
		t.Fatal("0000 VID = unknown vendor")
	}
}

func TestSortDevicesDeterministic(t *testing.T) {
	rs := []Device{{BusPath: "1-2"}, {BusPath: "1-1"}, {BusPath: "usb1"}}
	SortDevices(rs)
	if rs[0].BusPath != "1-1" || rs[1].BusPath != "1-2" || rs[2].BusPath != "usb1" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Device
}

func (f fakeSource) Enumerate(_ context.Context) ([]Device, error) { return f.rows, f.err }

func TestCollectorAnnotatesAndCaps(t *testing.T) {
	src := fakeSource{rows: []Device{
		{BusPath: "1-1", ClassCode: "09"},
		{BusPath: "1-2", ClassCode: "08", IsRemovable: true, VendorID: "0951"},
	}}
	got, err := NewCollectorWith(src).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[0].IsHub {
		t.Fatal("hub flag missing")
	}
	if !got[1].IsUnsanctionedStorageRisk {
		t.Fatal("removable storage risk missing")
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("usb fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "usbdevices" {
		t.Fatal("name drift")
	}
}
