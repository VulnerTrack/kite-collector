package pcidevices

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ClassStorage), "storage"},
		{string(ClassNetwork), "network"},
		{string(ClassDisplay), "display"},
		{string(ClassBridge), "bridge"},
		{string(ClassSerialBus), "serial-bus"},
		{string(ClassWireless), "wireless"},
		{string(ClassAccelerator), "accelerator"},
		{string(ClassSignalProc), "signal-processing"},
		{string(ClassNonEssential), "non-essential"},
		{string(ClassCoprocessor), "coprocessor"},
		{string(LinkSpeed2_5), "2.5"},
		{string(LinkSpeed64), "64"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestFormatBDF(t *testing.T) {
	cases := []struct {
		want string
		dom  int
		bus  int
		dev  int
		fn   int
	}{
		{want: "0000:00:00.0", dom: 0, bus: 0, dev: 0, fn: 0},
		{want: "0000:03:00.0", dom: 0, bus: 3, dev: 0, fn: 0},
		{want: "0000:ff:1f.7", dom: 0, bus: 0xff, dev: 0x1f, fn: 7},
		// Domain truncates after 4 hex digits.
		{want: "0000:12:0a.3", dom: 0x10000, bus: 0x12, dev: 0x0a, fn: 3},
	}
	for _, c := range cases {
		got := FormatBDF(c.dom, c.bus, c.dev, c.fn)
		if got != c.want {
			t.Fatalf("FormatBDF(%d,%d,%d,%d)=%q want %q",
				c.dom, c.bus, c.dev, c.fn, got, c.want)
		}
	}
}

func TestClassNameFromCode(t *testing.T) {
	cases := map[string]ClassName{
		"010802": ClassStorage,   // NVMe
		"020000": ClassNetwork,   // Ethernet
		"030000": ClassDisplay,   // VGA
		"060000": ClassBridge,    // Host bridge
		"060400": ClassBridge,    // PCI-PCI bridge
		"0c0330": ClassSerialBus, // xHCI
		"0d8000": ClassWireless,
		"110000": ClassSignalProc,
		"120000": ClassAccelerator,
		"130000": ClassNonEssential,
		"400000": ClassCoprocessor,
		"":       ClassUnknown,
		"ff":     ClassUnknown,
	}
	for code, want := range cases {
		if got := ClassNameFromCode(code); got != want {
			t.Fatalf("ClassNameFromCode(%q)=%q want %q", code, got, want)
		}
	}
}

func TestNormalizeAssignsBDFAndClass(t *testing.T) {
	d := Device{Domain: 0, Bus: 3, DeviceSlot: 0, Function: 0, ClassCode: "010802"}
	Normalize(&d)
	if d.BDF != "0000:03:00.0" {
		t.Fatalf("BDF=%q", d.BDF)
	}
	if d.ClassName != ClassStorage {
		t.Fatalf("class=%q", d.ClassName)
	}
	if !d.IsEndpoint {
		t.Fatal("storage endpoint must flag IsEndpoint")
	}
	if d.IsRootComplex || d.IsPCIBridge {
		t.Fatalf("storage endpoint mis-flagged as bridge/root: %+v", d)
	}
}

func TestNormalizeHostBridge(t *testing.T) {
	d := Device{Bus: 0, ClassCode: "060000"}
	Normalize(&d)
	if !d.IsRootComplex {
		t.Fatal("host bridge on bus 0 must be root complex")
	}
	if !d.IsPCIBridge {
		t.Fatal("host bridge must flag IsPCIBridge")
	}
	if d.IsEndpoint {
		t.Fatal("bridge must NOT be endpoint")
	}
}

func TestNormalizePCIBridge(t *testing.T) {
	d := Device{Bus: 1, ClassCode: "060400"}
	Normalize(&d)
	if d.IsRootComplex {
		t.Fatal("non-zero bus must NOT be root complex")
	}
	if !d.IsPCIBridge {
		t.Fatal("PCI-to-PCI bridge must flag")
	}
}

func TestNormalizeVFIODriverInfersBound(t *testing.T) {
	d := Device{Driver: "vfio-pci", ClassCode: "030000"}
	Normalize(&d)
	if !d.IsVFIOBound {
		t.Fatal("vfio-pci driver must flag IsVFIOBound")
	}
	if d.IsUnbound {
		t.Fatal("device with a driver must NOT be IsUnbound")
	}
}

func TestNormalizeMissingDriverIsUnbound(t *testing.T) {
	d := Device{ClassCode: "020000"}
	Normalize(&d)
	if !d.IsUnbound {
		t.Fatal("missing driver must flag IsUnbound")
	}
}

func TestAnnotateUnboundEndpointRisk(t *testing.T) {
	d := Device{ClassCode: "020000"}
	Normalize(&d)
	Annotate(&d, time.Now())
	if !d.IsUnboundEndpointRisk {
		t.Fatal("unbound endpoint must flag risk")
	}
}

func TestAnnotateVFIOPassthroughRisk(t *testing.T) {
	d := Device{Driver: "vfio-pci", ClassCode: "030000"}
	Normalize(&d)
	Annotate(&d, time.Now())
	if !d.IsVFIOPassthroughRisk {
		t.Fatal("vfio binding must flag passthrough risk")
	}
}

func TestAnnotateThunderboltDMARisk(t *testing.T) {
	d := Device{ClassCode: "020000", Driver: "iwlwifi", IsThunderboltTunneled: true}
	Normalize(&d)
	Annotate(&d, time.Now())
	if !d.IsThunderboltDMARisk {
		t.Fatal("Thunderbolt-tunneled endpoint must flag DMA risk")
	}
}

func TestAnnotateSRIOVActiveRisk(t *testing.T) {
	d := Device{ClassCode: "020000", Driver: "i40e", HasSRIOV: true, NumVFs: 4}
	Normalize(&d)
	Annotate(&d, time.Now())
	if !d.IsSRIOVActiveRisk {
		t.Fatal("PF with VFs > 0 must flag SR-IOV active risk")
	}
}

func TestSortDevicesDeterministic(t *testing.T) {
	rs := []Device{
		{BDF: "0000:03:00.0"},
		{BDF: "0000:00:00.0"},
		{BDF: "0000:01:00.0"},
	}
	SortDevices(rs)
	want := []string{"0000:00:00.0", "0000:01:00.0", "0000:03:00.0"}
	for i, r := range rs {
		if r.BDF != want[i] {
			t.Fatalf("sort drift @%d: %+v", i, rs)
		}
	}
}

// fakeSource lets us drive the Collector without OS access.
type fakeSource struct {
	err  error
	rows []Device
}

func (f fakeSource) Enumerate(_ context.Context) ([]Device, error) {
	return f.rows, f.err
}

func TestCollectorAnnotatesAndSorts(t *testing.T) {
	src := fakeSource{rows: []Device{
		{Domain: 0, Bus: 3, DeviceSlot: 0, Function: 0, ClassCode: "010802"},
		{Domain: 0, Bus: 0, DeviceSlot: 0, Function: 0, ClassCode: "060000"},
		{Domain: 0, Bus: 5, DeviceSlot: 0, Function: 0, ClassCode: "020000", Driver: "vfio-pci"},
	}}
	c := NewCollectorWith(src)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].BDF != "0000:00:00.0" {
		t.Fatalf("order drift: %+v", got)
	}
	if !got[0].IsRootComplex {
		t.Fatalf("root complex missed: %+v", got[0])
	}
	if !got[1].IsEndpoint {
		t.Fatalf("storage endpoint missed: %+v", got[1])
	}
	if !got[2].IsVFIOPassthroughRisk {
		t.Fatalf("vfio risk missed: %+v", got[2])
	}
}

func TestCollectorPropagatesSourceError(t *testing.T) {
	sentinel := errors.New("sysfs read fail")
	c := NewCollectorWith(fakeSource{err: sentinel})
	_, err := c.Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorCapsToMaxRows(t *testing.T) {
	rows := make([]Device, MaxRows+10)
	for i := range rows {
		rows[i] = Device{Domain: 0, Bus: i & 0xff, DeviceSlot: 0, Function: 0, ClassCode: "020000"}
	}
	c := NewCollectorWith(fakeSource{rows: rows})
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxRows {
		t.Fatalf("cap not applied: len=%d", len(got))
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "pcidevices" {
		t.Fatal("collector name drift")
	}
}
