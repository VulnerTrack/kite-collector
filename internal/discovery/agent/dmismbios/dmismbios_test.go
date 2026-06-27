package dmismbios

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestChassisTypeFromSMBIOSCode(t *testing.T) {
	cases := map[int]ChassisType{
		0:    ChassisUnknown,
		3:    ChassisDesktop,
		8:    ChassisLaptop,
		9:    ChassisNotebook,
		17:   ChassisRackMount,
		28:   ChassisBlade,
		30:   ChassisServer,
		35:   ChassisMiniPC,
		36:   ChassisStickPC,
		0x21: ChassisEmbedded,
		0x22: ChassisIoTGateway,
		255:  ChassisOther,
	}
	for in, want := range cases {
		if got := ChassisTypeFromSMBIOSCode(in); got != want {
			t.Fatalf("ChassisTypeFromSMBIOSCode(%d)=%q want %q", in, got, want)
		}
	}
}

func TestDetectHypervisor(t *testing.T) {
	cases := []struct {
		vendor, product, want string
	}{
		{"QEMU", "Standard PC", "qemu"},
		{"VMware, Inc.", "VMware Virtual Platform", "vmware"},
		{"innotek GmbH", "VirtualBox", "virtualbox"},
		{"Xen", "HVM domU", "xen"},
		{"Microsoft Corporation", "Virtual Machine", "hyperv"},
		{"Parallels Software", "Parallels", "parallels"},
		{"BHYVE", "BHYVE", "bhyve"},
		{"Dell Inc.", "PowerEdge R750", ""},
	}
	for _, c := range cases {
		got := DetectHypervisor(c.vendor, c.product, "")
		if got != c.want {
			t.Fatalf("DetectHypervisor(%q,%q)=%q want %q", c.vendor, c.product, got, c.want)
		}
	}
}

func TestParseBIOSAge(t *testing.T) {
	ref := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	cases := map[string]int{
		"06/24/2026":  0,
		"06/24/2025":  365,
		"2024-06-24":  730,
		"":            -1,
		"junk":        -1,
		"Jan 02 2026": int(ref.Sub(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) / (24 * time.Hour)),
	}
	for in, want := range cases {
		if got := ParseBIOSAge(in, ref); got != want {
			t.Fatalf("ParseBIOSAge(%q,%v)=%d want %d", in, ref, got, want)
		}
	}
}

func TestNormalizeDetectsHypervisor(t *testing.T) {
	r := Record{SystemManufacturer: "QEMU"}
	Normalize(&r)
	if !r.IsVirtualized || r.HypervisorHint != "qemu" {
		t.Fatalf("normalize: %+v", r)
	}
}

func TestAnnotateHashesSerialsAndBIOSAge(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	r := Record{
		BIOSReleaseDate: "06/24/2023",
	}
	r.SetRawSerials("S/N12345", "uuid-aaa", "BOARD-1", "CHASSIS-1")
	Annotate(&r, now)
	if r.SystemSerialHash == "" || len(r.SystemSerialHash) != 64 {
		t.Fatalf("system serial hash drift: %q", r.SystemSerialHash)
	}
	if r.SystemUUIDHash == "" {
		t.Fatal("uuid hash missing")
	}
	if r.BoardSerialHash == "" || r.ChassisSerialHash == "" {
		t.Fatal("board/chassis hash missing")
	}
	// 2023-06-24 → 2026-06-24 spans the 2024 leap year → 1096 days.
	if r.BIOSAgeDays != 1096 {
		t.Fatalf("bios age=%d want 1096", r.BIOSAgeDays)
	}
	if !r.IsBIOSStaleRisk {
		t.Fatalf(">730 day bios must flag stale risk: %+v", r)
	}
	if !r.IsRecent {
		t.Fatal("IsRecent must flag")
	}
}

func TestAnnotateClearsRawAfterHash(t *testing.T) {
	r := Record{}
	r.SetRawSerials("S/N", "U", "B", "C")
	Annotate(&r, time.Now())
	// Raw fields are unexported; we re-hash and compare. Calling
	// SetRawSerials with the same values should yield the same
	// hash if Annotate succeeds.
	if r.SystemSerialHash != hashIfNonempty("S/N") {
		t.Fatalf("hash mismatch")
	}
	// Inspect via unexported access (same package).
	if r.rawSystemSerial != "" {
		t.Fatalf("raw serial leaked: %q", r.rawSystemSerial)
	}
}

func TestHashIfNonemptyCaseInsensitive(t *testing.T) {
	a := hashIfNonempty("ABC-123")
	b := hashIfNonempty("abc-123")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if hashIfNonempty("") != "" {
		t.Fatal("empty input must yield empty hash")
	}
}

type fakeSource struct {
	err error
	r   Record
}

func (f fakeSource) Read(_ context.Context) (Record, error) { return f.r, f.err }

func TestCollectorProducesRecord(t *testing.T) {
	r := Record{SystemManufacturer: "VMware, Inc."}
	r.SetRawSerials("VMware-12345", "UUID-AB", "BOARD-1", "CHASSIS-X")
	got, err := NewCollectorWith(fakeSource{r: r}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.HypervisorHint != "vmware" || !got.IsVirtualized {
		t.Fatalf("hypervisor missed: %+v", got)
	}
	if got.SystemSerialHash == "" {
		t.Fatal("serial hash missing")
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("dmi fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
	// The wrapped error should reference the package name.
	if !strings.Contains(err.Error(), "dmismbios") {
		t.Fatalf("err msg=%q", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "dmismbios" {
		t.Fatal("name drift")
	}
}
