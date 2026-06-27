package blockdevices

import (
	"context"
	"errors"
	"testing"
)

func TestBusFromName(t *testing.T) {
	cases := map[string]Bus{
		"sda":     BusSCSI,
		"sr0":     BusSCSI,
		"nvme0n1": BusNVMe,
		"loop0":   BusLoop,
		"dm-0":    BusDM,
		"md0":     BusMD,
		"zram0":   BusZram,
		"rbd0":    BusRBD,
		"vda":     BusVirtio,
		"xvda":    BusXenBlk,
		"mmcblk0": BusMMC,
		"fd0":     BusFloppy,
		"nbd0":    BusNBD,
		"random":  BusUnknown,
	}
	for in, want := range cases {
		if got := BusFromName(in); got != want {
			t.Fatalf("BusFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDeriveMediaType(t *testing.T) {
	cases := []struct {
		bus        Bus
		want       MediaType
		rotational bool
		remov      bool
	}{
		{bus: BusNVMe, want: MediaNVMeSSD},
		{bus: BusLoop, want: MediaLoop},
		{bus: BusZram, want: MediaVirtual},
		{bus: BusDM, want: MediaVirtual},
		{bus: BusUSB, want: MediaRemovable},
		{bus: BusMMC, want: MediaRemovable},
		{bus: BusSATA, want: MediaHDD, rotational: true},
		{bus: BusSATA, want: MediaSSD},
		{bus: BusSCSI, want: MediaRemovable, remov: true},
		{bus: BusUnknown, want: MediaUnknown},
	}
	for _, c := range cases {
		got := DeriveMediaType(c.bus, c.rotational, c.remov)
		if got != c.want {
			t.Fatalf("DeriveMediaType(%q,rot=%v,rem=%v)=%q want %q",
				c.bus, c.rotational, c.remov, got, c.want)
		}
	}
}

func TestAnnotateUnencryptedRemovableRisk(t *testing.T) {
	d := Device{Bus: BusUSB, IsRemovable: true}
	Normalize(&d)
	Annotate(&d)
	if d.MediaType != MediaRemovable {
		t.Fatalf("media=%q", d.MediaType)
	}
	if !d.IsUnencryptedRemovableRisk {
		t.Fatal("removable unencrypted must flag risk")
	}
}

func TestAnnotateNoSMARTRisk(t *testing.T) {
	d := Device{Bus: BusSATA, IsRotational: true}
	Normalize(&d)
	// HasSMART is false because the test bypasses sysfs reading.
	Annotate(&d)
	if !d.IsNoSMARTRisk {
		t.Fatal("HDD without SMART must flag risk")
	}
}

func TestAnnotateHashesSerial(t *testing.T) {
	d := Device{Bus: BusSATA, IsRotational: true}
	d.SetRawSerial("ABC123XYZ")
	Normalize(&d)
	Annotate(&d)
	if d.SerialHash == "" || len(d.SerialHash) != 64 {
		t.Fatalf("serial hash drift: %q", d.SerialHash)
	}
	if d.rawSerial != "" {
		t.Fatalf("raw serial leaked: %q", d.rawSerial)
	}
}

func TestSortDevicesDeterministic(t *testing.T) {
	rs := []Device{{Name: "sdb"}, {Name: "sda"}, {Name: "nvme0n1"}}
	SortDevices(rs)
	if rs[0].Name != "nvme0n1" || rs[1].Name != "sda" || rs[2].Name != "sdb" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Device
}

func (f fakeSource) Enumerate(_ context.Context) ([]Device, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	rows := []Device{
		{Name: "sdb", Bus: BusUSB, IsRemovable: true},
		{Name: "nvme0n1", Bus: BusNVMe, HasSMART: true},
	}
	got, err := NewCollectorWith(fakeSource{rows: rows}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got[0].Name != "nvme0n1" {
		t.Fatalf("sort drift: %+v", got)
	}
	if !got[1].IsUnencryptedRemovableRisk {
		t.Fatalf("removable risk missing: %+v", got[1])
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("blk fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "blockdevices" {
		t.Fatal("name drift")
	}
}
