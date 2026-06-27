package netinterfaces

import (
	"context"
	"errors"
	"testing"
)

func TestTypeFromName(t *testing.T) {
	cases := map[string]IfaceType{
		"lo":      TypeLoopback,
		"eth0":    TypeEthernet,
		"enp3s0":  TypeEthernet,
		"em1":     TypeEthernet,
		"wlan0":   TypeWifi,
		"wlp3s0":  TypeWifi,
		"wwan0":   TypeCellular,
		"br0":     TypeBridge,
		"docker0": TypeBridge,
		"bond0":   TypeBond,
		"veth1":   TypeVeth,
		"tun0":    TypeTUN,
		"tap0":    TypeTAP,
		"dummy0":  TypeDummy,
		"vxlan1":  TypeVXLAN,
		"geneve0": TypeGeneve,
		"wg0":     TypeWireguard,
		"ovpn0":   TypeOpenVPN,
		"ib0":     TypeInfiniband,
		"can0":    TypeCAN,
		"ppp0":    TypePPP,
		"random":  TypeOther,
	}
	for in, want := range cases {
		if got := TypeFromName(in, ""); got != want {
			t.Fatalf("TypeFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeFlagsPhysicalAndWireless(t *testing.T) {
	cases := []struct {
		iface        string
		wantType     IfaceType
		wantPhys     bool
		wantWireless bool
	}{
		{"eth0", TypeEthernet, true, false},
		{"wlan0", TypeWifi, true, true},
		{"lo", TypeLoopback, false, false},
		{"docker0", TypeBridge, false, false},
		{"veth-abc", TypeVeth, false, false},
		{"wg0", TypeWireguard, false, false},
	}
	for _, c := range cases {
		i := Iface{Iface: c.iface}
		Normalize(&i)
		if i.IfaceType != c.wantType {
			t.Fatalf("%s type=%q want %q", c.iface, i.IfaceType, c.wantType)
		}
		if i.IsPhysical != c.wantPhys {
			t.Fatalf("%s physical=%v want %v", c.iface, i.IsPhysical, c.wantPhys)
		}
		if i.IsWireless != c.wantWireless {
			t.Fatalf("%s wireless=%v want %v", c.iface, i.IsWireless, c.wantWireless)
		}
	}
}

func TestNormalizeFlagsVPNAndContainer(t *testing.T) {
	wg := Iface{Iface: "wg0"}
	Normalize(&wg)
	if !wg.IsVPN {
		t.Fatal("wireguard must flag VPN")
	}
	veth := Iface{Iface: "veth123"}
	Normalize(&veth)
	if !veth.IsContainer {
		t.Fatal("veth must flag container")
	}
}

func TestAnnotateHashesMAC(t *testing.T) {
	i := Iface{Iface: "eth0"}
	i.SetRawMAC("aa:bb:cc:dd:ee:ff")
	Normalize(&i)
	Annotate(&i)
	if i.MACAddressHash == "" || len(i.MACAddressHash) != 64 {
		t.Fatalf("MAC hash drift: %q", i.MACAddressHash)
	}
	if i.OUIHex != "aabbcc" {
		t.Fatalf("OUI=%q", i.OUIHex)
	}
	if i.rawMAC != "" {
		t.Fatalf("raw MAC leaked: %q", i.rawMAC)
	}
}

func TestAnnotatePromiscuousRisk(t *testing.T) {
	i := Iface{Iface: "eth0", IsPromiscuous: true}
	Normalize(&i)
	Annotate(&i)
	if !i.IsPromiscuousRisk {
		t.Fatal("promisc must flag risk")
	}
}

func TestAnnotateNoCarrierRisk(t *testing.T) {
	i := Iface{Iface: "eth0", Operstate: OpUp, Carrier: false}
	Normalize(&i)
	Annotate(&i)
	if !i.IsNoCarrierRisk {
		t.Fatal("physical iface with no carrier (but not down) must flag risk")
	}
}

func TestAnnotateNoCarrierRiskSkipsDown(t *testing.T) {
	i := Iface{Iface: "eth0", Operstate: OpDown, Carrier: false}
	Normalize(&i)
	Annotate(&i)
	if i.IsNoCarrierRisk {
		t.Fatal("Down iface must NOT flag no-carrier risk")
	}
}

func TestAnnotateLowSpeedRisk(t *testing.T) {
	i := Iface{Iface: "eth0", SpeedMbps: 100}
	Normalize(&i)
	Annotate(&i)
	if !i.IsLowSpeedRisk {
		t.Fatal("100 Mb on a Gb-expected interface must flag low-speed risk")
	}
}

func TestSortIfacesDeterministic(t *testing.T) {
	rs := []Iface{{Iface: "wlan0"}, {Iface: "eth0"}, {Iface: "lo"}}
	SortIfaces(rs)
	if rs[0].Iface != "eth0" {
		t.Fatalf("sort drift: %+v", rs)
	}
}

type fakeSource struct {
	err  error
	rows []Iface
}

func (f fakeSource) Enumerate(_ context.Context) ([]Iface, error) { return f.rows, f.err }

func TestCollectorPipeline(t *testing.T) {
	src := fakeSource{rows: []Iface{
		{Iface: "wg0"},
		{Iface: "eth0", SpeedMbps: 100},
	}}
	got, err := NewCollectorWith(src).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got[0].Iface != "eth0" {
		t.Fatalf("sort drift: %+v", got)
	}
	if !got[0].IsLowSpeedRisk {
		t.Fatalf("low speed risk missing: %+v", got[0])
	}
	if !got[1].IsVPN {
		t.Fatalf("VPN flag missing: %+v", got[1])
	}
}

func TestCollectorPropagatesError(t *testing.T) {
	sentinel := errors.New("net fail")
	_, err := NewCollectorWith(fakeSource{err: sentinel}).Collect(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

func TestCollectorName(t *testing.T) {
	if NewCollector().Name() != "netinterfaces" {
		t.Fatal("name drift")
	}
}
