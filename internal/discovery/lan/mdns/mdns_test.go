package mdns

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestBuildQueryIsValidDNSMessage(t *testing.T) {
	raw, err := buildQuery([]string{"_workstation._tcp.local.", "_airplay._tcp.local."})
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		t.Fatalf("parse start: %v", err)
	}
	if hdr.Response {
		t.Fatalf("query must not have Response bit set")
	}
	var seen []string
	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			t.Fatalf("parse question: %v", err)
		}
		if q.Type != dnsmessage.TypePTR {
			t.Fatalf("expected PTR, got %v", q.Type)
		}
		seen = append(seen, q.Name.String())
	}
	if len(seen) != 2 {
		t.Fatalf("want 2 questions, got %d", len(seen))
	}
}

func TestAbsorbAndClassifyPrinter(t *testing.T) {
	r := &responder{services: map[string]struct{}{}, instances: map[string]struct{}{}}

	// PTR: _services._dns-sd._udp.local → _ipp._tcp.local
	absorbRecord(r, mkPTR(t, "_services._dns-sd._udp.local.", "_ipp._tcp.local."))
	// PTR: _ipp._tcp.local → "Office Printer._ipp._tcp.local"
	absorbRecord(r, mkPTR(t, "_ipp._tcp.local.", "Office Printer._ipp._tcp.local."))
	// SRV: target = office-printer.local
	absorbRecord(r, mkSRV(t, "Office Printer._ipp._tcp.local.", "office-printer.local."))
	// A record
	absorbRecord(r, mkA(t, "office-printer.local.", net.IPv4(192, 168, 1, 50)))

	if r.hostname != "office-printer.local" {
		t.Fatalf("want hostname office-printer.local, got %q", r.hostname)
	}
	if got := classify(r.services); got != model.AssetTypeAppliance {
		t.Fatalf("printer must classify as appliance, got %v", got)
	}
	if _, ok := r.instances["Office Printer._ipp._tcp.local"]; !ok {
		t.Fatalf("instance not absorbed: %+v", r.instances)
	}
	if _, ok := r.services["_ipp._tcp.local"]; !ok {
		t.Fatalf("ipp service not absorbed: %+v", r.services)
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		want     model.AssetType
		services []string
	}{
		{"appliance beats workstation", model.AssetTypeAppliance, []string{"_workstation._tcp.local", "_ipp._tcp.local"}},
		{"iot beats server", model.AssetTypeIOTDevice, []string{"_http._tcp.local", "_airplay._tcp.local"}},
		{"workstation", model.AssetTypeWorkstation, []string{"_workstation._tcp.local"}},
		{"server fallback", model.AssetTypeServer, []string{"_ssh._tcp.local"}},
		{"unknown becomes iot", model.AssetTypeIOTDevice, []string{"_weird._tcp.local"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]struct{}{}
			for _, s := range tc.services {
				m[s] = struct{}{}
			}
			if got := classify(m); got != tc.want {
				t.Fatalf("classify(%v) = %v, want %v", tc.services, got, tc.want)
			}
		})
	}
}

func TestAssetsFromResponders_DeterministicAndKeyed(t *testing.T) {
	in := map[string]*responder{
		"192.168.1.50": {
			addr:      net.IPv4(192, 168, 1, 50),
			hostname:  "office-printer.local",
			services:  map[string]struct{}{"_ipp._tcp.local": {}},
			instances: map[string]struct{}{"Office Printer._ipp._tcp.local": {}},
		},
		"192.168.1.10": {
			addr:      net.IPv4(192, 168, 1, 10),
			hostname:  "",
			services:  map[string]struct{}{"_workstation._tcp.local": {}},
			instances: map[string]struct{}{},
		},
	}
	got := assetsFromResponders(in)
	if len(got) != 2 {
		t.Fatalf("want 2 assets, got %d", len(got))
	}
	// Sorted by ip-key — 192.168.1.10 comes first.
	if got[0].Hostname != "192.168.1.10" {
		t.Fatalf("first asset hostname=%q (no SRV → fall back to addr)", got[0].Hostname)
	}
	if got[0].AssetType != model.AssetTypeWorkstation {
		t.Fatalf("want workstation, got %v", got[0].AssetType)
	}
	if got[1].Hostname != "office-printer.local" {
		t.Fatalf("want office-printer.local, got %q", got[1].Hostname)
	}
	if got[1].AssetType != model.AssetTypeAppliance {
		t.Fatalf("want appliance, got %v", got[1].AssetType)
	}
	if got[1].DiscoverySource != "mdns" {
		t.Fatalf("source not stamped: %q", got[1].DiscoverySource)
	}
	if got[1].NaturalKey == "" {
		t.Fatalf("natural key not computed")
	}
	if !strings.Contains(got[1].Tags, `"_ipp._tcp.local"`) {
		t.Fatalf("tags missing service: %s", got[1].Tags)
	}
}

func TestParseConfigDefaultsAndClamps(t *testing.T) {
	c := parseConfig(map[string]any{
		"listen_window": "999s",
		"query_repeat":  0,
	})
	if c.ListenWindow != maxListenWin {
		t.Fatalf("listen_window not clamped: %v", c.ListenWindow)
	}
	if c.QueryRepeat != 1 {
		t.Fatalf("query_repeat floor not applied: %d", c.QueryRepeat)
	}
	if len(c.ServiceTypes) != len(DefaultServiceTypes) {
		t.Fatalf("expected default service types, got %d", len(c.ServiceTypes))
	}
}

func TestParseMessageRoundTrip(t *testing.T) {
	// Hand-craft a response with one PTR Answer and one A Additional.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	_ = b.StartAnswers()
	name, _ := dnsmessage.NewName("_workstation._tcp.local.")
	target, _ := dnsmessage.NewName("kite-dev._workstation._tcp.local.")
	_ = b.PTRResource(dnsmessage.ResourceHeader{
		Name:  name,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
		TTL:   120,
	}, dnsmessage.PTRResource{PTR: target})
	_ = b.StartAdditionals()
	hostName, _ := dnsmessage.NewName("kite-dev.local.")
	_ = b.AResource(dnsmessage.ResourceHeader{
		Name:  hostName,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   120,
	}, dnsmessage.AResource{A: [4]byte{192, 168, 1, 11}})
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	records, err := parseMessage(raw)
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 records (answer + additional), got %d", len(records))
	}
}

// mkPTR / mkSRV / mkA build a Resource from a payload — used to feed
// absorbRecord directly without going through the full encode/decode path.
func mkPTR(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	o, _ := dnsmessage.NewName(owner)
	tgt, _ := dnsmessage.NewName(target)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: o, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.PTRResource{PTR: tgt},
	}
}

func mkSRV(t *testing.T, owner, target string) dnsmessage.Resource {
	t.Helper()
	o, _ := dnsmessage.NewName(owner)
	tgt, _ := dnsmessage.NewName(target)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: o, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.SRVResource{Target: tgt, Port: 631},
	}
}

func mkA(t *testing.T, owner string, ip net.IP) dnsmessage.Resource {
	t.Helper()
	o, _ := dnsmessage.NewName(owner)
	var a [4]byte
	copy(a[:], ip.To4())
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: o, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: a},
	}
}
