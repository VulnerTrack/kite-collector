package wsdiscovery

import (
	"context"
	"net"
	"testing"
	"time"
)

const testProbeMatchEnvelope = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <s:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <a:EndpointReference><a:Address>urn:uuid:test-cam</a:Address></a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:XAddrs>http://192.0.2.9/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>`

func TestNewAndName(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.Name(); got != "wsdiscovery" {
		t.Fatalf("Name=%q, want wsdiscovery", got)
	}
}

func TestNetworkFor(t *testing.T) {
	if got := networkFor(net.ParseIP("239.255.255.250")); got != "udp4" {
		t.Fatalf("v4 group → %q", got)
	}
	if got := networkFor(net.ParseIP("ff02::c")); got != "udp6" {
		t.Fatalf("v6 group → %q", got)
	}
}

func TestPickInterfaces(t *testing.T) {
	all, err := pickInterfaces(nil)
	if err != nil {
		t.Fatalf("pickInterfaces: %v", err)
	}
	for _, ifi := range all {
		if ifi.Flags&net.FlagLoopback != 0 {
			t.Fatalf("loopback %s must be excluded", ifi.Name)
		}
	}
	none, err := pickInterfaces([]string{"kite-no-such-iface0"})
	if err != nil || len(none) != 0 {
		t.Fatalf("nonexistent allowlist: got %v err %v", none, err)
	}
}

func TestDiscover_NoInterfacesSkips(t *testing.T) {
	machines, err := New().Discover(context.Background(), map[string]any{
		"interfaces":    []string{"kite-no-such-iface0"},
		"listen_window": "100ms",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if machines != nil {
		t.Fatalf("machines=%v, want nil", machines)
	}
}

func TestReadLoop_ParsesLoopbackDatagrams(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = recv.Close() }()
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	defer func() { _ = send.Close() }()

	type hit struct {
		pm  probeMatch
		src net.IP
	}
	got := make(chan hit, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		readLoop(ctx, recv, func(pm probeMatch, src net.IP) { got <- hit{pm, src} })
	}()

	dst := recv.LocalAddr().(*net.UDPAddr)
	if _, err := send.WriteToUDP([]byte("<not-xml"), dst); err != nil {
		t.Fatalf("send garbage: %v", err)
	}
	if _, err := send.WriteToUDP([]byte(testProbeMatchEnvelope), dst); err != nil {
		t.Fatalf("send envelope: %v", err)
	}

	select {
	case h := <-got:
		if h.pm.Address != "urn:uuid:test-cam" {
			t.Fatalf("address=%q", h.pm.Address)
		}
		if len(h.pm.XAddrs) != 1 || h.pm.XAddrs[0] != "http://192.0.2.9/onvif/device_service" {
			t.Fatalf("xaddrs=%v", h.pm.XAddrs)
		}
		if !h.src.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("src=%v", h.src)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop never delivered the probe match")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readLoop did not exit on cancellation")
	}
}

func TestAbsorbMergesMatches(t *testing.T) {
	r := &responder{}
	absorb(r, probeMatch{Types: "dn:A", XAddrs: []string{"http://192.0.2.9/svc"}})
	absorb(r, probeMatch{Types: "dn:B", Scopes: "onvif://x", XAddrs: []string{"http://192.0.2.9/svc", "http://192.0.2.10/svc"}})

	if r.hostname != "192.0.2.9" {
		t.Fatalf("hostname=%q, want host of first xaddr", r.hostname)
	}
	if len(r.xaddrs) != 2 {
		t.Fatalf("xaddrs must dedup: %v", r.xaddrs)
	}
	if r.types == "" || r.scopes == "" {
		t.Fatalf("types/scopes must merge: %q %q", r.types, r.scopes)
	}
	if r.lastSeen.IsZero() {
		t.Fatal("lastSeen must be stamped")
	}
}

func TestStringHelpers(t *testing.T) {
	if got := splitWS("  a  b\tc "); len(got) != 3 {
		t.Fatalf("splitWS=%v", got)
	}
	if splitWS("") != nil {
		t.Fatal("empty splitWS must be nil")
	}

	if !sliceContains([]string{"a", "b"}, "b") || sliceContains([]string{"a"}, "z") {
		t.Fatal("sliceContains broken")
	}

	if got := jsonEscape(`plain`); got != "plain" {
		t.Fatalf("no-escape fast path: %q", got)
	}
	if got := jsonEscape(`say "hi" \ bye`); got != `say \"hi\" \\ bye` {
		t.Fatalf("jsonEscape=%q", got)
	}

	if got := toStringSlice([]string{"x"}); len(got) != 1 {
		t.Fatalf("[]string passthrough: %v", got)
	}
	if got := toStringSlice([]any{"a", 7, "b"}); len(got) != 2 {
		t.Fatalf("[]any filters non-strings: %v", got)
	}
	if toStringSlice(nil) != nil || toStringSlice(42) != nil {
		t.Fatal("non-slice inputs must be nil")
	}
}
