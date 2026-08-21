package mdns

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNewAndName(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.Name(); got != "mdns" {
		t.Fatalf("Name=%q, want mdns", got)
	}
}

func TestNetworkFor(t *testing.T) {
	if got := networkFor(net.ParseIP("224.0.0.251")); got != "udp4" {
		t.Fatalf("v4 group → %q, want udp4", got)
	}
	if got := networkFor(net.ParseIP("ff02::fb")); got != "udp6" {
		t.Fatalf("v6 group → %q, want udp6", got)
	}
}

// pickInterfaces filters to up+multicast, never loopback, and an
// allowlist naming nothing yields nothing.
func TestPickInterfaces(t *testing.T) {
	all, err := pickInterfaces(nil)
	if err != nil {
		t.Fatalf("pickInterfaces: %v", err)
	}
	for _, ifi := range all {
		if ifi.Flags&net.FlagLoopback != 0 {
			t.Fatalf("loopback %s must be excluded", ifi.Name)
		}
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			t.Fatalf("%s is not up+multicast", ifi.Name)
		}
	}

	none, err := pickInterfaces([]string{"kite-no-such-iface0"})
	if err != nil {
		t.Fatalf("pickInterfaces filtered: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("nonexistent allowlist must select nothing, got %v", none)
	}
}

// An allowlist selecting no interfaces makes Discover a fast, quiet no-op —
// nil machines, nil error, and no packets on any wire.
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

// buildMDNSResponse constructs a minimal answer-bearing mDNS message.
func buildMDNSResponse(t *testing.T) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	if err := b.StartAnswers(); err != nil {
		t.Fatalf("answers: %v", err)
	}
	name := dnsmessage.MustNewName("kite-host.local.")
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}},
	); err != nil {
		t.Fatalf("a resource: %v", err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return raw
}

// readLoop over loopback: garbage datagrams are skipped, a valid answer
// reaches the recorder with the sender's IP, cancellation ends the loop.
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
		res dnsmessage.Resource
		src net.IP
	}
	got := make(chan hit, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		readLoop(ctx, recv, func(r dnsmessage.Resource, src net.IP) { got <- hit{r, src} })
	}()

	dst := recv.LocalAddr().(*net.UDPAddr)
	if _, err := send.WriteToUDP([]byte{0x01, 0x02}, dst); err != nil {
		t.Fatalf("send garbage: %v", err)
	}
	if _, err := send.WriteToUDP(buildMDNSResponse(t), dst); err != nil {
		t.Fatalf("send response: %v", err)
	}

	select {
	case h := <-got:
		if h.res.Header.Name.String() != "kite-host.local." {
			t.Fatalf("name=%q", h.res.Header.Name.String())
		}
		if h.res.Header.Type != dnsmessage.TypeA {
			t.Fatalf("type=%v, want A", h.res.Header.Type)
		}
		if !h.src.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("src=%v, want 127.0.0.1", h.src)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop never delivered the valid answer")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readLoop did not exit on cancellation")
	}
}
