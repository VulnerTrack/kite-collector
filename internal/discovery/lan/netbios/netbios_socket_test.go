package netbios

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewAndName(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.Name(); got != "netbios" {
		t.Fatalf("Name=%q, want netbios", got)
	}
}

// enableBroadcast sets SO_BROADCAST on a real (loopback-bound) socket —
// the only way to cover the fd-level sockopt without mocking syscalls.
func TestEnableBroadcast(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := enableBroadcast(conn); err != nil {
		t.Fatalf("enableBroadcast on a live UDP socket must succeed: %v", err)
	}
}

// readLoop drains loopback datagrams: garbage is skipped, a valid NBSTAT
// response reaches the recorder exactly once, and context cancellation
// ends the loop.
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

	got := make(chan responder, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		readLoop(ctx, recv, func(r responder) { got <- r })
	}()

	dst := recv.LocalAddr().(*net.UDPAddr)
	if _, err := send.WriteToUDP([]byte("not-a-netbios-packet"), dst); err != nil {
		t.Fatalf("send garbage: %v", err)
	}
	if _, err := send.WriteToUDP(buildSyntheticNBSTATResponse(t), dst); err != nil {
		t.Fatalf("send response: %v", err)
	}

	select {
	case r := <-got:
		if r.machine != "KITE-DEV" {
			t.Fatalf("machine=%q, want KITE-DEV", r.machine)
		}
		if r.addr.String() != "127.0.0.1" {
			t.Fatalf("addr=%s, want 127.0.0.1", r.addr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop never delivered the valid NBSTAT response")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("readLoop did not exit on context cancellation")
	}
}

// No destinations (broadcast off, no explicit targets) is a configured-off
// no-op: nil machines, nil error, no sockets held open past return.
func TestDiscover_NoTargetsSkips(t *testing.T) {
	s := New()
	machines, err := s.Discover(context.Background(), map[string]any{
		"no_broadcast":  true,
		"listen_window": "100ms",
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if machines != nil {
		t.Fatalf("machines=%v, want nil for a no-target config", machines)
	}
}
