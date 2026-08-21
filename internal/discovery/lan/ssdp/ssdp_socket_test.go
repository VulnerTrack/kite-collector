package ssdp

import (
	"context"
	"net"
	"testing"
)

func TestNewAndName(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.Name(); got != "ssdp" {
		t.Fatalf("Name=%q, want ssdp", got)
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

// An allowlist selecting no interfaces makes Discover a fast, quiet no-op.
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
