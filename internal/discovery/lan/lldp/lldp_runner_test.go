package lldp

import (
	"context"
	"strings"
	"testing"
)

func TestNewAndName(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.Name(); got != "lldp" {
		t.Fatalf("Name=%q, want lldp", got)
	}
	if s.run == nil || s.lookPath == nil {
		t.Fatal("New must wire the default runner and lookPath seams")
	}
}

// defaultRunner is a plain exec: stdout captured on success, a wrapped
// error naming the binary on failure.
func TestDefaultRunner(t *testing.T) {
	out, err := defaultRunner(context.Background(), "sh", "-c", "echo lldp-ok")
	if err != nil {
		t.Fatalf("defaultRunner success path: %v", err)
	}
	if strings.TrimSpace(string(out)) != "lldp-ok" {
		t.Fatalf("out=%q", out)
	}

	_, err = defaultRunner(context.Background(), "/no/such/kite-binary")
	if err == nil {
		t.Fatal("missing binary must error")
	}
	if !strings.Contains(err.Error(), "/no/such/kite-binary") {
		t.Fatalf("error must name the binary: %v", err)
	}
}
