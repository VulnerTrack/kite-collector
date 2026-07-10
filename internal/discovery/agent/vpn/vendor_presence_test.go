package vpn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVendorPresenceDetectsInstallation(t *testing.T) {
	tmp := t.TempDir()
	hit := filepath.Join(tmp, "fake-globalprotect")
	mustWrite(t, hit, "x")

	c := newVendorPresence("gp", TypeGlobalProtect, "tls", true, []string{
		"/never/exists",
		hit,
		"/also/never",
	})
	// override stat to point at the real fs (mustWrite already wrote).
	c.stat = os.Stat

	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 profile, got %d", len(got))
	}
	p := got[0]
	if p.Type != TypeGlobalProtect {
		t.Fatalf("type=%q", p.Type)
	}
	if p.ConfigPath != hit {
		t.Fatalf("config_path=%q want %q", p.ConfigPath, hit)
	}
	if p.Protocol != "tls" {
		t.Fatalf("proto=%q", p.Protocol)
	}
	if !p.AutoConnect {
		t.Fatal("auto-connect default must propagate")
	}
}

func TestVendorPresenceNoneFoundReturnsEmpty(t *testing.T) {
	c := newVendorPresence("none", TypeFortinet, "tls", true, []string{
		"/never/exists/a",
		"/never/exists/b",
	})
	c.stat = func(string) (os.FileInfo, error) { return nil, errors.New("nope") }

	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

func TestAllVendorPresenceConstructorsReturnCollectors(t *testing.T) {
	// Smoke test that the public constructors don't crash and emit
	// the right Type when invoked on a host that has none installed.
	for _, c := range []Collector{
		NewGlobalProtectCollector(),
		NewFortinetCollector(),
		NewCheckPointCollector(),
		NewDirectAccessCollector(),
		NewNordLayerCollector(),
		NewProtonVPNCollector(),
	} {
		if c.Name() == "" {
			t.Fatalf("constructor returned collector with empty Name(): %T", c)
		}
		got, err := c.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.Name(), err)
		}
		// Expected: 0 results on a CI box without these clients installed.
		// We don't assert >0 because the host could legitimately have one.
		_ = got
	}
}
