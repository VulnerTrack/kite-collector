package vpn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseZeroTierFullTunnel(t *testing.T) {
	const raw = `allowDNS=1
allowDefault=1
allowGlobal=0
allowManaged=1
`
	p, ok := parseZeroTierConfig(raw)
	if !ok {
		t.Fatal("parse failed")
	}
	if !p.IsFullTunnel {
		t.Fatal("allowDefault=1 must flag full tunnel")
	}
	if !contains(p.RoutedSubnets, "0.0.0.0/0") || !contains(p.RoutedSubnets, "::/0") {
		t.Fatalf("default routes missing: %v", p.RoutedSubnets)
	}
	if len(p.DNSServers) == 0 {
		t.Fatal("allowDNS=1 must surface a DNS marker")
	}
}

func TestParseZeroTierSplitTunnel(t *testing.T) {
	p, ok := parseZeroTierConfig("allowDefault=0\nallowDNS=0\n")
	if !ok {
		t.Fatal("parse failed")
	}
	if p.IsFullTunnel {
		t.Fatal("allowDefault=0 must NOT flag full tunnel")
	}
}

func TestZeroTierCollectorEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	mustWrite(t, filepath.Join(tmp, "a09acf0233abcdef.conf"), "allowDefault=1\n")
	mustWrite(t, filepath.Join(tmp, "b09acf0233000000.conf"), "allowDefault=0\n")
	mustWrite(t, filepath.Join(tmp, "README"), "skip me")

	c := &zerotierCollector{
		networksDir:  tmp,
		identityPath: "/never/exists",
		readFile:     os.ReadFile,
		readDir:      func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
		stat:         func(string) (os.FileInfo, error) { return nil, errors.New("nope") },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(got))
	}
	for _, p := range got {
		if p.Type != TypeZeroTier {
			t.Fatalf("type=%q", p.Type)
		}
		if p.PrivateKeyPresent {
			t.Fatal("stat() should fail → no identity → no private key flag")
		}
	}
}

func TestZeroTierMissingDirReturnsEmpty(t *testing.T) {
	c := &zerotierCollector{
		networksDir: "/does/not/exist",
		readDir:     func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
		stat:        func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

// time import kept for parity with sibling tests.
var _ = time.Now
