package vpn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const nebulaConfigSample = `pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

static_host_map:
  '192.168.100.1': ['lighthouse1.example.com:4242']

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - '192.168.100.1'

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false

listen:
  host: 0.0.0.0
  port: 4242
`

const nebulaLighthouseConfig = `pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/lh.crt
  key: /etc/nebula/lh.key

lighthouse:
  am_lighthouse: true
  interval: 60
`

func TestParseNebulaClientConfig(t *testing.T) {
	p, ok := parseNebulaConfig(nebulaConfigSample)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Type != TypeNebula {
		t.Fatalf("type=%q", p.Type)
	}
	if p.Endpoint != "lighthouse1.example.com:4242" {
		t.Fatalf("endpoint=%q (should be first static_host_map entry)", p.Endpoint)
	}
	if p.Protocol != "udp" {
		t.Fatalf("proto=%q", p.Protocol)
	}
	if p.IsFullTunnel {
		t.Fatal("Nebula is a mesh VPN — must NOT default to full tunnel")
	}
	// parseNebulaConfig stashes the pki.key path in Name for Collect().
	if p.Name != "/etc/nebula/host.key" {
		t.Fatalf("name (key path stash)=%q", p.Name)
	}
}

func TestParseNebulaLighthouseFlag(t *testing.T) {
	p, ok := parseNebulaConfig(nebulaLighthouseConfig)
	if !ok {
		t.Fatal("parse failed")
	}
	if !contains(p.RoutedSubnets, "lighthouse") {
		t.Fatalf("am_lighthouse=true must surface marker, got %v", p.RoutedSubnets)
	}
}

func TestNebulaCollectorPrivateKeyPresenceFromDisk(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "host.key")
	mustWrite(t, keyPath, "fake-key")
	cfgPath := filepath.Join(tmp, "config.yml")
	mustWrite(t, cfgPath, "pki:\n  key: "+keyPath+"\n"+
		"static_host_map:\n  '10.0.0.1': ['lh.example:4242']\n")
	c := &nebulaCollector{
		configPath: cfgPath,
		readFile:   os.ReadFile,
		stat:       func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if !got[0].PrivateKeyPresent {
		t.Fatal("key file exists on disk → private_key_present must be true")
	}
	if got[0].Name != "nebula" {
		t.Fatalf("Collect must reset Name to stable label, got %q", got[0].Name)
	}
}

func TestNebulaMissingConfigReturnsEmpty(t *testing.T) {
	c := &nebulaCollector{
		configPath: "/does/not/exist/config.yml",
		readFile:   func(string) ([]byte, error) { return nil, os.ErrNotExist },
		stat:       func(string) (os.FileInfo, error) { return nil, errors.New("nope") },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing config must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

func TestExtractEndpointShapes(t *testing.T) {
	cases := map[string]string{
		`'192.168.100.1': ['lh.example.com:4242']`: "lh.example.com:4242",
		`192.168.100.1: ["1.2.3.4:4242"]`:          "1.2.3.4:4242",
		`- 1.2.3.4:4242`:                           "", // bare list items go through splitYAMLKV path, no colon-key match
		`foo: bar`:                                 "", // no port pattern
	}
	for in, want := range cases {
		if got := extractEndpoint(in); got != want {
			t.Errorf("extractEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
