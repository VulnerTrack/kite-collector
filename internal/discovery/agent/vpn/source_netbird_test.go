package vpn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const netbirdConfigSample = `{
  "PrivateKey": "abc123===",
  "ManagementURL": "https://api.netbird.io:443",
  "AdminURL": "https://app.netbird.io:443",
  "WgIface": "wt0",
  "WgPort": 51820,
  "DisableAutoConnect": false,
  "CustomDNSAddress": "10.0.0.53",
  "DNSResolverAddress": "100.100.100.100",
  "DisableClientRoutes": false,
  "DisableServerRoutes": false
}`

const netbirdMinimalConfig = `{
  "PrivateKey": "",
  "ManagementURL": "https://self-hosted.example.com",
  "DisableAutoConnect": true,
  "DisableClientRoutes": true,
  "DisableServerRoutes": true
}`

func TestProfileFromNetBirdConfigPopulated(t *testing.T) {
	var cfg netbirdConfig
	if err := jsonUnmarshalForTest(netbirdConfigSample, &cfg); err != nil {
		t.Fatal(err)
	}
	p := profileFromNetBirdConfig(cfg)
	if p.Type != TypeNetBird {
		t.Fatalf("type=%q", p.Type)
	}
	if !p.PrivateKeyPresent {
		t.Fatal("non-empty PrivateKey → private_key_present")
	}
	if !p.AutoConnect {
		t.Fatal("DisableAutoConnect=false → auto_connect")
	}
	if p.Endpoint != "https://api.netbird.io:443" {
		t.Fatalf("endpoint=%q", p.Endpoint)
	}
	if p.Port != 51820 {
		t.Fatalf("port=%d", p.Port)
	}
	if p.Name != "wt0" {
		t.Fatalf("name=%q", p.Name)
	}
	if len(p.DNSServers) != 1 || p.DNSServers[0] != "10.0.0.53" {
		t.Fatalf("dns=%v (CustomDNSAddress should win over default)", p.DNSServers)
	}
}

func TestProfileFromNetBirdMinimal(t *testing.T) {
	var cfg netbirdConfig
	if err := jsonUnmarshalForTest(netbirdMinimalConfig, &cfg); err != nil {
		t.Fatal(err)
	}
	p := profileFromNetBirdConfig(cfg)
	if p.PrivateKeyPresent {
		t.Fatal("empty PrivateKey must NOT flag private_key_present")
	}
	if p.AutoConnect {
		t.Fatal("DisableAutoConnect=true must clear auto_connect")
	}
	if p.Name != "netbird" {
		t.Fatalf("name fallback=%q", p.Name)
	}
	if len(p.RoutedSubnets) != 0 {
		t.Fatalf("Disable*Routes=true must produce no synthetic routes, got %v", p.RoutedSubnets)
	}
}

func TestNetBirdCollectorEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	mustWrite(t, cfgPath, netbirdConfigSample)
	c := &netbirdCollector{
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
	if got[0].ConfigPath != cfgPath {
		t.Fatalf("config_path=%q", got[0].ConfigPath)
	}
}

func TestNetBirdMissingConfigReturnsEmpty(t *testing.T) {
	c := &netbirdCollector{
		configPath: "/does/not/exist/config.json",
		stat:       func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing config must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

// jsonUnmarshalForTest wraps encoding/json to keep this test file
// self-contained without re-importing json in every test func.
func jsonUnmarshalForTest(raw string, v any) error {
	return decodeJSON(raw, v)
}
