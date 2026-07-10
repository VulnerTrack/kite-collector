package vpn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const mullvadSettingsJSON = `{
  "relay_settings": {},
  "tunnel_options": {
    "wireguard": { "mtu": 1380 },
    "openvpn": { "protocol": "", "port": null },
    "generic": { "enable_ipv6": false },
    "dns_options": {
      "state": "default",
      "default_options": { "block_ads": true, "block_trackers": true, "block_malware": false },
      "custom_options": { "addresses": [] }
    }
  },
  "account_history": ["1234567890123456"],
  "auto_connect": true,
  "allow_lan": false,
  "block_when_disconnected": true
}`

const mullvadCustomDNSJSON = `{
  "tunnel_options": {
    "wireguard": {},
    "openvpn": { "protocol": "udp", "port": 1194 },
    "dns_options": {
      "custom_options": { "addresses": ["10.0.0.53", "10.0.0.54"] }
    }
  },
  "account_history": [],
  "auto_connect": false
}`

func TestProfileFromMullvadSettingsBlocklist(t *testing.T) {
	p, ok := profileFromMullvadSettings([]byte(mullvadSettingsJSON))
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Type != TypeMullvad {
		t.Fatalf("type=%q", p.Type)
	}
	if !p.IsFullTunnel {
		t.Fatal("Mullvad is exit-VPN — IsFullTunnel must always be true")
	}
	if !p.AutoConnect {
		t.Fatal("auto_connect=true → AutoConnect")
	}
	if !p.PrivateKeyPresent {
		t.Fatal("account_history non-empty → PrivateKeyPresent")
	}
	if p.MTU != 1380 {
		t.Fatalf("mtu=%d", p.MTU)
	}
	if p.Protocol != "wireguard" {
		t.Fatalf("proto=%q (no openvpn override → wireguard)", p.Protocol)
	}
	if len(p.DNSServers) != 1 || p.DNSServers[0] != "mullvad-content-block" {
		t.Fatalf("dns=%v (blocklist enabled → marker)", p.DNSServers)
	}
}

func TestProfileFromMullvadSettingsCustomDNSAndOpenVPN(t *testing.T) {
	p, ok := profileFromMullvadSettings([]byte(mullvadCustomDNSJSON))
	if !ok {
		t.Fatal("parse failed")
	}
	if p.PrivateKeyPresent {
		t.Fatal("empty account_history must NOT flag PrivateKeyPresent")
	}
	if p.AutoConnect {
		t.Fatal("auto_connect=false must clear AutoConnect")
	}
	if p.Protocol != "udp" {
		t.Fatalf("openvpn.protocol=udp must override, got %q", p.Protocol)
	}
	if p.Port != 1194 {
		t.Fatalf("port=%d", p.Port)
	}
	if len(p.DNSServers) != 2 {
		t.Fatalf("custom DNS addresses must surface, got %v", p.DNSServers)
	}
}

func TestProfileFromMullvadMalformed(t *testing.T) {
	if _, ok := profileFromMullvadSettings([]byte(`not-json`)); ok {
		t.Fatal("malformed must return false")
	}
}

func TestMullvadCollectorFindsFirstExistingPath(t *testing.T) {
	tmp := t.TempDir()
	good := filepath.Join(tmp, "settings.json")
	mustWrite(t, good, mullvadSettingsJSON)
	c := &mullvadCollector{
		settingsPaths: []string{
			"/does/not/exist/settings.json",
			good,
		},
		readFile: os.ReadFile,
		stat:     func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].ConfigPath != good {
		t.Fatalf("config_path=%q", got[0].ConfigPath)
	}
}
