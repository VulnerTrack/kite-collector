package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"testing"
)

const tsJSONFullTunnel = `{
  "Version": "1.96.4",
  "TUN": true,
  "BackendState": "Running",
  "HaveNodeKey": true,
  "Self": {
    "HostName": "cest",
    "DNSName": "cest.tail1234.ts.net.",
    "OS": "linux",
    "PublicKey": "nodekey:abc",
    "TailscaleIPs": ["100.64.0.1", "fd7a::1"],
    "PrimaryRoutes": [],
    "AllowedIPs": ["100.64.0.1/32"],
    "Relay": "lax",
    "CurAddr": "",
    "UserID": 100,
    "Online": true,
    "ExitNode": false,
    "ExitNodeOption": false
  },
  "Peer": {
    "x": { "HostName": "exit-node", "DNSName": "exit-node.tail1234.ts.net.", "UserID": 100, "ExitNode": true },
    "y": { "HostName": "shared-prod-db", "DNSName": "shared-prod-db.other.ts.net.", "UserID": 999, "ExitNode": false }
  },
  "CurrentTailnet": {
    "Name": "example.com",
    "MagicDNSSuffix": "tail1234.ts.net",
    "MagicDNSEnabled": true
  }
}`

const tsJSONSubnetRouter = `{
  "Version": "1.96.4",
  "BackendState": "Running",
  "HaveNodeKey": true,
  "Self": {
    "HostName": "router",
    "DNSName": "router.ts.net.",
    "OS": "linux",
    "TailscaleIPs": ["100.64.0.2"],
    "PrimaryRoutes": ["10.0.0.0/16", "192.168.42.0/24"],
    "AllowedIPs": ["100.64.0.2/32"],
    "Relay": "sfo",
    "CurAddr": "203.0.113.5:41641",
    "Online": true
  }
}`

const tsJSONStopped = `{
  "BackendState": "Stopped",
  "HaveNodeKey": false,
  "Self": { "HostName": "h", "Online": false }
}`

func TestProfileFromStatusFullTunnelViaExitPeer(t *testing.T) {
	var st tsStatus
	if err := json.Unmarshal([]byte(tsJSONFullTunnel), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := profileFromStatus(st)

	if p.Type != TypeTailscale {
		t.Fatalf("type=%q", p.Type)
	}
	if !p.IsFullTunnel {
		t.Fatal("active exit-node peer must flag full tunnel")
	}
	if !contains(p.RoutedSubnets, "0.0.0.0/0") || !contains(p.RoutedSubnets, "::/0") {
		t.Fatalf("default routes missing: %v", p.RoutedSubnets)
	}
	if !p.PrivateKeyPresent {
		t.Fatal("HaveNodeKey=true → private_key_present")
	}
	if !p.Enabled {
		t.Fatal("BackendState=Running + Online → enabled")
	}
	if !p.AutoConnect {
		t.Fatal("tailscaled auto-connects via daemon")
	}
	if p.Protocol != "wireguard" {
		t.Fatalf("proto=%q", p.Protocol)
	}
	if p.Endpoint != "derp:lax" {
		t.Fatalf("endpoint=%q (CurAddr empty → derp relay)", p.Endpoint)
	}
	if p.Name != "cest.tail1234.ts.net" {
		t.Fatalf("name=%q", p.Name)
	}
	if len(p.DNSServers) != 1 || p.DNSServers[0] != "magicdns:tail1234.ts.net" {
		t.Fatalf("dns=%v", p.DNSServers)
	}
}

func TestProfileFromStatusFlagsSharedPeer(t *testing.T) {
	var st tsStatus
	if err := json.Unmarshal([]byte(tsJSONFullTunnel), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := profileFromStatus(st)

	// peer "x" matches Self.UserID (100) → not shared; peer "y" has
	// UserID=999 → shared INTO this tailnet view by another user.
	if len(p.SharedPeers) != 1 {
		t.Fatalf("want exactly 1 shared peer, got %v", p.SharedPeers)
	}
	if p.SharedPeers[0] != "shared-prod-db.other.ts.net" {
		t.Fatalf("shared peer dns name=%q", p.SharedPeers[0])
	}
}

func TestSharedPeersZeroWhenSelfUserIDUnknown(t *testing.T) {
	// If we can't tell who Self belongs to, we can't reliably classify
	// peers — better to suppress than to misfire.
	st := tsStatus{
		Self: tsSelf{UserID: 0},
		Peer: map[string]tsPeer{"a": {UserID: 999, DNSName: "x."}},
	}
	if got := sharedPeers(st); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestProfileFromStatusSubnetRouter(t *testing.T) {
	var st tsStatus
	if err := json.Unmarshal([]byte(tsJSONSubnetRouter), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := profileFromStatus(st)

	if p.IsFullTunnel {
		t.Fatal("subnet router with scoped routes must NOT be full tunnel")
	}
	if p.Endpoint != "203.0.113.5:41641" {
		t.Fatalf("endpoint=%q (CurAddr present → direct)", p.Endpoint)
	}
	if !contains(p.RoutedSubnets, "10.0.0.0/16") || !contains(p.RoutedSubnets, "192.168.42.0/24") {
		t.Fatalf("subnets=%v", p.RoutedSubnets)
	}
}

func TestTailscaleCollectorWithFakeRunner(t *testing.T) {
	c := &tailscaleCollector{
		run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte(tsJSONFullTunnel), nil
		},
		lookPath: func(string) (string, error) { return "/usr/bin/tailscale", nil },
		binary:   "tailscale",
		timeout:  0, // ctx.WithTimeout(0) still returns immediately-cancelable ctx but fake runner ignores it
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 profile, got %d", len(got))
	}
	if got[0].ConfigPath != "/usr/bin/tailscale" {
		t.Fatalf("config_path=%q (should be resolved binary)", got[0].ConfigPath)
	}
}

func TestTailscaleCollectorBinaryMissing(t *testing.T) {
	c := &tailscaleCollector{
		run:      func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("never called") },
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		binary:   "tailscale",
		// No state files configured → empty result (clean miss).
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing binary must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

func TestTailscaleCollectorDaemonStoppedFallsBackToStateFile(t *testing.T) {
	// Create a fake state file; daemon path fails, fallback should
	// produce an "enrolled but offline" profile.
	tmp := t.TempDir()
	statePath := tmp + "/tailscaled.state"
	if err := writeFileOrFail(t, statePath, "fake-state"); err != nil {
		t.Fatal(err)
	}
	c := &tailscaleCollector{
		run:        func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("daemon down") },
		lookPath:   func(string) (string, error) { return "/usr/bin/tailscale", nil },
		binary:     "tailscale",
		stateFiles: []string{statePath},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 fallback profile, got %d", len(got))
	}
	if got[0].Enabled {
		t.Fatal("daemon-down profile must NOT be Enabled")
	}
	if !got[0].PrivateKeyPresent {
		t.Fatal("state-file presence implies node key on disk")
	}
	if got[0].ConfigPath != statePath {
		t.Fatalf("config_path=%q want %q", got[0].ConfigPath, statePath)
	}
}

func TestProfileFromStatusStopped(t *testing.T) {
	var st tsStatus
	if err := json.Unmarshal([]byte(tsJSONStopped), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := profileFromStatus(st)
	if p.Enabled {
		t.Fatal("BackendState=Stopped must not be Enabled")
	}
	if p.PrivateKeyPresent {
		t.Fatal("HaveNodeKey=false must not flag private key")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func writeFileOrFail(t *testing.T, path, body string) error {
	t.Helper()
	mustWrite(t, path, body)
	return nil
}
