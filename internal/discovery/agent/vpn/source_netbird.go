package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// netbirdCollector reads NetBird's persisted client config from
// /etc/netbird/config.json (Linux). NetBird stores the management
// URL, the device key (or its file path) and protocol settings as a
// single JSON document written by the netbird daemon after
// `netbird up` succeeds. We only decode the audit-relevant subset so
// upstream additions cannot break our parser.
//
// Audit signals captured:
//   - private_key_present ← PrivateKey field is non-empty
//   - auto_connect ← config exists ⇒ the daemon rejoins the mesh
//     on boot (NetBird is daemon-managed via systemd/launchd)
//   - endpoint ← ManagementURL (the SaaS or self-hosted control plane)
type netbirdCollector struct {
	readFile   func(string) ([]byte, error)
	stat       func(string) (os.FileInfo, error)
	configPath string
}

// NewNetBirdCollector returns the default NetBird collector.
func NewNetBirdCollector() Collector {
	return &netbirdCollector{
		configPath: "/etc/netbird/config.json",
		readFile:   func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
		stat:       func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
}

func (c *netbirdCollector) Name() string { return "netbird-config" }

// netbirdConfig is the JSON shape we read from config.json.
type netbirdConfig struct {
	PrivateKey           string   `json:"PrivateKey"`
	ManagementURL        string   `json:"ManagementURL"`
	AdminURL             string   `json:"AdminURL"`
	WgIface              string   `json:"WgIface"`
	DNSResolverAddress   string   `json:"DNSResolverAddress"`
	CustomDNSAddress     string   `json:"CustomDNSAddress"`
	NATExternalIPs       []string `json:"NATExternalIPs"`
	WgPort               int      `json:"WgPort"`
	DisableAutoConnect   bool     `json:"DisableAutoConnect"`
	RosenpassEnabled     bool     `json:"RosenpassEnabled"`
	BlockInbound         bool     `json:"BlockInbound"`
	DisableClientRoutes  bool     `json:"DisableClientRoutes"`
	DisableServerRoutes  bool     `json:"DisableServerRoutes"`
	DisableDNS           bool     `json:"DisableDNS"`
	DisableFirewall      bool     `json:"DisableFirewall"`
	DisableNotifications bool     `json:"DisableNotifications"`
	NetworkMonitor       bool     `json:"NetworkMonitor"`
}

func (c *netbirdCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	if _, err := c.stat(c.configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Profile{}, nil
		}
		return []Profile{}, nil //nolint:nilerr // unreadable config = not installed for our purposes
	}
	data, err := c.readFile(c.configPath)
	if err != nil {
		return []Profile{}, nil //nolint:nilerr
	}
	var cfg netbirdConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return []Profile{}, nil //nolint:nilerr // malformed json shouldn't fail the chain
	}
	p := profileFromNetBirdConfig(cfg)
	p.ConfigPath = c.configPath
	return []Profile{p}, nil
}

// profileFromNetBirdConfig is pure for testability — it does NOT touch
// disk or perform IO of any kind.
func profileFromNetBirdConfig(cfg netbirdConfig) Profile {
	p := Profile{
		Type:              TypeNetBird,
		Protocol:          "wireguard", // NetBird tunnels WireGuard
		Enabled:           true,
		AutoConnect:       !cfg.DisableAutoConnect,
		PrivateKeyPresent: strings.TrimSpace(cfg.PrivateKey) != "",
		Port:              cfg.WgPort,
		Endpoint:          strings.TrimSpace(cfg.ManagementURL),
	}
	// Name: interface name if present, else "netbird".
	p.Name = strings.TrimSpace(cfg.WgIface)
	if p.Name == "" {
		p.Name = "netbird"
	}
	// DNS: NetBird's split-DNS resolver address. CustomDNSAddress
	// (operator override) wins; DNSResolverAddress is the
	// daemon-injected default.
	switch {
	case strings.TrimSpace(cfg.CustomDNSAddress) != "":
		p.DNSServers = []string{cfg.CustomDNSAddress}
	case strings.TrimSpace(cfg.DNSResolverAddress) != "":
		p.DNSServers = []string{cfg.DNSResolverAddress}
	}
	// NetBird doesn't push static routes to clients in the config —
	// routes come from the controller at runtime. We can still flag
	// "no client routes accepted" as a deliberate split-tunnel
	// posture, and "BlockInbound=false" as the inverse.
	if !cfg.DisableClientRoutes && !cfg.DisableServerRoutes {
		// Both directions accepted ⇒ full mesh participation.
		p.RoutedSubnets = []string{"controller-managed"}
	}
	return p
}
