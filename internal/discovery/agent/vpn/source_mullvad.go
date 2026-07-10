package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// mullvadCollector reads Mullvad VPN's persisted settings from
// settings.json. The daemon stores tunnel-protocol selection,
// auto-connect, allow-LAN, kill-switch state and (depending on
// version) the obfuscated WireGuard private key. We decode the
// audit-relevant subset; unknown fields are tolerated.
//
// Path layout varies by OS — Linux uses /etc, macOS uses
// /Library/Application Support, Windows uses %ProgramData%.
type mullvadCollector struct {
	readFile      func(string) ([]byte, error)
	stat          func(string) (os.FileInfo, error)
	settingsPaths []string
}

// NewMullvadCollector returns the default Mullvad collector.
func NewMullvadCollector() Collector {
	return &mullvadCollector{
		settingsPaths: []string{
			"/etc/mullvad-vpn/settings.json",
			"/var/cache/mullvad-vpn/settings.json",
			"/Library/Caches/mullvad-vpn/settings.json",
			"/Library/Application Support/Mullvad VPN/settings.json",
			`C:\ProgramData\Mullvad VPN\settings.json`,
		},
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed well-known paths
		stat:     func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
}

func (c *mullvadCollector) Name() string { return "mullvad-settings" }

// mullvadTunnelOptions mirrors the tunnel_options sub-document. Pulled
// out as a named type so govet's fieldalignment can be satisfied per
// sub-struct without nesting churn in the parent type.
type mullvadTunnelOptions struct {
	Wireguard struct {
		MTU                   *int `json:"mtu"`
		RotationIntervalHours *int `json:"rotation_interval"`
	} `json:"wireguard"`
	OpenVPN struct {
		Port     *int   `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"openvpn"`
	DNSOptions struct {
		State         string `json:"state"`
		CustomOptions struct {
			Addresses []string `json:"addresses"`
		} `json:"custom_options"`
		DefaultOptions struct {
			BlockAds      bool `json:"block_ads"`
			BlockTrackers bool `json:"block_trackers"`
			BlockMalware  bool `json:"block_malware"`
		} `json:"default_options"`
	} `json:"dns_options"`
	Generic struct {
		EnableIPv6 bool `json:"enable_ipv6"`
	} `json:"generic"`
}

// mullvadSettings mirrors the JSON shape we care about. Mullvad's
// schema evolves between releases; we only pull stable top-level
// fields that have been present since 2022.
type mullvadSettings struct {
	RelaySettings         json.RawMessage      `json:"relay_settings"`
	AccountHistory        []string             `json:"account_history"`
	TunnelOptions         mullvadTunnelOptions `json:"tunnel_options"`
	AutoConnect           bool                 `json:"auto_connect"`
	AllowLAN              bool                 `json:"allow_lan"`
	BlockWhenDisconnected bool                 `json:"block_when_disconnected"`
	ShowBetaReleases      bool                 `json:"show_beta_releases"`
}

func (c *mullvadCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	for _, path := range c.settingsPaths {
		if _, err := c.stat(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				continue
			}
			continue
		}
		data, err := c.readFile(path)
		if err != nil {
			continue
		}
		p, ok := profileFromMullvadSettings(data)
		if !ok {
			continue
		}
		p.ConfigPath = path
		return []Profile{p}, nil
	}
	return []Profile{}, nil
}

// profileFromMullvadSettings is pure for testability — no IO.
func profileFromMullvadSettings(raw []byte) (Profile, bool) {
	var s mullvadSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return Profile{}, false
	}
	p := Profile{
		Type:        TypeMullvad,
		Name:        "mullvad",
		Protocol:    "wireguard", // Mullvad defaults to WireGuard in modern versions
		Enabled:     true,
		AutoConnect: s.AutoConnect,
		// account_history non-empty ⇒ the daemon holds a Mullvad
		// account token on disk, functionally equivalent to a
		// private credential for CWE-321 purposes.
		PrivateKeyPresent: len(s.AccountHistory) > 0,
		// Mullvad is by design a full-tunnel exit VPN — every
		// install routes 0.0.0.0/0 through the relay.
		IsFullTunnel:  true,
		RoutedSubnets: []string{"0.0.0.0/0", "::/0"},
	}
	if s.TunnelOptions.OpenVPN.Protocol != "" {
		// Operator explicitly chose OpenVPN over WireGuard.
		p.Protocol = strings.ToLower(strings.TrimSpace(s.TunnelOptions.OpenVPN.Protocol))
		if s.TunnelOptions.OpenVPN.Port != nil {
			p.Port = *s.TunnelOptions.OpenVPN.Port
		}
	}
	if s.TunnelOptions.Wireguard.MTU != nil {
		p.MTU = *s.TunnelOptions.Wireguard.MTU
	}
	switch {
	case len(s.TunnelOptions.DNSOptions.CustomOptions.Addresses) > 0:
		p.DNSServers = append(p.DNSServers, s.TunnelOptions.DNSOptions.CustomOptions.Addresses...)
	case s.TunnelOptions.DNSOptions.DefaultOptions.BlockAds ||
		s.TunnelOptions.DNSOptions.DefaultOptions.BlockTrackers ||
		s.TunnelOptions.DNSOptions.DefaultOptions.BlockMalware:
		// Mullvad's content-blocking resolver — surface as marker.
		p.DNSServers = []string{"mullvad-content-block"}
	}
	sortStrings(p.DNSServers)
	return p, true
}
