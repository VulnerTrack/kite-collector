package vpn

import "context"

// Stubs for VPN technologies not yet wired.

// NewTailscaleCollector returns a stub Tailscale collector.
//
// TODO(cdms-iter): shell out to `tailscale status --json` (works
// without root on the local socket). Pull `Self.IPs`, `Self.Tags`,
// per-peer routes, `ExitNode` (full-tunnel indicator). Falls back to
// reading `/var/lib/tailscale/tailscaled.state` (JSON) when the daemon
// is offline.
func NewTailscaleCollector() Collector { return sourceStub{name: "tailscale-stub"} }

// NewIPSecCollector returns a stub IPSec / strongSwan collector.
//
// TODO(cdms-iter): parse /etc/ipsec.conf + /etc/strongswan/swanctl/
// (modern strongSwan). For Libreswan: /etc/ipsec.d/. For both, query
// `ipsec statusall` / `swanctl --list-sas` for runtime state.
func NewIPSecCollector() Collector { return sourceStub{name: "ipsec-stub"} }

// NewZeroTierCollector returns a stub ZeroTier collector.
//
// TODO(cdms-iter): /var/lib/zerotier-one/networks.d/<network-id>.conf
// gives the joined-network list; `zerotier-cli listnetworks -j` for
// runtime route table.
func NewZeroTierCollector() Collector { return sourceStub{name: "zerotier-stub"} }

// NewNebulaCollector returns a stub Nebula collector.
//
// TODO(cdms-iter): /etc/nebula/config.yml + per-host certs in
// /etc/nebula/host.crt + /etc/nebula/host.key.
func NewNebulaCollector() Collector { return sourceStub{name: "nebula-stub"} }

// NewWindowsBuiltinCollector returns a stub Windows builtin VPN collector.
//
// TODO(cdms-iter): PowerShell `Get-VpnConnection -AllUserConnection`
// and `Get-VpnConnection` for per-user, then map TunnelType (Pptp /
// L2tp / Sstp / Ikev2 / Wireguard) to our Type enum. Or COM via
// `Microsoft.NetworkingService.NetworkingService`.
func NewWindowsBuiltinCollector() Collector { return sourceStub{name: "windows-vpn-stub"} }

// NewMacOSBuiltinCollector returns a stub macOS builtin VPN collector.
//
// TODO(cdms-iter): `scutil --nc list` for runtime profiles, then
// `/Library/Preferences/com.apple.networkextension.plist` and the
// `/var/db/ConfigurationProfiles/Store/` MDM-pushed profiles. Per-user
// `~/Library/Preferences/com.apple.networkextension.plist`.
func NewMacOSBuiltinCollector() Collector { return sourceStub{name: "macos-vpn-stub"} }

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Profile, error) {
	return []Profile{}, nil
}
