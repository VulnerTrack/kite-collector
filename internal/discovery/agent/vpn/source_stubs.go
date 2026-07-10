package vpn

import "context"

// Stubs for VPN technologies not yet wired.

// NewIPSecCollector returns a stub IPSec / strongSwan collector.
//
// TODO(cdms-iter): parse /etc/ipsec.conf + /etc/strongswan/swanctl/
// (modern strongSwan). For Libreswan: /etc/ipsec.d/. For both, query
// `ipsec statusall` / `swanctl --list-sas` for runtime state.
func NewIPSecCollector() Collector { return sourceStub{name: "ipsec-stub"} }

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
