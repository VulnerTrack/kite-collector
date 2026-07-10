package vpn

import (
	"context"
	"fmt"
	"os"
)

// vendorPresenceCollector emits a single Profile when any of a known
// set of installation paths exists on disk. Used for commercial /
// closed-source VPN clients whose state lives in proprietary formats
// we don't fully parse (binary blobs, encrypted plists, registry).
//
// Detection is *evidence of installation*, not connection state.
// Knowing the client is on the host is itself useful — it widens
// the asset's egress-tunnel surface area regardless of whether
// the user is currently connected.
//
// AutoConnect defaults to true because most enterprise endpoints are
// MDM-pushed with auto-connect enabled; operators tune per-collector
// when they have better information.
type vendorPresenceCollector struct {
	stat        func(string) (os.FileInfo, error)
	name        string
	vpnType     Type
	protocol    string // "tls", "ipsec", "wireguard", "" if unknown
	paths       []string
	autoConnect bool
}

func newVendorPresence(name string, t Type, protocol string, autoConnect bool, paths []string) *vendorPresenceCollector {
	return &vendorPresenceCollector{
		name:        name,
		vpnType:     t,
		protocol:    protocol,
		autoConnect: autoConnect,
		paths:       paths,
		stat:        func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
}

func (c *vendorPresenceCollector) Name() string { return c.name }

func (c *vendorPresenceCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	for _, path := range c.paths {
		if _, err := c.stat(path); err == nil {
			return []Profile{{
				Type:        c.vpnType,
				Name:        string(c.vpnType),
				ConfigPath:  path,
				Protocol:    c.protocol,
				Enabled:     true,
				AutoConnect: c.autoConnect,
			}}, nil
		}
	}
	return []Profile{}, nil
}

// NewGlobalProtectCollector detects Palo Alto Networks GlobalProtect
// agent installation. GlobalProtect tunnels TLS (SSL-VPN) and
// optionally IPSec — we report "tls" as the canonical protocol since
// every install supports it.
//
// Paths cover macOS plist (system-wide), Linux daemon install dir,
// and the Windows ProgramData log path written by PanGPS.exe.
func NewGlobalProtectCollector() Collector {
	return newVendorPresence("globalprotect-presence", TypeGlobalProtect, "tls", true, []string{
		"/Library/Preferences/com.paloaltonetworks.GlobalProtect.client.xml",
		"/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist",
		"/opt/paloaltonetworks/globalprotect",
		"/Applications/GlobalProtect.app",
		`C:\ProgramData\Palo Alto Networks\GlobalProtect\PanGPS.log`,
		`C:\Program Files\Palo Alto Networks\GlobalProtect`,
	})
}

// NewFortinetCollector detects Fortinet FortiClient / FortiClient VPN.
// FortiClient supports SSL-VPN and IPSec; "tls" again covers the
// default mode that ships with every install.
func NewFortinetCollector() Collector {
	return newVendorPresence("forticlient-presence", TypeFortinet, "tls", true, []string{
		"/Library/Application Support/Fortinet",
		"/Applications/FortiClient.app",
		"/opt/forticlient",
		"/etc/forticlient",
		`C:\Program Files\Fortinet\FortiClient`,
		`C:\ProgramData\Fortinet`,
	})
}

// NewCheckPointCollector detects Check Point Remote Secure Access
// client (formerly Endpoint Security VPN / Mobile Access). Tunnels
// IPSec / SSL depending on the corporate policy.
func NewCheckPointCollector() Collector {
	return newVendorPresence("checkpoint-presence", TypeCheckPoint, "ipsec", true, []string{
		"/Library/Application Support/Checkpoint",
		"/Applications/Check Point Endpoint Security.app",
		"/Applications/Endpoint Security VPN.app",
		"/opt/CPshrd-R*",
		"/etc/cp.macro",
		`C:\Program Files (x86)\CheckPoint\Endpoint Connect`,
		`C:\Program Files (x86)\CheckPoint`,
	})
}

// NewDirectAccessCollector detects Microsoft DirectAccess client
// configuration. DirectAccess is Windows-only and provisioned via
// Group Policy; presence of the registry-mirrored configuration in
// %ProgramData% is the most portable signal we can stat from a
// non-Windows host running these checks against a mounted volume.
//
// Linux/macOS paths included for completeness — they always miss,
// which keeps the collector silent on those platforms.
func NewDirectAccessCollector() Collector {
	return newVendorPresence("directaccess-presence", TypeDirectAccess, "ipsec", true, []string{
		`C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk`,
		`C:\Windows\System32\drivers\etc\hosts.ics`,
		`C:\ProgramData\Microsoft\Network\DirectAccess`,
	})
}

// NewNordLayerCollector detects NordLayer (formerly NordVPN Teams)
// installation. NordLayer uses NordLynx (WireGuard) by default and
// auto-reconnects via daemon.
func NewNordLayerCollector() Collector {
	return newVendorPresence("nordlayer-presence", TypeNordLayer, "wireguard", true, []string{
		"/Applications/NordLayer.app",
		"/var/lib/nordlayer",
		"/etc/nordlayer",
		`C:\Program Files\NordLayer`,
		`C:\ProgramData\NordLayer`,
	})
}

// NewProtonVPNCollector detects the Proton VPN client (including the
// "Proton VPN for Business" variant which shares the same daemon and
// settings store). Default protocol is WireGuard; OpenVPN is also
// available but the daemon controls selection.
func NewProtonVPNCollector() Collector {
	return newVendorPresence("protonvpn-presence", TypeProtonVPN, "wireguard", true, []string{
		"/Applications/Proton VPN.app",
		"/Applications/ProtonVPN.app",
		"/etc/protonvpn",
		"/var/lib/protonvpn",
		`C:\Program Files\Proton\VPN`,
		`C:\Program Files\Proton VPN`,
		`C:\Users\Public\AppData\Local\Proton\Proton VPN`,
	})
}
