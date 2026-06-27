package firewall

import "context"

// Stubs for engines not yet wired. Each returns empty so the chain can
// call them unconditionally without runtime branches. Replace with a
// real implementation as each lands.

// NewNFTablesCollector returns a stub nftables collector.
//
// TODO(cdms-iter): wire `nft -j list ruleset`. JSON output is cleaner
// than iptables-save's text — likely the next implementation since the
// parser will be a straight json.Unmarshal vs a token-walk.
func NewNFTablesCollector() Collector { return engineStub{name: "nftables-stub"} }

// NewPFCollector returns a stub pf collector (macOS, BSDs).
//
// TODO(cdms-iter): wire `pfctl -s rules`.
func NewPFCollector() Collector { return engineStub{name: "pf-stub"} }

// NewWindowsFirewallCollector returns a stub Windows Firewall collector.
//
// TODO(cdms-iter): wire `Get-NetFirewallRule | ConvertTo-Json -Depth 5`
// via PowerShell, or NetFirewallAPI via Win32 COM.
func NewWindowsFirewallCollector() Collector { return engineStub{name: "windows-firewall-stub"} }

// NewUFWCollector returns a stub ufw collector. ufw is a thin wrapper
// over iptables — its rules already appear via the iptables collector,
// so this stub mostly exists for engine attribution in queries.
//
// TODO(cdms-iter): wire `ufw status verbose` for the higher-level rule
// names that don't survive translation to iptables.
func NewUFWCollector() Collector { return engineStub{name: "ufw-stub"} }

// NewFirewalldCollector returns a stub firewalld collector. Same story
// as ufw: rules appear via iptables/nftables. Stub for zone metadata.
//
// TODO(cdms-iter): wire `firewall-cmd --list-all-zones --permanent`.
func NewFirewalldCollector() Collector { return engineStub{name: "firewalld-stub"} }

type engineStub struct{ name string }

func (s engineStub) Name() string { return s.name }
func (s engineStub) Collect(_ context.Context) ([]Rule, error) {
	return []Rule{}, nil
}
