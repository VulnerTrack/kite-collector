package dedup

import "github.com/vulnertrack/kite-collector/internal/model"

// LANAgentlessFingerprinter identifies a host observed only through
// passive LAN signals: MACs, SSH host key, mDNS service set, DHCP
// fingerprint. These are weaker than hardware IDs (someone can clone
// a MAC; SSH keys can be rotated) so the maximum confidence band is
// Network. The fingerprinter intentionally maps to AssetTypeServer
// because that is the conservative default for an unenrolled host —
// promoting to workstation or appliance happens via the alias graph
// once stronger signals arrive.
type LANAgentlessFingerprinter struct{}

// AssetType returns the asset type this fingerprinter handles.
func (LANAgentlessFingerprinter) AssetType() model.AssetType { return model.AssetTypeServer }

// Identity composes whichever LAN signals are present. SSH host key is
// the strongest single signal here when reachable; it gets the most
// weight by virtue of being a cryptographic key fingerprint, but the
// overall confidence stays Network because nothing here roots in
// physical hardware.
func (LANAgentlessFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	var sigs []Signal

	if v := CanonLowerHex(r.SSHHostKeySHA256); v != "" {
		sigs = append(sigs, Signal{Kind: "ssh_hostkey", Bytes: []byte(v)})
	}
	if macs := CanonSortedMACs(r.MACAddresses); macs != nil {
		sigs = append(sigs, Signal{Kind: "macs", Bytes: macs})
	}
	if mdns := CanonStringSet(r.MDNSServiceSet); mdns != nil {
		sigs = append(sigs, Signal{Kind: "mdns_services", Bytes: mdns})
	}
	if v := CanonLowerHex(r.DHCPFingerprint); v != "" {
		sigs = append(sigs, Signal{Kind: "dhcp_fingerprint", Bytes: []byte(v)})
	}

	if len(sigs) == 0 {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	return Compose(FPVersion, r.TenantID, model.AssetTypeServer, sigs), sigs, ConfidenceNetwork, true
}
