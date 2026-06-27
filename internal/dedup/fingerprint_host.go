package dedup

import "github.com/vulnertrack/kite-collector/internal/model"

// AgentEnrolledHostFingerprinter identifies a host by hardware-rooted
// signals collected from the on-host agent: DMI system UUID, machine-id,
// TPM endorsement-key SHA-256, and the sorted set of MAC addresses. Any
// non-empty subset produces an identity; presence of a hardware-grade
// signal (TPM or DMI) upgrades the confidence band from Network to
// Hardware. With neither hardware nor network signals available the
// fingerprinter declines so the caller falls back to the hostname path.
//
// Registered for AssetTypeServer and AssetTypeWorkstation; the Type
// field selects which one this instance handles so the Registry can hold
// two entries that share the same logic.
type AgentEnrolledHostFingerprinter struct {
	Type model.AssetType
}

// AssetType returns the asset type this fingerprinter handles.
func (f AgentEnrolledHostFingerprinter) AssetType() model.AssetType { return f.Type }

// Identity composes a digest from whichever hardware/network signals are
// present. The order of signals contributed to the pre-image is fixed
// (TPM → DMI → machine-id → MACs) so the same underlying machine
// produces a stable digest regardless of discovery-source ordering.
func (f AgentEnrolledHostFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	var sigs []Signal
	conf := ConfidenceUnknown

	if v := CanonLowerHex(r.TPMEKPubSHA256); v != "" {
		sigs = append(sigs, Signal{Kind: "tpm_ek", Bytes: []byte(v)})
		conf = ConfidenceHardware
	}
	if v := CanonUUID(r.DMISystemUUID); v != "" {
		sigs = append(sigs, Signal{Kind: "dmi_uuid", Bytes: []byte(v)})
		if conf < ConfidenceHardware {
			conf = ConfidenceHardware
		}
	}
	if v := CanonLowerHex(r.MachineID); v != "" {
		sigs = append(sigs, Signal{Kind: "machine_id", Bytes: []byte(v)})
		if conf < ConfidenceHardware {
			conf = ConfidenceHardware
		}
	}
	if macs := CanonSortedMACs(r.MACAddresses); macs != nil {
		sigs = append(sigs, Signal{Kind: "macs", Bytes: macs})
		if conf < ConfidenceNetwork {
			conf = ConfidenceNetwork
		}
	}

	if len(sigs) == 0 {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	return Compose(FPVersion, r.TenantID, f.Type, sigs), sigs, conf, true
}
