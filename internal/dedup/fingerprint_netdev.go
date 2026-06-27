package dedup

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// NetworkDeviceFingerprinter identifies routers, switches, firewalls,
// and similar gear by LLDP chassis-id, SNMP sysObjectID, or serial
// number. LLDP chassis-id is the IETF-blessed stable identifier; we
// prefer it when present. SNMP sysObjectID is a stable OID for the
// vendor/model and combines with serial to disambiguate identical
// hardware in the same fleet.
type NetworkDeviceFingerprinter struct{}

// AssetType returns the asset type this fingerprinter handles.
func (NetworkDeviceFingerprinter) AssetType() model.AssetType { return model.AssetTypeNetworkDevice }

// Identity composes whichever signals are available. LLDP alone is
// Network confidence; LLDP + serial or SNMP + serial is Cryptographic.
func (NetworkDeviceFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	var sigs []Signal
	conf := ConfidenceUnknown

	if v := strings.ToLower(strings.TrimSpace(r.LLDPChassisID)); v != "" {
		sigs = append(sigs, Signal{Kind: "lldp_chassis_id", Bytes: []byte(v)})
		conf = ConfidenceNetwork
	}
	if v := strings.TrimSpace(r.SNMPSysObjectID); v != "" {
		sigs = append(sigs, Signal{Kind: "snmp_sys_oid", Bytes: []byte(v)})
		if conf < ConfidenceNetwork {
			conf = ConfidenceNetwork
		}
	}
	if v := strings.TrimSpace(r.SerialNumber); v != "" {
		sigs = append(sigs, Signal{Kind: "serial", Bytes: []byte(strings.ToLower(v))})
		if conf >= ConfidenceNetwork {
			conf = ConfidenceCryptographic
		} else {
			conf = ConfidenceNetwork
		}
	}

	if len(sigs) == 0 {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	return Compose(FPVersion, r.TenantID, model.AssetTypeNetworkDevice, sigs), sigs, conf, true
}
