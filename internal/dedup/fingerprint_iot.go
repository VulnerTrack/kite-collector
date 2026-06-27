package dedup

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// IOTDeviceFingerprinter identifies IoT devices and appliances primarily
// through UPnP UUIDs and mDNS UUIDs (printers, smart-TVs, cameras
// frequently advertise these). MAC-OUI plus a model string is the
// fallback when no UUID is broadcast — it is weak but better than
// hostname-only.
type IOTDeviceFingerprinter struct{}

// AssetType returns the asset type this fingerprinter handles.
func (IOTDeviceFingerprinter) AssetType() model.AssetType { return model.AssetTypeIOTDevice }

// Identity prefers UPnPUUID (most IoT gear that exposes it is stable on
// it). Falls back to MAC set; declines when neither is present.
func (IOTDeviceFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	var sigs []Signal
	conf := ConfidenceUnknown

	if v := CanonUUID(r.UPnPUUID); v != "" {
		sigs = append(sigs, Signal{Kind: "upnp_uuid", Bytes: []byte(v)})
		conf = ConfidenceNetwork
	}
	if macs := CanonSortedMACs(r.MACAddresses); macs != nil {
		sigs = append(sigs, Signal{Kind: "macs", Bytes: macs})
		if conf < ConfidenceNetwork {
			conf = ConfidenceNetwork
		}
	}
	// Model string (when conveyed via mDNS TXT) is appended verbatim,
	// lowercased. We accept the trailing hostname as a weak last resort
	// because IoT hostnames are vendor-assigned and somewhat stable.
	if v := strings.ToLower(strings.TrimSpace(r.Hostname)); v != "" && len(sigs) == 0 {
		sigs = append(sigs, Signal{Kind: "hostname", Bytes: []byte(v)})
		conf = ConfidenceNominal
	}

	if len(sigs) == 0 {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	return Compose(FPVersion, r.TenantID, model.AssetTypeIOTDevice, sigs), sigs, conf, true
}
