package dedup

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// CMDBFingerprinter trusts an upstream system of record (Netbox,
// ServiceNow, Intune, Jamf, SCCM, …) as the authority for asset
// identity. It composes (upstream_source, upstream_id) without
// re-deriving identity from hardware or hostname signals — those
// fingerprinters can still match the same physical asset later via
// alias-graph promotion.
//
// CMDBFingerprinter does not bind to a single AssetType because the
// upstream may emit servers, workstations, network devices, or
// appliances. Callers register one instance per AssetType the upstream
// produces; the Type field selects which the instance handles.
type CMDBFingerprinter struct {
	Type model.AssetType
}

// AssetType returns the asset type this fingerprinter handles.
func (f CMDBFingerprinter) AssetType() model.AssetType { return f.Type }

// Identity requires both UpstreamSource and UpstreamID. Without those
// it declines — there is no fallback because the whole point of the
// CMDB path is that the upstream is canonical for *its own* records.
func (f CMDBFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	src := strings.ToLower(strings.TrimSpace(r.UpstreamSource))
	id := strings.TrimSpace(r.UpstreamID)
	if src == "" || id == "" {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	sigs := []Signal{
		{Kind: "upstream_source", Bytes: []byte(src)},
		{Kind: "upstream_id", Bytes: []byte(id)},
	}
	return Compose(FPVersion, r.TenantID, f.Type, sigs), sigs, ConfidenceCryptographic, true
}
