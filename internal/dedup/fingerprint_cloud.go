package dedup

import "github.com/vulnertrack/kite-collector/internal/model"

// CloudInstanceFingerprinter identifies a cloud VM by the immutable
// triple (provider, account, instance_id). Provider tags the digest space
// so the same opaque instance_id cannot collide across AWS/Azure/GCP, and
// the account-id partitions across tenants of the same provider.
type CloudInstanceFingerprinter struct{}

// AssetType returns the asset type this fingerprinter handles.
func (CloudInstanceFingerprinter) AssetType() model.AssetType {
	return model.AssetTypeCloudInstance
}

// Identity returns a Cryptographic-confidence digest when (provider,
// instance_id) are present. AccountID is included when known but is not
// strictly required — some discoverers report unowned public instances
// without an account context, and a missing field is preferable to a
// fabricated one.
func (CloudInstanceFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	provider := CanonProvider(r.Provider)
	if provider == "" || r.InstanceID == "" {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}
	sigs := []Signal{
		{Kind: "provider", Bytes: []byte(provider)},
		{Kind: "instance_id", Bytes: []byte(r.InstanceID)},
	}
	if acct := CanonAccount(provider, r.AccountID); acct != "" {
		// Insert account_id between provider and instance_id to keep the
		// pre-image order intuitive. Position does not affect the
		// avalanche property (Compose() hashes Kind before Bytes).
		sigs = []Signal{
			{Kind: "provider", Bytes: []byte(provider)},
			{Kind: "account_id", Bytes: []byte(acct)},
			{Kind: "instance_id", Bytes: []byte(r.InstanceID)},
		}
	}
	return Compose(FPVersion, r.TenantID, model.AssetTypeCloudInstance, sigs),
		sigs, ConfidenceCryptographic, true
}
