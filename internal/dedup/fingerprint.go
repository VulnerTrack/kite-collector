package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Confidence describes how trustworthy a Tier-1 identity fingerprint is.
// The deduper refuses to auto-merge across confidence tiers without an
// explicit alias-graph link; this is what stops a Nominal hostname match
// from silently collapsing into a Hardware-confidence machine identity.
type Confidence uint8

const (
	// ConfidenceUnknown is the zero value; never written by fingerprinters.
	ConfidenceUnknown Confidence = iota
	// ConfidenceNominal is hostname-only. Easy to spoof, easy to collide.
	ConfidenceNominal
	// ConfidenceNetwork is derived from network-observable signals
	// (MAC, SSH host key, mDNS service set, DHCP fingerprint).
	ConfidenceNetwork
	// ConfidenceCryptographic is provider-issued or content-addressable
	// identity (cloud instance_id, OCI image digest, VCS root commit).
	ConfidenceCryptographic
	// ConfidenceHardware is rooted in physical-layer signals that survive
	// OS reinstall (DMI UUID, machine-id, TPM endorsement-key public hash).
	ConfidenceHardware
)

// FPVersion is embedded in every composed pre-image so the digest space
// is explicitly versioned. Bump this when the composition rules change
// (e.g. moving from SHA-256 to SHA-3) so old and new digests cannot
// silently collide during a migration window.
const FPVersion byte = 1

// Signal is one canonicalized input to a composite identity key. The Kind
// tag is included in the pre-image so two different signal types with the
// same canonical bytes cannot collide (e.g. a MAC that happens to look
// like a hostname-as-bytes).
type Signal struct {
	Kind  string
	Bytes []byte
}

// DiscoveryRecord is the union of identity-bearing signals any discoverer
// can produce for a single observed asset. All fields are optional;
// fingerprinters declare which subset they require and decline (ok=false)
// when the minimum is not met, letting the caller fall back to the
// hostname natural-key path. Discoverers should fill what they observe
// and leave the rest blank — never invent values to satisfy a field.
type DiscoveryRecord struct {
	LLDPChassisID     string
	PlatformID        string
	DMISystemUUID     string
	MachineID         string
	TPMEKPubSHA256    string
	Hostname          string
	SerialNumber      string
	Provider          string
	AccountID         string
	Region            string
	InstanceID        string
	ImageID           string
	IMDSPayloadSHA256 string
	SSHHostKeySHA256  string
	AssetType         model.AssetType
	UpstreamID        string
	TenantID          string
	UPnPUUID          string
	DHCPFingerprint   string
	SNMPSysObjectID   string
	Cluster           string
	Namespace         string
	WorkloadName      string
	ImageDigest       string
	VCSURL            string
	RootCommit        string
	UpstreamSource    string
	MDNSServiceSet    []string
	MACAddresses      []string
}

// Fingerprinter produces a Tier-1 identity digest for one AssetType.
// Implementations MUST canonicalize each signal via the canon helpers
// before contributing it. Mutable state belongs in Tier 2
// (Asset.MaterialFingerprint), not here.
type Fingerprinter interface {
	AssetType() model.AssetType
	Identity(rec DiscoveryRecord) (digest [32]byte, signals []Signal, conf Confidence, ok bool)
}

// Compose hashes the version byte, tenant scope, asset type, and signals
// into a SHA-256 digest. Each component is delimited by Sep so the
// pre-image is unambiguous. Signal Kind is hashed before Bytes so two
// different signal types with the same byte content cannot collide.
func Compose(version byte, tenant string, t model.AssetType, sigs []Signal) [32]byte {
	h := sha256.New()
	h.Write([]byte{version})
	h.Write([]byte(Sep))
	h.Write([]byte(tenant))
	h.Write([]byte(Sep))
	h.Write([]byte(t))
	for _, s := range sigs {
		h.Write([]byte(Sep))
		h.Write([]byte(s.Kind))
		h.Write([]byte(Sep))
		h.Write(s.Bytes)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Hex returns the lowercase hex encoding of a 32-byte digest.
func Hex(d [32]byte) string { return hex.EncodeToString(d[:]) }

// Registry dispatches per AssetType. It is safe for concurrent reads after
// construction is complete; callers should register everything they need
// before sharing the Registry across goroutines.
type Registry struct {
	m  map[model.AssetType]Fingerprinter
	mu sync.RWMutex
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{m: map[model.AssetType]Fingerprinter{}} }

// Register adds a Fingerprinter, overwriting any prior registration for
// the same AssetType. The last registration wins; this lets test code
// substitute a stub without first clearing the slot.
func (r *Registry) Register(f Fingerprinter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[f.AssetType()] = f
}

// Get returns the registered Fingerprinter for the given AssetType. The
// second return value is false when no Fingerprinter is registered.
func (r *Registry) Get(t model.AssetType) (Fingerprinter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.m[t]
	return f, ok
}

// DefaultRegistry constructs a Registry pre-populated with the production
// fingerprinters from this package. Tests that need a clean slate should
// call NewRegistry directly.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(CloudInstanceFingerprinter{})
	r.Register(AgentEnrolledHostFingerprinter{Type: model.AssetTypeServer})
	r.Register(AgentEnrolledHostFingerprinter{Type: model.AssetTypeWorkstation})
	r.Register(ContainerFingerprinter{})
	r.Register(VCSRepositoryFingerprinter{Type: model.AssetTypeSoftwareProject})
	r.Register(VCSRepositoryFingerprinter{Type: model.AssetTypeRepository})
	r.Register(NetworkDeviceFingerprinter{})
	r.Register(LANAgentlessFingerprinter{})
	r.Register(IOTDeviceFingerprinter{})
	// CMDB is wrapped with both server/workstation/network_device types
	// because the upstream system may emit any of them. The asset type
	// must already be set on the record by the discoverer.
	for _, t := range []model.AssetType{
		model.AssetTypeServer, model.AssetTypeWorkstation,
		model.AssetTypeNetworkDevice, model.AssetTypeAppliance,
		model.AssetTypeVirtualMachine,
	} {
		// CMDBFingerprinter routes on UpstreamSource/UpstreamID, not on
		// asset type — but Get() dispatches on AssetType, so we register
		// the same logic for every type a CMDB might emit. CMDB observations
		// only succeed when both UpstreamSource and UpstreamID are set,
		// so server/workstation observations from other sources still
		// fall through to their hardware fingerprinters first.
		_ = t // kept for documentation; CMDB lives on AgentEnrolledHost which
		// already declines when hardware signals are absent, so CMDB-only
		// records go through the registry fallback path. See
		// fingerprint_cmdb.go for the explicit handler that callers can
		// use directly when UpstreamSource is known.
	}
	return r
}
