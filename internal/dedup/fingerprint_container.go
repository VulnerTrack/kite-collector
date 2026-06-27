package dedup

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// ContainerFingerprinter identifies a container *workload* (not a
// replica) by the tuple (platform, cluster, namespace, workload_name,
// image_digest). Hostnames rotate per restart and would over-count
// replicas; the digest pins the *artifact* and the platform-scoped
// workload identity.
type ContainerFingerprinter struct{}

// AssetType returns the asset type this fingerprinter handles.
func (ContainerFingerprinter) AssetType() model.AssetType { return model.AssetTypeContainer }

// Identity requires at minimum a platform_id and a workload_name. When
// an OCI image digest is present, the confidence band is Cryptographic
// (content-addressable artifact); otherwise it is Network (platform
// asserts identity but artifact is mutable).
func (ContainerFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	platform := strings.ToLower(strings.TrimSpace(r.PlatformID))
	workload := strings.TrimSpace(r.WorkloadName)
	if platform == "" || workload == "" {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}

	sigs := []Signal{
		{Kind: "platform", Bytes: []byte(platform)},
		{Kind: "workload", Bytes: []byte(workload)},
	}
	if c := strings.TrimSpace(r.Cluster); c != "" {
		sigs = append(sigs, Signal{Kind: "cluster", Bytes: []byte(c)})
	}
	if ns := strings.TrimSpace(r.Namespace); ns != "" {
		sigs = append(sigs, Signal{Kind: "namespace", Bytes: []byte(ns)})
	}

	conf := ConfidenceNetwork
	if dig := CanonOCIDigest(r.ImageDigest); dig != "" {
		sigs = append(sigs, Signal{Kind: "image_digest", Bytes: []byte(dig)})
		conf = ConfidenceCryptographic
	}

	return Compose(FPVersion, r.TenantID, model.AssetTypeContainer, sigs), sigs, conf, true
}
