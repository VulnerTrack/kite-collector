package dedup

import "github.com/vulnertrack/kite-collector/internal/model"

// VCSRepositoryFingerprinter identifies a software project or repository
// by canonical VCS URL and (when known) the root commit. Root commit is
// the strongest identity signal — it survives renames, host migrations,
// and forks while remaining a single byte string. The Type field lets
// the same logic register for both AssetTypeSoftwareProject (a logical
// project) and AssetTypeRepository (a specific repo).
type VCSRepositoryFingerprinter struct {
	Type model.AssetType
}

// AssetType returns the asset type this fingerprinter handles.
func (f VCSRepositoryFingerprinter) AssetType() model.AssetType { return f.Type }

// Identity composes a digest from canonical VCS URL plus optional root
// commit. URL alone is Network confidence (URLs change under fork,
// rename, mirror); URL+root_commit is Cryptographic.
func (f VCSRepositoryFingerprinter) Identity(r DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	url := CanonVCSURL(r.VCSURL)
	root := CanonLowerHex(r.RootCommit)
	if url == "" && root == "" {
		return [32]byte{}, nil, ConfidenceUnknown, false
	}

	var sigs []Signal
	conf := ConfidenceNetwork
	if url != "" {
		sigs = append(sigs, Signal{Kind: "vcs_url", Bytes: []byte(url)})
	}
	if root != "" {
		sigs = append(sigs, Signal{Kind: "root_commit", Bytes: []byte(root)})
		conf = ConfidenceCryptographic
	}
	return Compose(FPVersion, r.TenantID, f.Type, sigs), sigs, conf, true
}
