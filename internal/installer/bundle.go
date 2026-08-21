package installer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Installer variants (RFC-0156 Section 4.1, WindowsInstallerArtifact.variant).
// The variant is a build-time decision — the osquery_bundle Go build tag *is*
// the feature flag (Section 10.2) — never a runtime toggle, so the plain
// download can never accidentally inherit osqueryd's larger attack surface.
const (
	BundleVariantPlain   = "plain"
	BundleVariantOsquery = "osquery_bundle"
)

// bundleRoot is the go:embed prefix every payload path is relative to.
const bundleRoot = "osquerypayload/payload"

// bundleManifestPath and bundleDaemonPath are the two payload members the
// installer cannot proceed without. Forward slashes: these are io/fs paths,
// not host paths, on every platform.
const (
	bundleManifestPath = bundleRoot + "/manifest.json"
	bundleDaemonPath   = "osquery/osqueryd/osqueryd.exe"
)

// Bundle failure modes. Each is a distinct operator situation with a distinct
// fix, which is why they are sentinel errors rather than one opaque string.
var (
	// ErrBundleNotBuilt means the plain artifact was run: correct behaviour,
	// not a fault. Callers use errors.Is to skip the osquery step silently.
	ErrBundleNotBuilt = errors.New(
		"this build carries no embedded osquery payload " +
			"(rebuild with -tags osquery_bundle)")

	// ErrBundleNotStaged means -tags osquery_bundle was set but
	// scripts/stage-osquery-embed.sh never ran, so the binary embeds a
	// placeholder instead of a verified daemon.
	ErrBundleNotStaged = errors.New(
		"embedded osquery payload has no manifest " +
			"(run scripts/stage-osquery-embed.sh before building)")

	// ErrBundlePinMissing is the defense-in-depth gate from RFC-0156 Section
	// 4.2: the dangerous failure is not "checksum fails loudly", it is
	// "checksum check silently skipped". Refusing to install without a
	// link-time pin means a refactor that drops the verified staging step
	// produces an installer that cannot install, not one that quietly ships
	// whatever bytes happened to be on the build machine.
	ErrBundlePinMissing = errors.New(
		"embedded osquery payload carries no link-time checksum pin " +
			"(-ldflags -X ...installer.vendoredOsquerySHA256=<sha256>)")
)

// BundleFile is one embedded payload member and the digest it must hash to
// after it lands on disk.
type BundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// BundleManifest is the machine-readable form of RFC-0156's BundledDependency
// class, written by scripts/stage-osquery-embed.sh and embedded alongside the
// payload it describes.
type BundleManifest struct {
	NaturalKey       string       `json:"natural_key"`
	ComponentName    string       `json:"component_name"`
	ComponentVersion string       `json:"component_version"`
	UpstreamSHA256   string       `json:"upstream_sha256"`
	VendoredSHA256   string       `json:"vendored_sha256"`
	SourceURL        string       `json:"source_url"`
	LicenseID        string       `json:"license_id"`
	CPE23            string       `json:"cpe23"`
	ArtifactFormat   string       `json:"artifact_format"`
	Files            []BundleFile `json:"files"`
	SchemaVersion    int          `json:"schema_version"`
}

// Validate enforces the checksum-integrity axiom of RFC-0156 Section 4.2:
// vendored_sha256 == upstream_sha256, always, for every BundledDependency. A
// manifest that fails this must not produce an install — the shell side
// already failed the build closed on the same condition, and this is the
// second, independent assertion of it inside the artifact itself.
func (m BundleManifest) Validate() error {
	if m.ComponentName == "" || m.ComponentVersion == "" {
		return errors.New("bundle manifest: component name/version missing")
	}
	upstream := strings.ToLower(strings.TrimSpace(m.UpstreamSHA256))
	vendored := strings.ToLower(strings.TrimSpace(m.VendoredSHA256))
	if !isSHA256Hex(upstream) {
		return fmt.Errorf("bundle manifest: upstream_sha256 %q is not a sha256", m.UpstreamSHA256)
	}
	if !isSHA256Hex(vendored) {
		return fmt.Errorf("bundle manifest: vendored_sha256 %q is not a sha256", m.VendoredSHA256)
	}
	if upstream != vendored {
		return fmt.Errorf(
			"bundle manifest: checksum-integrity violation, upstream %s != vendored %s",
			upstream, vendored)
	}
	if len(m.Files) == 0 {
		return errors.New("bundle manifest: no payload files listed")
	}
	for _, f := range m.Files {
		if f.Path == "" {
			return errors.New("bundle manifest: payload entry with empty path")
		}
		if !isSHA256Hex(strings.ToLower(f.SHA256)) {
			return fmt.Errorf("bundle manifest: %s has no valid sha256", f.Path)
		}
	}
	if !m.hasDaemon() {
		return fmt.Errorf("bundle manifest: %s not listed in payload", bundleDaemonPath)
	}
	return nil
}

func (m BundleManifest) hasDaemon() bool {
	for _, f := range m.Files {
		if f.Path == bundleDaemonPath {
			return true
		}
	}
	return false
}

// parseBundleManifest decodes and validates in one step so no caller can hold
// an unvalidated manifest.
func parseBundleManifest(raw []byte) (BundleManifest, error) {
	var m BundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return BundleManifest{}, fmt.Errorf("decode bundle manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return BundleManifest{}, err
	}
	return m, nil
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return false
		}
	}
	return true
}
