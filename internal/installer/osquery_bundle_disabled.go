//go:build !osquery_bundle

package installer

// Default build: no embedded osquery payload.
//
// RFC-0156 R2 makes bundling a build-time decision producing a separate,
// explicitly-named artifact, never the default for the plain flat-binary or
// wizard download. Users who did not ask for FIM/YARA discovery must not
// inherit osqueryd's attack surface or its ~55 MB of download weight, so the
// default build compiles these no-op shims and callers skip the osquery step
// via errors.Is(err, ErrBundleNotBuilt).
//
// Everything else about osquery stays available on this build: ProbeOsquery
// still reports an MSI-installed kite-osqueryd, and BuildOsquerySvcConfig still
// describes it. Only the embedded payload is absent.

// BundleAvailable reports that this binary carries no payload.
func BundleAvailable() bool { return false }

// BundledOsqueryVersion is empty on a plain build.
func BundledOsqueryVersion() string { return "" }

// VerifyBundle always fails with ErrBundleNotBuilt.
func VerifyBundle() (BundleManifest, error) {
	return BundleManifest{}, ErrBundleNotBuilt
}

// ExtractBundlePayload always fails with ErrBundleNotBuilt.
func ExtractBundlePayload(_ string) (BundleManifest, error) {
	return BundleManifest{}, ErrBundleNotBuilt
}
