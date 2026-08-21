//go:build osquery_bundle

// Package-local: the embedded-payload half of the self-contained Windows
// installer (RFC-0156 R1/R4). Compiled only into the explicitly-named
// kite-collector-osquery artifact; the plain flat-binary/wizard/MSI channels
// never see this file, which is what makes "the build tag is the feature flag"
// (Section 10.2) literally true rather than an aspiration.

package installer

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// The payload is staged by scripts/stage-osquery-embed.sh from the pinned,
// SHA256-verified upstream osquery MSI. Only osquerypayload/payload/README.md
// is committed; everything else here is build output, which is why the embed
// pattern points at the directory rather than at named files (a bare
// //go:embed of a missing file is a compile error, and an unstaged tree must
// still be loadable by `go vet -tags osquery_bundle ./...`).
//
//go:embed osquerypayload/payload
var bundleFS embed.FS

// vendoredOsquerySHA256 is injected at link time by the release build:
//
//	-ldflags "-X github.com/vulnertrack/kite-collector/internal/installer.vendoredOsquerySHA256=<sha256>"
//
// scripts/stage-osquery-embed.sh prints the exact flag and writes it to
// dist/osquery-embed-ldflags.txt. Its value must equal the manifest's
// vendored_sha256 or VerifyBundle refuses to install (ErrBundlePinMissing /
// pin-mismatch). This is deliberately a second, independent binding of the
// same fact: the manifest travels with the payload, the pin travels with the
// link step, and only a build that ran the verified staging script can make
// the two agree.
var vendoredOsquerySHA256 string

var (
	bundleOnce     sync.Once
	bundleManifest BundleManifest
	bundleErr      error
)

// loadBundle parses and validates the embedded manifest exactly once.
func loadBundle() (BundleManifest, error) {
	bundleOnce.Do(func() {
		raw, err := bundleFS.ReadFile(bundleManifestPath)
		if err != nil {
			bundleErr = fmt.Errorf("%w: %w", ErrBundleNotStaged, err)
			return
		}
		bundleManifest, bundleErr = parseBundleManifest(raw)
	})
	return bundleManifest, bundleErr
}

// BundleAvailable reports that this binary was built with a payload.
func BundleAvailable() bool { return true }

// BundledOsqueryVersion returns the pinned osquery version, or "" when the
// payload is unstaged or malformed. Used by status surfaces, which should keep
// working (and keep saying something useful) even on a build that would refuse
// to install.
func BundledOsqueryVersion() string {
	m, err := loadBundle()
	if err != nil {
		return ""
	}
	return m.ComponentVersion
}

// VerifyBundle checks everything that can be checked without touching the disk:
// the manifest parses, satisfies the checksum-integrity axiom, and agrees with
// the link-time pin. Cheap enough to call from a probe or a UI fragment.
func VerifyBundle() (BundleManifest, error) {
	m, err := loadBundle()
	if err != nil {
		return BundleManifest{}, err
	}
	pin := strings.ToLower(strings.TrimSpace(vendoredOsquerySHA256))
	if pin == "" {
		return BundleManifest{}, ErrBundlePinMissing
	}
	if pin != strings.ToLower(m.VendoredSHA256) {
		return BundleManifest{}, fmt.Errorf(
			"embedded osquery payload pin mismatch: link-time %s, manifest %s",
			pin, m.VendoredSHA256)
	}
	return m, nil
}

// ExtractBundlePayload writes the verified payload under destRoot (the
// collector's install directory), reproducing the MSI's on-disk layout:
//
//	<destRoot>\osquery\osqueryd\osqueryd.exe
//	<destRoot>\osquery\certs\certs.pem
//	<destRoot>\osquery\osquery.{conf,flags}
//	<destRoot>\osquery\packs\*.conf
//
// Every file is streamed through a SHA256 hasher into a temp file and only
// renamed into place once the digest matches the manifest. That is the
// extracting -> services_registering transition of RFC-0156 Section 4.2: a
// half-written file (disk full) or a byte-mangled one (AV real-time protection
// touching the target directory mid-write) fails the install loudly instead of
// leaving a service pointed at a truncated binary that will run as LocalSystem.
//
// Streaming rather than ReadFile keeps the memory footprint at one copy buffer
// instead of ~55 MB, which matters on the small VMs this agent targets.
func ExtractBundlePayload(destRoot string) (BundleManifest, error) {
	m, err := VerifyBundle()
	if err != nil {
		return BundleManifest{}, err
	}
	for _, f := range m.Files {
		if extractErr := extractBundleFile(destRoot, f); extractErr != nil {
			return BundleManifest{}, extractErr
		}
	}
	return m, nil
}

func extractBundleFile(destRoot string, f BundleFile) error {
	dst := filepath.Join(destRoot, filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("create payload dir %s: %w", filepath.Dir(dst), err)
	}

	src, err := bundleFS.Open(path.Join(bundleRoot, f.Path))
	if err != nil {
		return fmt.Errorf("open embedded payload %s: %w", f.Path, err)
	}
	defer func() { _ = src.Close() }()

	tmp := dst + ".tmp"
	written, sum, err := writeVerified(tmp, src, bundleFileMode(f.Path))
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if f.Size > 0 && written != f.Size {
		_ = os.Remove(tmp)
		return fmt.Errorf(
			"payload %s: wrote %d bytes, manifest declares %d", f.Path, written, f.Size)
	}
	if sum != strings.ToLower(f.SHA256) {
		_ = os.Remove(tmp)
		return fmt.Errorf(
			"payload %s failed on-disk checksum verification: %s != %s",
			f.Path, sum, f.SHA256)
	}
	if renameErr := os.Rename(tmp, dst); renameErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("place payload %s: %w", dst, renameErr)
	}
	return nil
}

// writeVerified copies src into path, returning the byte count and the hex
// SHA256 of what was actually written.
func writeVerified(dst string, src fs.File, mode os.FileMode) (int64, string, error) {
	//#nosec G302,G304 -- dst is under the trusted install root and the daemon must be executable
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return 0, "", fmt.Errorf("create %s: %w", dst, err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, hasher), src)
	closeErr := out.Close()
	if copyErr != nil {
		return 0, "", fmt.Errorf("write %s: %w", dst, copyErr)
	}
	if closeErr != nil {
		return 0, "", fmt.Errorf("close %s: %w", dst, closeErr)
	}
	return written, hex.EncodeToString(hasher.Sum(nil)), nil
}

// bundleFileMode keeps the daemon executable and everything else read-only for
// non-owners. The mode is advisory on Windows (the ACL is what matters there)
// but correct on any platform a future bundle variant might target.
func bundleFileMode(payloadPath string) os.FileMode {
	if strings.HasSuffix(payloadPath, ".exe") ||
		strings.Contains(payloadPath, "/osqueryd/") {
		return 0o755
	}
	return 0o644
}
