package installer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// InstallManifestName is the file install writes next to the install log,
// recording exactly what it created so uninstall can remove exactly that
// set — and nothing a package manager owns.
const InstallManifestName = "install-manifest.json"

// InstallManifest records the artifacts one `kite-collector install` run
// created or adopted. Uninstall consumes it for symmetric removal: a
// copied binary is deleted, an adopted (manager-owned) binary is left to
// its manager.
type InstallManifest struct {
	// BinaryPath is the service executable that was registered.
	BinaryPath string `json:"binary_path"`
	// BinaryCopied is true when install itself placed the binary there.
	// False means the binary was adopted from a package manager (Owner
	// says which) or was already in place.
	BinaryCopied bool `json:"binary_copied"`
	// Owner is the owning package manager when the binary was adopted
	// ("homebrew", "dpkg", "rpm", "pacman"); empty for install-owned.
	Owner string `json:"owner,omitempty"`
	// PackagedUnit is the package-shipped systemd unit the install
	// adopted instead of registering its own. Uninstall must then only
	// stop and disable — the unit belongs to the package. Empty means
	// install registered the service itself (kardianos) and uninstall
	// removes that registration.
	PackagedUnit string `json:"packaged_unit,omitempty"`
	// UserMode records the service domain the manifest describes.
	UserMode bool `json:"user_mode"`
	// WrittenAt is the RFC3339 timestamp of the install run.
	WrittenAt string `json:"written_at"`
}

// InstallManifestPath resolves the manifest location inside the
// collector's data directory (beside install.log).
func InstallManifestPath(opts Options) string {
	return filepath.Join(opts.CertsDir, InstallManifestName)
}

// WriteInstallManifest persists the manifest. Best-effort by design: an
// install that succeeded must not fail because its bookkeeping file could
// not be written, so the error is returned for logging but callers treat
// it as advisory.
func WriteInstallManifest(opts Options, m InstallManifest) error {
	m.WrittenAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode install manifest: %w", err)
	}
	if err := os.MkdirAll(opts.CertsDir, 0o750); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}
	if err := os.WriteFile(InstallManifestPath(opts), append(data, '\n'), 0o640); err != nil { //#nosec G306 -- operator-readable bookkeeping, no secrets
		return fmt.Errorf("write install manifest: %w", err)
	}
	return nil
}

// ReadInstallManifest loads the manifest if present. ok is false when no
// manifest exists or it cannot be parsed — callers fall back to the
// historical leave-everything uninstall behavior.
func ReadInstallManifest(opts Options) (InstallManifest, bool) {
	data, err := os.ReadFile(InstallManifestPath(opts)) //#nosec G304 -- path derives from the trusted certs dir option
	if err != nil {
		return InstallManifest{}, false
	}
	var m InstallManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return InstallManifest{}, false
	}
	return m, true
}
