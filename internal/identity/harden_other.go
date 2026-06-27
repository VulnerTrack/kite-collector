//go:build !linux

package identity

import "log/slog"

// HardenProcess is a no-op on non-Linux platforms. Linux-specific
// hardening (PR_SET_DUMPABLE, mlockall) requires Linux syscalls.
func HardenProcess(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("process hardening: not available on this platform")
}

// TPMAvailable always returns false on non-Linux platforms.
// TPM support requires Linux /dev/tpmrm0.
func TPMAvailable() bool { return false }

// KeyringAvailable always returns false on non-Linux platforms.
// Kernel keyring support requires Linux keyctl.
func KeyringAvailable() bool { return false }
