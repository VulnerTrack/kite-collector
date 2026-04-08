//go:build linux

package identity

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// HardenProcess applies security hardening on Linux:
// - PR_SET_DUMPABLE=0: prevents core dumps and /proc/pid/mem reads
// - mlockall: locks memory pages to prevent key material hitting swap
func HardenProcess(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	// Prevent core dumps and /proc/pid/mem reads.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Warn("failed to set PR_SET_DUMPABLE=0", "error", err)
	} else {
		logger.Info("process hardening: core dumps disabled (PR_SET_DUMPABLE=0)")
	}

	// Lock all current and future memory pages (prevent swap).
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		logger.Warn("failed to mlockall — key material may be swapped to disk", "error", err)
	} else {
		logger.Info("process hardening: memory locked (mlockall)")
	}
}

// TPMAvailable checks if a TPM 2.0 device is accessible.
func TPMAvailable() bool {
	// Check for the standard Linux TPM device paths.
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err == nil {
			return true
		}
	}
	return false
}

// KeyringAvailable checks if the Linux kernel keyring is accessible.
func KeyringAvailable() bool {
	// Try to access the user session keyring.
	_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_SESSION_KEYRING, false)
	return err == nil
}
