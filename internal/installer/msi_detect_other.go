//go:build !windows

package installer

// DetectPriorInstall always reports a fresh install off Windows.
//
// The MSI channel, the Add/Remove Programs registry, and the self-contained
// .exe this pre-flight check exists for are all Windows-only concepts. On
// Linux the equivalent "don't side-install a duplicate" guarantee already comes
// from dpkg/rpm: the plain and kite-collector-osquery packages declare each
// other in `conflicts`, so the package manager enforces the swap.
func DetectPriorInstall() PriorInstall {
	return PriorInstall{Kind: PriorInstallNone}
}

// SetMachineEnv is a no-op off Windows. The Linux equivalent of the
// machine-wide KITE_OSQUERY_SOCKET is the systemd drop-in the deb installs
// (packaging/deb/10-kite-osquery-socket.conf), which is owned by the package,
// not by this process.
func SetMachineEnv(_, _ string) error { return nil }

// ConfigureServiceRecovery is a no-op off Windows. systemd units already carry
// Restart=on-failure/RestartSec=5 declaratively — the parity gap R5 closes is
// Windows-only by construction.
func ConfigureServiceRecovery(_ string) error { return nil }

// RecordInstallMarker is a no-op off Windows: there is no registry to mark.
func RecordInstallMarker(_ Options, _, _, _ string) error { return nil }

// HardenFileACL is a no-op off Windows. The install log's directory is created
// with 0o750 by the caller, which is the POSIX equivalent of the
// Administrators+SYSTEM DACL the Windows implementation applies.
func HardenFileACL(_ string) error { return nil }
