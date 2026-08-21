package installer

import (
	"fmt"
	"os"

	"github.com/kardianos/service"
)

// OsqueryInstallResult is what the sibling-daemon install actually did, so the
// wizard, the CLI, and the install log can all report the same facts instead of
// each inferring them.
type OsqueryInstallResult struct {
	Manifest    BundleManifest `json:"manifest"`
	InstallDir  string         `json:"install_dir"`
	DataDir     string         `json:"data_dir"`
	SocketPath  string         `json:"socket_path"`
	RecoverySet bool           `json:"recovery_configured"`
	Started     bool           `json:"started"`
}

// InstallOsqueryBundle lays down the embedded payload and registers
// kite-osqueryd as the collector's sibling service (R1, R3, R5, R6).
//
// Ordering is not incidental:
//
//  1. Verify before touching anything. A payload that fails the
//     checksum-integrity axiom must not reach the disk at all.
//  2. Stop and deregister any prior kite-osqueryd *before* extraction. On
//     Windows a running daemon holds an exclusive handle on osqueryd.exe and
//     the atomic rename would fail with "used by another process" — the
//     upgrade-over-a-live-install case, which is the common one.
//  3. Extract, then create the mutable data/log dirs the daemon needs before
//     it is ever started, so its first run does not race directory creation.
//  4. Register, then configure recovery actions, then publish the socket
//     env var, and only then start. Recovery must be in place before the
//     daemon can crash for the first time, and the env var must be visible
//     before the collector's next scan dials the pipe.
//
// Every failure after registration rolls the registration back. RFC-0156
// Section 4.2 makes this an axiom of InstallationRun: a run that did not
// complete MUST NOT claim it created service registrations. Leaving a
// half-configured kite-osqueryd behind would present as a healthy install with
// no crash protection — precisely the silent degradation R5 exists to end.
// The extracted payload is deliberately *not* rolled back: it is inert without
// a service registration, and keeping it lets an operator inspect the daemon
// (`osqueryd.exe -S`) to find out why the start failed.
func InstallOsqueryBundle(opts Options) (OsqueryInstallResult, error) {
	res := OsqueryInstallResult{
		InstallDir: opts.BinaryDir,
		DataDir:    OsqueryDataDir(opts),
		SocketPath: OsqueryExtensionsEndpoint(),
	}

	manifest, err := VerifyBundle()
	if err != nil {
		return res, err
	}
	res.Manifest = manifest

	svc, err := service.New(&noopProgram{}, BuildOsquerySvcConfig(opts))
	if err != nil {
		return res, fmt.Errorf("create %s service handle: %w", OsquerySvcName, err)
	}

	// Best-effort: both fail when nothing is registered yet, which is the
	// fresh-install case.
	_ = svc.Stop()
	_ = svc.Uninstall()

	if _, extractErr := ExtractBundlePayload(opts.BinaryDir); extractErr != nil {
		return res, extractErr
	}
	for _, dir := range []string{OsqueryDataDir(opts), OsqueryLogDir(opts)} {
		if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
			return res, fmt.Errorf("create osquery data dir %s: %w", dir, mkErr)
		}
	}

	if instErr := svc.Install(); instErr != nil {
		return res, fmt.Errorf("register %s service: %w", OsquerySvcName, instErr)
	}

	if recErr := ConfigureServiceRecovery(OsquerySvcName); recErr != nil {
		_ = svc.Uninstall()
		return res, fmt.Errorf("configure %s recovery actions: %w", OsquerySvcName, recErr)
	}
	res.RecoverySet = true

	if envErr := SetMachineEnv(OsquerySocketEnvVar, res.SocketPath); envErr != nil {
		_ = svc.Uninstall()
		return res, fmt.Errorf("publish %s: %w", OsquerySocketEnvVar, envErr)
	}

	if startErr := svc.Start(); startErr != nil {
		_ = svc.Uninstall()
		return res, fmt.Errorf("start %s service: %w", OsquerySvcName, startErr)
	}
	res.Started = true
	return res, nil
}

// UninstallOsqueryBundle stops and deregisters the sibling daemon. Like
// realInstaller.Uninstall it leaves the payload and the osquery database on
// disk, so a re-install does not lose the FIM event history the daemon has
// buffered (RFC-0151 Section 8.4's events_expiry window).
//
// Deregistration errors are swallowed on purpose: kardianos returns a plain
// formatted error — not a sentinel — when the service was never registered,
// and "it is already gone" is success for an uninstall.
func UninstallOsqueryBundle(opts Options) error {
	svc, err := service.New(&noopProgram{}, BuildOsquerySvcConfig(opts))
	if err != nil {
		return fmt.Errorf("create %s service handle: %w", OsquerySvcName, err)
	}
	_ = svc.Stop()
	_ = svc.Uninstall()
	return nil
}
