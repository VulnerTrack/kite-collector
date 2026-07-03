package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// realInstaller is the production Installer wired into the dashboard. It
// performs the same three steps as the `kite-collector install` CLI:
//
//  1. Copy the running binary to the target install dir
//  2. Create the certs dir
//  3. Register the kite-collector service with the OS service manager
//
// The dashboard hands the operator a smart-defaults Options blob; this
// implementation honors whatever paths it receives so an operator who
// edited the form gets exactly what they asked for. Errors are wrapped
// with the failing step so the dashboard's error pane points at a
// specific remediation rather than a generic "install failed".
type realInstaller struct{}

func newRealInstaller() realInstaller { return realInstaller{} }

// Uninstall best-effort stops the kite-collector service and removes its
// OS registration. The binary and certificate store are left in place by
// design: re-install is reversible without re-enrolling. Mirrors the
// `kite-collector uninstall` CLI subcommand so the dashboard and CLI
// surfaces share one Lifecycle.
func (realInstaller) Uninstall(_ context.Context, opts installer.Options) error {
	cfg := installer.BuildSvcConfig(opts)
	svc, err := service.New(&program{}, cfg)
	if err != nil {
		return fmt.Errorf("create service handle: %w", err)
	}
	// Best-effort stop; ignore "not running" — uninstall must still proceed.
	_ = svc.Stop()
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	return nil
}

// Install runs the install steps in order, aborting at the first failure.
// The kardianos service registration replaces any prior unit with the same
// name so re-running install is idempotent — matching the CLI's behavior
// and avoiding "service already registered" footguns when an operator
// re-clicks the dashboard button.
func (realInstaller) Install(ctx context.Context, opts installer.Options) error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	src, _ = filepath.Abs(src)

	dst := opts.BinaryPath()

	// Stop any existing service before copying the binary to release the file lock
	if runtime.GOOS == "windows" && !opts.UserMode {
		cfg := installer.BuildSvcConfig(opts)
		if svc, err := service.New(&program{}, cfg); err == nil {
			_ = svc.Stop()
		}
	}

	// Forcefully kill any other running instances of kite-collector.exe on Windows
	// to make sure no file locks remain (excluding this installer's process).
	if runtime.GOOS == "windows" {
		currentPid := os.Getpid()
		//#nosec G204 -- PID is an integer retrieved via os.Getpid(), not user input.
		killCmd := exec.CommandContext(ctx, "taskkill", "/F", "/IM", "kite-collector.exe", "/FI", fmt.Sprintf("PID ne %d", currentPid))
		setHideWindow(killCmd)
		_ = killCmd.Run()
		time.Sleep(300 * time.Millisecond) // Give the OS a moment to clean up process handles
	}

	// Retry loop for copying and renaming the binary, since Windows might take a moment
	// to release the file lock on the running executable after stopping/killing the process.
	var binErr error
	for i := 0; i < 5; i++ {
		binErr = installer.InstallBinary(src, dst)
		if binErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if binErr != nil {
		return fmt.Errorf("install binary: %w", binErr)
	}
	if mkErr := os.MkdirAll(opts.CertsDir, 0o750); mkErr != nil {
		return fmt.Errorf("create certs dir %s: %w", opts.CertsDir, mkErr)
	}
	if pathErr := installer.ConfigurePath(opts); pathErr != nil {
		return fmt.Errorf("configure PATH: %w", pathErr)
	}
	if runtime.GOOS == "windows" && opts.UserMode {
		return nil
	}

	cfg := installer.BuildSvcConfig(opts)
	svc, svcErr := service.New(&program{}, cfg)
	if svcErr != nil {
		return fmt.Errorf("create service handle: %w", svcErr)
	}
	// Best-effort stop and uninstall first so re-install replaces any stale unit.
	_ = svc.Stop()
	_ = svc.Uninstall()
	if instErr := svc.Install(); instErr != nil {
		return fmt.Errorf("install service: %w", instErr)
	}
	return nil
}
