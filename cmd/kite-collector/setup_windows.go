//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// setupTimeout bounds an unattended run. Generous relative to the ~1–2 minute
// budget RFC-0156 Section 7.3 sets, because the bundle variant writes a ~55 MB
// payload through on-disk checksum verification on hardware that may be slow
// and may have real-time AV scanning every byte.
const setupTimeout = 5 * time.Minute

// runSetup dispatches an installer-style command line.
func runSetup(args setupArgs) error {
	if args.Help {
		_, _ = fmt.Print(setupUsage())
		return nil
	}
	if !args.Silent {
		// /DIR= without /SILENT: the operator wants the wizard, pre-pointed.
		return runWizard(args)
	}
	return runUnattendedSetup(args)
}

// runUnattendedSetup performs the whole install with no UI (R13).
//
// It is the same code path the wizard drives — realInstaller.Install — rather
// than a parallel implementation, so the silent channel can never drift from
// the interactive one. What is silent-specific is the surrounding structure:
// an explicit elevation check (there is nobody to answer a UAC prompt), a
// structured install log to read afterwards, and a non-zero exit code that
// deployment tooling can act on.
func runUnattendedSetup(args setupArgs) error {
	opts := installer.DetectDefaults().Options

	log := installer.OpenInstallLog(opts, args.LogPath)
	defer func() { _ = log.Close() }()

	log.Info("unattended setup started",
		"code", installer.LogCodeInstallStarted,
		"variant", setupVariant(),
		"version", version,
		"very_silent", args.VerySilent)

	if args.InstallDir != "" {
		if err := installer.ValidateInstallDir(args.InstallDir); err != nil {
			log.Error("rejected the requested install directory",
				"code", installer.LogCodeInstallDirRejected,
				"requested", args.InstallDir,
				"error", err.Error())
			return fmt.Errorf("/DIR: %w", err)
		}
		opts.BinaryDir = filepath.Clean(args.InstallDir)
	}

	// The embedded app.manifest requests requireAdministrator, so a
	// non-elevated process here means elevation was denied or stripped by
	// policy — the aborted_uac_declined terminal state of RFC-0156 Section
	// 4.2, reached without a prompt because nobody is watching.
	if !installer.DetectDefaults().Detected.Privileged {
		log.Error("elevation was not granted",
			"code", installer.LogCodeUACDeclined)
		return errors.New(
			"unattended setup requires Administrator privileges; " +
				"run it from an elevated context (SCCM/Intune system context, " +
				"or an elevated shell)")
	}

	var out io.Writer = os.Stdout
	if args.VerySilent {
		out = io.Discard
	}

	opts = resolveBundleInstallDir(opts, out, log)

	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	if err := newRealInstallerWithLog(log, out).Install(ctx, opts); err != nil {
		log.Error("unattended setup failed",
			"code", installer.LogCodeInstallFailed,
			"error", err.Error())
		return fmt.Errorf("unattended setup: %w", err)
	}

	state := installer.Probe(opts)
	osq := installer.ProbeOsquery(opts)
	log.Info("unattended setup completed",
		"code", installer.LogCodeInstallCompleted,
		"binary", state.BinaryPath,
		"certs_dir", state.CertsDir,
		"service_state", state.ServiceState,
		"osquery_service_state", osq.ServiceState,
		"osquery_version", osq.Version)

	_, _ = fmt.Fprintf(out,
		"kite-collector installed to %s (service %s, %s %s)\n",
		state.BinaryPath, state.ServiceState,
		installer.OsquerySvcName, osq.ServiceState)
	return nil
}
