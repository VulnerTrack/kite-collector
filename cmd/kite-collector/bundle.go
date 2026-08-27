package main

import (
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// setupVariant names which artifact is running, using the same vocabulary
// WindowsInstallerArtifact.variant uses in RFC-0156 Section 4.1 so the install
// log and the release provenance rows agree on one word.
func setupVariant() string {
	if installer.BundleAvailable() {
		return installer.BundleVariantOsquery
	}
	return installer.BundleVariantPlain
}

// resolveBundleInstallDir applies the R7 pre-flight decision.
//
// Detection runs on every build so the log line is always available, but the
// *adoption* — writing into a previously-installed tree rather than this
// binary's own smart default — is deliberately limited to the self-contained
// bundle artifact. RFC-0156 explicitly keeps the existing MSI and plain
// flat-binary channels untouched (Section 2.2, MUST NOT), and silently
// relocating where `kite-collector install` puts things on the plain channel
// would be exactly that kind of untouched-channel change.
func resolveBundleInstallDir(
	opts installer.Options,
	out io.Writer,
	log *installer.InstallLog,
) installer.Options {
	prior := installer.DetectPriorInstall()
	if !prior.Found() {
		return opts
	}

	code := installer.LogCodeUpgradeDetectedPriorSelf
	if prior.Kind == installer.PriorInstallMSI {
		code = installer.LogCodeUpgradeDetectedPriorMSI
	}
	logEvent(log, code, "prior kite-collector installation detected",
		"kind", prior.Kind,
		"display_name", prior.DisplayName,
		"display_version", prior.DisplayVersion,
		"product_code", prior.ProductCode,
		"install_location", prior.InstallLocation,
		"preflight_result", prior.PreflightResult())
	writeLine(out, fmt.Sprintf("  ›  found a prior %s install (%s)",
		prior.Kind, prior.DisplayName))

	if !installer.BundleAvailable() {
		return opts
	}
	resolved := installer.ResolveInstallDir(opts, prior)
	if resolved == opts.BinaryDir {
		return opts
	}
	logEvent(log, installer.LogCodeUpgradeAdoptedInstallDir,
		"upgrading the existing installation in place",
		"from", opts.BinaryDir,
		"to", resolved)
	writeLine(out, fmt.Sprintf("  ›  upgrading it in place at %s", resolved))
	opts.BinaryDir = resolved
	return opts
}

// installBundledOsquery runs the osquery half of a self-contained install.
//
// A no-op returning nil on the plain build: R2 makes bundling a build-time
// decision, so every shared code path (CLI install, dashboard install API,
// double-click wizard) calls this unconditionally and the tag decides whether
// anything happens.
func installBundledOsquery(
	opts installer.Options,
	out io.Writer,
	log *installer.InstallLog,
) error {
	if !installer.BundleAvailable() {
		return nil
	}
	if opts.UserMode {
		// kite-osqueryd must run as LocalSystem to read the system-wide state
		// FIM/YARA discovery is about, and a non-elevated process cannot
		// register a machine service. Skipping loudly beats failing the whole
		// install: the collector itself installs fine in user mode.
		logEvent(log, installer.LogCodeBundleSkippedUserMode,
			"osquery bundle skipped for a per-user install")
		writeLine(out, "  -  osquery bundle skipped (user-mode install cannot "+
			"register a machine service)")
		return nil
	}

	res, err := installer.InstallOsqueryBundle(opts)
	switch {
	case errors.Is(err, installer.ErrBundleNotBuilt):
		logEvent(log, installer.LogCodeBundleSkippedNotAvailable,
			"no embedded osquery payload in this build")
		return nil
	case err != nil:
		logEvent(log, installer.LogCodeServiceRegisterFailed,
			"osquery bundle install failed",
			"service", installer.OsquerySvcName,
			"error", err.Error())
		return fmt.Errorf("install bundled osquery: %w", err)
	}

	logEvent(log, installer.LogCodeServiceRegistered,
		"osquery sibling service registered",
		"service", installer.OsquerySvcName,
		"osquery_version", res.Manifest.ComponentVersion,
		"install_dir", res.InstallDir,
		"recovery_configured", res.RecoverySet,
		"started", res.Started)
	logEvent(log, installer.LogCodeSocketEnvPublished,
		"osquery extensions socket published machine-wide",
		"variable", installer.OsquerySocketEnvVar,
		"value", res.SocketPath)

	writeLine(out, fmt.Sprintf("  ✓  osquery %s payload installed to %s",
		res.Manifest.ComponentVersion, res.InstallDir))
	writeLine(out, fmt.Sprintf("  ✓  service %q registered with SCM recovery actions",
		installer.OsquerySvcName))
	writeLine(out, fmt.Sprintf("  ✓  %s=%s",
		installer.OsquerySocketEnvVar, res.SocketPath))
	return nil
}

// installSiblingOsquery is the CLI entry point for the optional osquery half.
//
// Two lanes register the same kite-osqueryd service, and which one applies is
// decided by the artifact, not by the operator:
//
//   - bundled — this binary carries a checksum-pinned osqueryd payload
//     (-tags osquery_bundle). It installs unconditionally, because an operator
//     who downloaded kite-collector-osquery has already asked for osquery.
//   - host — no payload, and the platform adopts the operator's own osqueryd
//     (macOS). Requested explicitly with --with-osquery: registering a new
//     machine-wide daemon is not something a plain `install` should do behind
//     the operator's back.
//
// requested is answered rather than ignored on platforms with no host lane: a
// flag that silently does nothing is worse than one that says why.
func installSiblingOsquery(
	opts installer.Options,
	requested bool,
	out io.Writer,
	log *installer.InstallLog,
) error {
	if installer.BundleAvailable() {
		// The payload lane wins: asking for --with-osquery on the bundle
		// artifact is redundant, not contradictory.
		return installBundledOsquery(opts, out, log)
	}
	if !requested {
		return nil
	}
	if !installer.HostOsqueryInstallSupported() {
		logEvent(log, installer.LogCodeHostOsqueryUnsupported,
			"host-osquery registration unsupported on this platform",
			"goos", runtime.GOOS)
		return fmt.Errorf(
			"--with-osquery: %w; install the kite-collector-osquery package instead, which ships osqueryd as the %s service",
			installer.ErrHostOsqueryUnsupported, installer.OsquerySvcName)
	}
	return installHostOsquery(opts, out, log)
}

// installHostOsquery registers kite-osqueryd against the operator's osqueryd.
func installHostOsquery(
	opts installer.Options,
	out io.Writer,
	log *installer.InstallLog,
) error {
	res, err := installer.InstallHostOsquery(opts)
	switch {
	case errors.Is(err, installer.ErrHostOsqueryUserMode):
		// Same reasoning as the bundled lane: skipping loudly beats failing
		// the whole install, because the collector itself installs fine in
		// user mode.
		logEvent(log, installer.LogCodeBundleSkippedUserMode,
			"osquery service skipped for a per-user install")
		writeLine(out, "  -  osquery skipped (a per-user install cannot "+
			"register a machine daemon)")
		return nil
	case errors.Is(err, installer.ErrHostOsquerydNotFound):
		logEvent(log, installer.LogCodeHostOsqueryNotFound,
			"no osqueryd found on this host")
		return fmt.Errorf(
			"--with-osquery: %w; install it first with `brew install --cask osquery` "+
				"or the pkg from https://osquery.io/downloads", err)
	case err != nil:
		logEvent(log, installer.LogCodeServiceRegisterFailed,
			"host osquery registration failed",
			"service", installer.OsquerySvcName,
			"error", err.Error())
		return fmt.Errorf("register %s: %w", installer.OsquerySvcName, err)
	}

	logEvent(log, installer.LogCodeHostOsqueryAdopted,
		"osquery sibling service registered against the host osqueryd",
		"service", installer.OsquerySvcName,
		"daemon_path", res.DaemonPath,
		"daemon_origin", res.DaemonOrigin,
		"data_dir", res.DataDir,
		"socket", res.SocketPath,
		"started", res.Started)
	writeLine(out, fmt.Sprintf("  ✓  service %q registered against %s",
		installer.OsquerySvcName, res.DaemonPath))
	writeLine(out, fmt.Sprintf("  ✓  osquery extensions socket %s", res.SocketPath))
	if res.ConfigPreserved {
		logEvent(log, installer.LogCodeHostOsqueryConfigKept,
			"existing osquery configuration left untouched",
			"config", installer.OsqueryConfigPath(opts))
		writeLine(out, fmt.Sprintf("  ›  kept your existing %s",
			installer.OsqueryConfigPath(opts)))
	} else {
		writeLine(out, fmt.Sprintf("  ✓  osquery configuration written to %s",
			installer.OsqueryConfigPath(opts)))
	}
	return nil
}

// uninstallBundledOsquery deregisters the sibling daemon alongside the
// collector's own service.
//
// Both lanes are torn down, not just the one this binary could have installed:
// an operator who ran `install --with-osquery` and later moved to the bundle
// artifact (or the reverse) still has exactly one kite-osqueryd registration,
// and leaving it behind would keep a machine daemon alive with nothing reading
// its socket.
func uninstallBundledOsquery(opts installer.Options) error {
	if installer.BundleAvailable() {
		if err := installer.UninstallOsqueryBundle(opts); err != nil {
			return fmt.Errorf("uninstall bundled osquery: %w", err)
		}
		return nil
	}
	if !installer.HostOsqueryInstallSupported() {
		return nil
	}
	if err := installer.UninstallHostOsquery(opts); err != nil {
		return fmt.Errorf("uninstall osquery service: %w", err)
	}
	return nil
}

// logEvent tolerates a nil log so callers that have no install log (the
// dashboard's install API, unit tests) share one code path with the wizard.
func logEvent(log *installer.InstallLog, code, msg string, attrs ...any) {
	if log == nil {
		return
	}
	log.Info(msg, append([]any{"code", code}, attrs...)...)
}

// writeLine tolerates a nil writer for the same reason.
func writeLine(out io.Writer, line string) {
	if out == nil {
		return
	}
	_, _ = fmt.Fprintln(out, line)
}

// printOsqueryPlan renders the osquery half of a --dry-run. Detection runs for
// real here — the point of a dry run is to find out whether --with-osquery
// would find a daemon BEFORE registering a system service, not to be told it
// will be attempted.
func printOsqueryPlan(out io.Writer, opts installer.Options, requested bool) {
	if installer.BundleAvailable() {
		writeLine(out, fmt.Sprintf("  install bundled osquery %s and register %q",
			installer.BundledOsqueryVersion(), installer.OsquerySvcName))
		return
	}
	if !requested {
		return
	}
	if !installer.HostOsqueryInstallSupported() {
		writeLine(out, fmt.Sprintf("  --with-osquery: REFUSED on %s (the kite-collector-osquery package owns %s here)",
			runtime.GOOS, installer.OsquerySvcName))
		return
	}
	host, found := installer.DetectHostOsqueryd()
	if !found {
		writeLine(out, "  --with-osquery: no osqueryd found on this host — nothing would be registered")
		return
	}
	writeLine(out, fmt.Sprintf("  register service %q against %s (%s)",
		installer.OsquerySvcName, host.Path, host.Origin))
	writeLine(out, fmt.Sprintf("    config:     %s", installer.OsqueryConfigPath(opts)))
	writeLine(out, fmt.Sprintf("    flagfile:   %s", installer.OsqueryFlagsPath(opts)))
	writeLine(out, fmt.Sprintf("    socket:     %s", installer.OsqueryExtensionsEndpoint()))
}
