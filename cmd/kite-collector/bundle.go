package main

import (
	"errors"
	"fmt"
	"io"

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

// uninstallBundledOsquery deregisters the sibling daemon alongside the
// collector's own service. No-op on the plain build.
func uninstallBundledOsquery(opts installer.Options) error {
	if !installer.BundleAvailable() {
		return nil
	}
	if err := installer.UninstallOsqueryBundle(opts); err != nil {
		return fmt.Errorf("uninstall bundled osquery: %w", err)
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
