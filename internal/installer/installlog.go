package installer

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Structured install-log codes (RFC-0156 Section 6.4). Same dotted-code
// convention RFC-0151 established for this codebase, in an `installer.*`
// family so an operator (or a SIEM ingesting %ProgramData% logs) can pivot on a
// stable identifier rather than grepping prose.
//
// Codes are immutable once shipped — add a new one rather than renaming.
const (
	LogCodeInstallStarted            = "installer.run.started"
	LogCodeInstallCompleted          = "installer.run.completed"
	LogCodeInstallFailed             = "installer.run.failed"
	LogCodeUpgradeDetectedPriorMSI   = "installer.upgrade.detected_prior_msi"
	LogCodeUpgradeDetectedPriorSelf  = "installer.upgrade.detected_prior_self_contained"
	LogCodeUpgradeAdoptedInstallDir  = "installer.upgrade.adopted_install_dir"
	LogCodeChecksumMismatch          = "installer.checksum.mismatch"
	LogCodeUACDeclined               = "installer.uac.declined"
	LogCodeServiceRegistered         = "installer.service.registered"
	LogCodeServiceRegisterFailed     = "installer.service.register_failed"
	LogCodeSocketEnvPublished        = "installer.env.socket_published"
	LogCodeInstallLogACLNotApplied   = "installer.log.acl_not_applied"
	LogCodeInstallDirRejected        = "installer.args.install_dir_rejected"
	LogCodeBundleSkippedNotAvailable = "installer.bundle.not_available"
	LogCodeBundleSkippedUserMode     = "installer.bundle.skipped_user_mode"
)

// InstallLogName is the file the install log is appended to inside the
// collector's data directory.
const InstallLogName = "install.log"

// InstallLogPath resolves to %ProgramData%\kite-collector\install.log for a
// per-machine Windows install.
func InstallLogPath(opts Options) string {
	return filepath.Join(opts.CertsDir, InstallLogName)
}

// InstallLog is a JSON-lines structured logger for the install flow, backed by
// a file under the collector's data dir and hardened to Administrators+SYSTEM
// on Windows.
//
// It embeds *slog.Logger so call sites read like the rest of the codebase
// (`log.Info(msg, "code", LogCode…, …)`), rather than inventing a second
// logging vocabulary for one flow.
type InstallLog struct {
	*slog.Logger
	file   *os.File
	extras []*os.File
}

// OpenInstallLog never fails: a wizard that refuses to install because it could
// not open its own log would be a worse outcome than an install nobody can
// audit afterwards. When the file cannot be created (non-elevated run, missing
// directory, read-only disk) the logger falls back to stderr and everything
// else proceeds unchanged.
//
// extraPaths is the /LOG=<path> switch (R13): deployment tooling routinely
// collects installer logs from a share it controls. Those copies are written
// where the operator asked and are deliberately NOT ACL-hardened — the
// canonical %ProgramData% copy is the one this installer makes guarantees
// about, and silently re-ACLing a path the operator chose would be surprising.
func OpenInstallLog(opts Options, extraPaths ...string) *InstallLog {
	logPath := InstallLogPath(opts)

	var out io.Writer = os.Stderr
	var file *os.File
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err == nil {
		//#nosec G304 -- path is derived from resolved install options, never from untrusted input
		opened, openErr := os.OpenFile(
			logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if openErr == nil {
			file = opened
			out = opened
		}
	}

	extras := openExtraLogs(extraPaths)
	if len(extras) > 0 {
		writers := make([]io.Writer, 0, len(extras)+1)
		writers = append(writers, out)
		for _, extra := range extras {
			writers = append(writers, extra)
		}
		out = io.MultiWriter(writers...)
	}

	l := &InstallLog{
		Logger: slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		file:   file,
		extras: extras,
	}
	if file == nil {
		return l
	}
	// Strip the inherited "Users: Read & Execute" ACE %ProgramData% hands down
	// (Section 6.1, Information Disclosure). Best-effort: a log a local
	// administrator can read is the pre-existing state, not a regression.
	if aclErr := HardenFileACL(logPath); aclErr != nil {
		l.Warn("install log ACL not applied",
			"code", LogCodeInstallLogACLNotApplied,
			"path", logPath,
			"error", aclErr.Error())
	}
	return l
}

// openExtraLogs opens the /LOG= destinations, skipping any that cannot be
// created. A bad log path must never fail an install.
func openExtraLogs(paths []string) []*os.File {
	files := make([]*os.File, 0, len(paths))
	for _, p := range paths {
		clean := strings.TrimSpace(p)
		if clean == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
			continue
		}
		//#nosec G304 -- operator-supplied destination from the /LOG= switch
		f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			continue
		}
		files = append(files, f)
	}
	return files
}

// Close releases the underlying files. Safe on a nil receiver and on a
// stderr-backed logger. The first close error wins; the remaining handles are
// still released so a failure cannot leak descriptors.
func (l *InstallLog) Close() error {
	if l == nil {
		return nil
	}
	var firstErr error
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			firstErr = fmt.Errorf("close install log: %w", err)
		}
		l.file = nil
	}
	for _, extra := range l.extras {
		if err := extra.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close extra install log: %w", err)
		}
	}
	l.extras = nil
	return firstErr
}
