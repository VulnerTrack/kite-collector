package installer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"

	"github.com/vulnertrack/kite-collector/internal/installer/osqueryconf"
)

// The host-osquery lane: register kite-osqueryd against an osqueryd the
// operator already installed, instead of one kite vendored.
//
// macOS is the only platform that needs it, and the reason is distribution,
// not technology. The deb and the MSI can carry osqueryd because a Linux
// package and a Windows installer may redistribute a binary as-is; a macOS
// artifact that shipped osqueryd would have to be Developer ID-signed and
// notarized as a unit, and the sibling daemon would then run under kite's
// signature rather than osquery's — which also means kite's TCC (Full Disk
// Access) grant, not osquery's. Adopting the operator's own
// /opt/osquery/lib/osquery.app keeps the daemon signed and TCC-attributed to
// osquery, exactly as `osqueryctl start` would run it.
//
// What kite owns on macOS is therefore only: the configuration, the state
// directory, and the launchd job — all namespaced under kite-osqueryd so they
// can never collide with the io.osquery.agent job the pkg registers.

// Sentinel errors so callers can tell "this platform has a different lane"
// from "the operator has no osquery" — the two need different remediation.
var (
	// ErrHostOsqueryUnsupported is returned on platforms where a package
	// already owns kite-osqueryd. Registering a second one would put two
	// owners on one artifact: on Linux a unit written to /etc/systemd/system
	// shadows the deb's /usr/lib/systemd/system unit, so a later `apt upgrade`
	// silently stops managing the daemon it installed.
	ErrHostOsqueryUnsupported = errors.New("installer: host-osquery registration is not supported on this platform")

	// ErrHostOsquerydNotFound means no osqueryd was found in any well-known
	// location or on PATH.
	ErrHostOsquerydNotFound = errors.New("installer: no osqueryd found on this host")

	// ErrHostOsqueryUserMode means the install is per-user. kite-osqueryd is a
	// machine daemon by construction: it reads the system-wide state FIM/YARA
	// discovery is about, and a LaunchAgent runs as the logged-in user.
	ErrHostOsqueryUserMode = errors.New("installer: kite-osqueryd cannot be registered from a per-user install")
)

// Origins reported by DetectHostOsqueryd, stable enough to grep for in install
// logs.
const (
	// HostOsqueryOriginPkg is the app bundle laid down by the official macOS
	// pkg — and therefore also by `brew install --cask osquery`, which
	// installs that same pkg.
	HostOsqueryOriginPkg = "osquery-pkg"
	// HostOsqueryOriginHomebrew is a Homebrew prefix bin.
	HostOsqueryOriginHomebrew = "homebrew"
	// HostOsqueryOriginSystem is a system bin directory.
	HostOsqueryOriginSystem = "system"
	// HostOsqueryOriginPath is a PATH lookup — the last resort.
	HostOsqueryOriginPath = "path"
)

// HostOsquery is an osqueryd binary that belongs to the operator.
type HostOsquery struct {
	// Path is symlink-resolved. The official pkg puts a /usr/local/bin
	// symlink next to the real app-bundle binary, and osqueryd applies its own
	// "is this path safe" check (root-owned, not writable by others) to the
	// paths it is handed — /usr/local/bin is admin-group writable on macOS,
	// the app bundle is not.
	Path   string `json:"path"`
	Origin string `json:"origin"`
}

// hostOsquerydCandidates lists the well-known daemon locations for this
// platform, most authoritative first.
func hostOsquerydCandidates() []HostOsquery {
	switch runtime.GOOS {
	case "darwin":
		return []HostOsquery{
			// The real binary inside the pkg's app bundle. Preferred over the
			// symlink below so the path handed to launchd is the signed,
			// root-owned one.
			{Path: "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd", Origin: HostOsqueryOriginPkg},
			{Path: "/usr/local/bin/osqueryd", Origin: HostOsqueryOriginSystem},
			{Path: "/opt/homebrew/bin/osqueryd", Origin: HostOsqueryOriginHomebrew},
		}
	case "windows":
		return []HostOsquery{
			{Path: `C:\Program Files\osquery\osqueryd\osqueryd.exe`, Origin: HostOsqueryOriginSystem},
		}
	default:
		return []HostOsquery{
			// The kite deb's own payload first: on a host that has both, that
			// is the one kite configured.
			{Path: "/opt/kite-collector/osquery/bin/osqueryd", Origin: HostOsqueryOriginPkg},
			{Path: "/opt/osquery/bin/osqueryd", Origin: HostOsqueryOriginPkg},
			{Path: "/usr/bin/osqueryd", Origin: HostOsqueryOriginSystem},
		}
	}
}

// DetectHostOsqueryd returns the operator's osqueryd, or false when none is
// installed. Safe on every platform — it is also what the doctor check uses to
// explain "osquery discovery is inert here" with a path instead of a shrug.
func DetectHostOsqueryd() (HostOsquery, bool) {
	for _, c := range hostOsquerydCandidates() {
		if resolved, ok := resolveDaemon(c.Path); ok {
			c.Path = resolved
			return c, true
		}
	}
	if p, err := exec.LookPath(OsquerydBinaryName()); err == nil {
		if resolved, ok := resolveDaemon(p); ok {
			return HostOsquery{Path: resolved, Origin: HostOsqueryOriginPath}, true
		}
	}
	return HostOsquery{}, false
}

// resolveDaemon accepts a candidate only if it is a regular, executable file
// after symlink resolution. A dangling /usr/local/bin symlink is what a
// half-removed osquery leaves behind, and handing that to launchd produces a
// job that fails to spawn with no obvious cause.
func resolveDaemon(path string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	fi, err := os.Stat(resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return "", false
	}
	return resolved, true
}

// HostOsqueryInstallSupported reports whether this platform registers
// kite-osqueryd against a host osqueryd. See ErrHostOsqueryUnsupported for why
// Linux and Windows do not.
func HostOsqueryInstallSupported() bool { return runtime.GOOS == "darwin" }

// OsqueryConfigPath and OsqueryFlagsPath live in the state directory rather
// than under /etc, because on this lane nothing else owns them: there is no
// dpkg conffile and no MSI component, so they belong with the database and the
// logs in the one tree the collector itself created. Both are passed on the
// launchd job's command line, so a relocated install keeps working.
func OsqueryConfigPath(opts Options) string {
	return filepath.Join(OsqueryDataDir(opts), "osquery.conf")
}

// OsqueryFlagsPath is the --flagfile the job is started with.
func OsqueryFlagsPath(opts Options) string {
	return filepath.Join(OsqueryDataDir(opts), "osquery.flags")
}

// BuildHostOsquerySvcConfig assembles the kardianos config for a kite-osqueryd
// job backed by the operator's daemon.
//
// It mirrors BuildOsquerySvcConfig flag for flag — same name, same path-flags-
// on-the-command-line split, same socket — and differs only in Executable and
// in where the config files live. That is deliberate: ProbeOsquery,
// `kite-collector service status`, and the dashboard all key on the service
// NAME, so both lanes must present one service with one contract.
func BuildHostOsquerySvcConfig(opts Options, daemon string) *service.Config {
	dataDir := OsqueryDataDir(opts)
	return &service.Config{
		Name:        OsquerySvcName,
		DisplayName: OsquerySvcDisplayName,
		Description: OsquerySvcDescription,
		Executable:  daemon,
		Arguments: []string{
			"--flagfile=" + OsqueryFlagsPath(opts),
			"--config_path=" + OsqueryConfigPath(opts),
			"--database_path=" + filepath.Join(dataDir, "osquery.db"),
			"--logger_path=" + OsqueryLogDir(opts),
			"--extensions_socket=" + OsqueryExtensionsEndpoint(),
		},
		Option: service.KeyValue{
			"UserService": false,
			"RunAtLoad":   true,
			"KeepAlive":   true,
			"Restart":     "always",
		},
	}
}

// StageOsqueryConfig writes the osquery.conf/osquery.flags pair into the state
// directory, creating it and the log directory on the way.
//
// Existing files are LEFT ALONE and reported via the returned preserved flag.
// Once written, the operator owns them: they are where FIM file_paths and YARA
// rules get turned on, and an upgrade that silently reverted those edits would
// disarm monitoring the operator deliberately armed. Deleting a file is how
// you ask for the shipped default back.
//
// Modes matter here. osqueryd applies a "safe permissions" check to the files
// it is pointed at and refuses to load anything group- or world-writable, so
// 0600 on the files and 0750 on the directories is not belt-and-braces — a
// looser mode is a daemon that will not start.
//
// Every path is derived from opts, so this is safe to call against a temp
// directory. The fixed system socket directory is deliberately NOT created
// here — see ensureSocketDir.
func StageOsqueryConfig(opts Options) (preserved bool, err error) {
	for _, dir := range []string{OsqueryDataDir(opts), OsqueryLogDir(opts)} {
		if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
			return false, fmt.Errorf("create osquery dir %s: %w", dir, mkErr)
		}
	}

	files := []struct {
		path    string
		content []byte
	}{
		{OsqueryConfigPath(opts), osqueryconf.DarwinConf()},
		{OsqueryFlagsPath(opts), osqueryconf.DarwinFlags()},
	}
	for _, f := range files {
		if _, statErr := os.Stat(f.path); statErr == nil {
			preserved = true
			continue
		}
		if wErr := os.WriteFile(f.path, f.content, 0o600); wErr != nil {
			return preserved, fmt.Errorf("write %s: %w", f.path, wErr)
		}
	}
	return preserved, nil
}

// InstallHostOsquery registers kite-osqueryd against the operator's osqueryd.
//
// Ordering matches InstallOsqueryBundle for the same reason it does there:
// deregister first (kardianos' launchd Install refuses to overwrite an
// existing plist), lay down every file and directory the daemon needs before
// it can ever be started, and roll the registration back on any later failure
// so a run that did not complete never leaves a half-configured job behind.
func InstallHostOsquery(opts Options) (OsqueryInstallResult, error) {
	res := OsqueryInstallResult{
		Mode:       OsqueryModeHost,
		DataDir:    OsqueryDataDir(opts),
		SocketPath: OsqueryExtensionsEndpoint(),
	}
	if !HostOsqueryInstallSupported() {
		return res, ErrHostOsqueryUnsupported
	}
	if opts.UserMode {
		return res, ErrHostOsqueryUserMode
	}

	host, found := DetectHostOsqueryd()
	if !found {
		return res, ErrHostOsquerydNotFound
	}
	res.DaemonPath = host.Path
	res.DaemonOrigin = host.Origin
	res.InstallDir = filepath.Dir(host.Path)

	svc, err := service.New(&noopProgram{}, BuildHostOsquerySvcConfig(opts, host.Path))
	if err != nil {
		return res, fmt.Errorf("create %s service handle: %w", OsquerySvcName, err)
	}
	// Both fail when nothing is registered yet, which is the fresh-install
	// case.
	_ = svc.Stop()
	_ = svc.Uninstall()

	preserved, err := StageOsqueryConfig(opts)
	if err != nil {
		return res, err
	}
	res.ConfigPreserved = preserved

	if sockErr := ensureSocketDir(); sockErr != nil {
		return res, sockErr
	}

	if instErr := svc.Install(); instErr != nil {
		return res, fmt.Errorf("register %s service: %w", OsquerySvcName, instErr)
	}
	if startErr := svc.Start(); startErr != nil {
		_ = svc.Uninstall()
		return res, fmt.Errorf("start %s service: %w", OsquerySvcName, startErr)
	}
	res.Started = true
	return res, nil
}

// ensureSocketDir creates the directory the extensions socket is bound in.
// osqueryd binds the socket but never creates its parent, so without this the
// daemon comes up, fails to bind, and launchd restarts it into the same
// failure forever — the macOS equivalent of the deb unit's
// RuntimeDirectory=kite-osquery.
//
// It writes to a fixed system path (OsquerySocketDir), which is why it is not
// folded into StageOsqueryConfig: that one is called from tests against a temp
// tree and must never touch /var.
func ensureSocketDir() error {
	dir := OsquerySocketDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create osquery socket dir %s: %w", dir, err)
	}
	return nil
}

// UninstallHostOsquery stops and deregisters the job. Like
// UninstallOsqueryBundle it leaves the state directory alone, so a re-install
// keeps the FIM event history the daemon has buffered — and, more importantly
// here, the operator's edits to osquery.conf. The daemon binary is never
// touched: it was never kite's.
//
// Deregistration is keyed on the service NAME, so it deliberately does not
// re-detect the daemon first. An osquery that was uninstalled before the
// collector was must still leave zero kite-osqueryd registrations behind, and
// a teardown that first asked "where is osqueryd?" would skip exactly that
// case.
func UninstallHostOsquery(opts Options) error {
	svc, err := service.New(&noopProgram{}, BuildHostOsquerySvcConfig(opts, OsquerydBinaryName()))
	if err != nil {
		return fmt.Errorf("create %s service handle: %w", OsquerySvcName, err)
	}
	_ = svc.Stop()
	_ = svc.Uninstall()
	return nil
}
