package installer

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"
)

// Sibling-service identity for the bundled osquery daemon (RFC-0156 R3).
//
// osqueryd is never a child process of the collector — it is an independent,
// namespaced OS service, exactly as the MSI and the deb already register it.
// RFC-0151's daily drift/edge/kite-runner batteries validate that architecture;
// a redesigned child-process model would invalidate them, so the self-contained
// installer registers the same second service under the same name rather than
// supervising the daemon itself.
//
// Every literal here is a deployed contract shared with
// cmd/kite-collector/wix.wxs (Windows MSI) and packaging/deb/ (Linux). Changing
// one without changing the others silently splits a fleet in half.
const (
	OsquerySvcName        = "kite-osqueryd"
	OsquerySvcDisplayName = "Kite Collector osquery daemon"
	OsquerySvcDescription = "Bundled osquery daemon for the Kite Collector agent"

	// OsquerySocketEnvVar is written machine-wide at install time and read by
	// internal/discovery/osquery's socket resolution (cfg -> env -> autodetect).
	OsquerySocketEnvVar = "KITE_OSQUERY_SOCKET"

	// OsqueryWindowsPipe is namespaced for the same reason the service is:
	// standalone osquery owns \\.\pipe\osquery.em, and a bundled daemon must
	// never collide with an operator's own osquery install.
	OsqueryWindowsPipe = `\\.\pipe\kite-osquery.em`

	// OsqueryUnixSocket mirrors the deb's kite-osqueryd.service drop-in.
	OsqueryUnixSocket = "/run/kite-osquery/kite-osquery.em"

	// OsqueryDarwinSocket is the macOS endpoint. It is deliberately NOT
	// OsqueryUnixSocket: macOS has no /run, and its /var/run is recreated
	// empty on every boot, so a socket directory made once at install time
	// would be gone after the first restart and launchd would restart
	// kite-osqueryd into a bind failure forever. /var/kite-osquery is the
	// namespaced analogue of the /var/osquery directory osquery's own pkg
	// creates: persistent, root-owned, and impossible to collide with a
	// standalone osquery install. The other end of this contract is
	// internal/discovery/osquery/socketpaths_darwin.go.
	OsqueryDarwinSocket = "/var/kite-osquery/kite-osquery.em"
)

// SCM failure-recovery tuning (RFC-0156 R5) — the Windows counterpart of the
// Linux unit's Restart=on-failure / RestartSec=5.
//
// The delay is deliberately longer than the collector's 30s per-scan Thrift
// dial deadline (RFC-0151 Section 8.2). A shorter delay would let a genuine
// crash-loop present as a healthy daemon that just happened to be restarting
// every time the dial landed, which is the failure mode RFC-0156 Section 4.2
// flags in the KiteWindowsService risk analysis: recovery that masks the fault
// it is recovering from.
const (
	OsqueryRestartDelay      = 60 * time.Second
	OsqueryRestartDelayLater = 120 * time.Second

	// OsqueryRecoveryResetSeconds is the window after which SCM forgets the
	// accumulated failure count (24h). Held as seconds rather than a Duration
	// because that is the unit ChangeServiceConfig2 takes, and a conversion at
	// the call site would be an unchecked int64 -> uint32 narrowing.
	OsqueryRecoveryResetSeconds uint32 = 86400
)

// OsquerydBinaryName returns the OS-appropriate daemon filename.
func OsquerydBinaryName() string {
	if runtime.GOOS == "windows" {
		return "osqueryd.exe"
	}
	return "osqueryd"
}

// OsqueryExtensionsEndpoint returns the platform's extensions socket/pipe —
// the value written to KITE_OSQUERY_SOCKET and passed as
// --extensions_socket, so both ends of the contract come from one constant.
func OsqueryExtensionsEndpoint() string {
	switch runtime.GOOS {
	case "windows":
		return OsqueryWindowsPipe
	case "darwin":
		return OsqueryDarwinSocket
	default:
		return OsqueryUnixSocket
	}
}

// OsquerySocketDir is the directory the extensions socket is bound in, or ""
// on Windows (a named pipe has no parent directory to create). osqueryd binds
// the socket but does NOT create its parent, so an installer that skips this
// leaves the daemon crash-looping on "cannot bind" — the same reason the deb's
// unit carries RuntimeDirectory=kite-osquery.
func OsquerySocketDir() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return filepath.Dir(OsqueryExtensionsEndpoint())
}

// OsqueryDir is the immutable payload root, alongside the collector binary.
// Matches the MSI's [OSQUERYDIR] (<install dir>\osquery).
func OsqueryDir(opts Options) string {
	return filepath.Join(opts.BinaryDir, "osquery")
}

// OsquerydPath is the daemon the SCM entry points at.
func OsquerydPath(opts Options) string {
	return filepath.Join(OsqueryDir(opts), "osqueryd", OsquerydBinaryName())
}

// OsqueryDataDir holds mutable state (RocksDB database, logs). It lives under
// the collector's own data dir — %ProgramData%\kite-collector\osquery — and not
// under Program Files, matching the MSI's [OSQUERYDATADIR]. The inherited
// ProgramData ACL gives the LocalSystem service full control while non-admins
// cannot modify anything created there, which is also what satisfies osqueryd's
// own safe-permissions checks.
func OsqueryDataDir(opts Options) string {
	return filepath.Join(opts.CertsDir, "osquery")
}

// OsqueryLogDir is where result/status logs land.
func OsqueryLogDir(opts Options) string {
	return filepath.Join(OsqueryDataDir(opts), "logs")
}

// BuildOsquerySvcConfig assembles the kardianos config for the sibling daemon.
//
// The path flags ride the service command line rather than osquery.flags for
// the same reason the MSI puts them there: they resolve against the *actual*
// install location, so a relocated install keeps working, and being passed
// after --flagfile they win over any conflicting flagfile line.
//
// Each flag is one argv element. kardianos hands them to
// mgr.CreateService, which escapes them individually, so a path containing
// spaces ("C:\Program Files\Kite Collector\...") needs no manual quoting — and,
// unlike the MSI's string-concatenated command line, cannot be broken by a
// directory property that ends in a backslash.
func BuildOsquerySvcConfig(opts Options) *service.Config {
	osqDir := OsqueryDir(opts)
	dataDir := OsqueryDataDir(opts)
	return &service.Config{
		Name:        OsquerySvcName,
		DisplayName: OsquerySvcDisplayName,
		Description: OsquerySvcDescription,
		Executable:  OsquerydPath(opts),
		Arguments: []string{
			"--flagfile=" + filepath.Join(osqDir, "osquery.flags"),
			"--config_path=" + filepath.Join(osqDir, "osquery.conf"),
			"--database_path=" + filepath.Join(dataDir, "osquery.db"),
			"--logger_path=" + OsqueryLogDir(opts),
			"--extensions_socket=" + OsqueryExtensionsEndpoint(),
		},
		Option: service.KeyValue{
			// Never a user service: the daemon needs LocalSystem to read the
			// system-wide state FIM/YARA discovery is about.
			"UserService": false,
			"RunAtLoad":   true,
			"KeepAlive":   true,
			"Restart":     "always",
		},
	}
}

// OsqueryState is the probe result for the sibling daemon. Deliberately a
// separate struct from State rather than extra fields on it: State is the wire
// shape of three already-shipping dashboard endpoints, and "is osquery here"
// is a question only the bundle-aware surfaces ask.
//
// Strings precede bools so the struct packs without padding.
type OsqueryState struct {
	ServiceState string `json:"service_state"`
	DaemonPath   string `json:"daemon_path"`
	SocketPath   string `json:"socket_path"`
	// Version is the pinned version this binary would install, empty on a
	// build without the payload compiled in.
	Version string `json:"version,omitempty"`
	// DaemonOrigin is set when DaemonPath came from an osquery install the
	// operator owns rather than from a kite payload (the macOS lane) — see
	// osquery_host.go. Empty on the bundled lanes.
	DaemonOrigin string `json:"daemon_origin,omitempty"`
	// DaemonPresent reports an osqueryd binary on disk at DaemonPath,
	// independent of registration — the two diverge exactly when an install
	// aborted mid-flight. On the host lane the binary is the operator's, so
	// "present but not registered" is also the ordinary state of a machine
	// that has osquery and has not run install --with-osquery.
	DaemonPresent bool `json:"daemon_present"`
	// Bundled reports whether this binary carries an embedded payload at all,
	// i.e. whether it was built with -tags osquery_bundle.
	Bundled bool `json:"bundled"`
}

// ProbeOsquery reports the sibling daemon's on-disk and SCM state. Safe on
// every platform and on plain (non-bundle) builds: an MSI-installed
// kite-osqueryd is reported just as faithfully as a bundle-installed one, which
// is what makes the install-status surface (RFC-0156 R14) meaningful for both
// distribution channels.
func ProbeOsquery(opts Options) OsqueryState {
	st := OsqueryState{
		DaemonPath: OsquerydPath(opts),
		SocketPath: OsqueryExtensionsEndpoint(),
		Bundled:    BundleAvailable(),
		Version:    BundledOsqueryVersion(),
	}
	if _, err := os.Stat(st.DaemonPath); err == nil {
		st.DaemonPresent = true
	} else if host, found := DetectHostOsqueryd(); found {
		// No kite-owned payload at the bundle location. On the host lane
		// (macOS) that is the NORMAL state, not a broken install: the daemon
		// belongs to the operator's osquery. Reporting the bundle path as
		// absent and stopping there would tell the dashboard "no osquery here"
		// on a host that has a perfectly good one.
		st.DaemonPath = host.Path
		st.DaemonOrigin = host.Origin
		st.DaemonPresent = true
	}
	st.ServiceState = serviceStateForConfig(BuildOsquerySvcConfig(opts))
	return st
}
