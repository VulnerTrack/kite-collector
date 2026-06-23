package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// Service identity. The kardianos library uses this single name as the
// systemd unit name, launchd plist label, and Windows Service name.
const (
	svcName        = "kite-collector"
	svcDisplayName = "Kite Collector"
	svcDescription = "Continuous asset discovery and OTLP streaming agent"
)

// ---------------------------------------------------------------------------
// program — implements service.Interface
// ---------------------------------------------------------------------------

// program is the service.Interface implementation the OS service manager
// drives. Start spawns runAgent in a goroutine, Stop cancels its context.
type program struct {
	cancel   context.CancelFunc
	done     chan struct{}
	certsDir string
	cfgFile  string
	dbPath   string
	endpoint string
	verbose  bool
}

func (p *program) Start(_ service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		// runAgent's error is intentionally swallowed here: the service
		// manager only cares about the process exit code, and unrecoverable
		// errors will already have been logged by runAgent itself.
		_ = runAgent(ctx, p.cfgFile, p.dbPath, "", p.certsDir, p.endpoint, "", p.verbose, true)
	}()
	return nil
}

func (p *program) Stop(_ service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
	}
	return nil
}

// ---------------------------------------------------------------------------
// Service config builder
// ---------------------------------------------------------------------------

type svcOpts struct {
	executable  string
	certsDir    string
	cfgFile     string
	dbPath      string
	endpoint    string
	userService bool
	verbose     bool
}

func buildSvcConfig(o svcOpts) *service.Config {
	args := []string{"service", "run", "--certs-dir", o.certsDir}
	if o.cfgFile != "" {
		args = append(args, "--config", o.cfgFile)
	}
	if o.dbPath != "" {
		args = append(args, "--db", o.dbPath)
	}
	if o.endpoint != "" {
		args = append(args, "--endpoint", o.endpoint)
	}
	if o.verbose {
		args = append(args, "--verbose")
	}

	return &service.Config{
		Name:        svcName,
		DisplayName: svcDisplayName,
		Description: svcDescription,
		Executable:  o.executable,
		Arguments:   args,
		Option: service.KeyValue{
			"UserService": o.userService,
			"RunAtLoad":   true,
			"KeepAlive":   true,
			"Restart":     "always",
		},
	}
}

// newProgramService returns the kardianos service paired with a fresh program{}
// for the run subcommand. The OS service manager invokes the binary with the
// arguments embedded at install time, so the run subcommand re-reads the same
// flags off its own command line.
func newProgramService(o svcOpts) (service.Service, *program, error) {
	prg := &program{
		certsDir: o.certsDir,
		cfgFile:  o.cfgFile,
		dbPath:   o.dbPath,
		endpoint: o.endpoint,
		verbose:  o.verbose,
	}
	svc, err := service.New(prg, buildSvcConfig(o))
	if err != nil {
		return nil, nil, fmt.Errorf("create service: %w", err)
	}
	return svc, prg, nil
}

// ---------------------------------------------------------------------------
// install / uninstall commands
// ---------------------------------------------------------------------------

func newInstallCmd() *cobra.Command {
	var (
		certsDir  string
		binaryDir string
		cfgFile   string
		dbPath    string
		endpoint  string
		userMode  bool
		dryRun    bool
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install kite-collector as a system or user service",
		Long: `Register the kite-collector streaming agent with the OS service manager.

This command works on Linux (systemd, upstart, sysv, OpenRC), macOS (launchd),
and Windows (Service Control Manager) via the kardianos/service library.

By default, the service is installed system-wide and runs as root / LocalSystem
(requires sudo on Unix, Administrator PowerShell on Windows). Pass --user to
install a per-user service that runs without elevated privileges.

What it does:
  1. Copies this binary to {binary-dir}/kite-collector
  2. Creates {certs-dir}/   (certificate store)
  3. Registers the "kite-collector" service with the OS service manager
  4. Configures it to run "kite-collector service run --certs-dir {certs-dir}"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certsDir == "" {
				certsDir = defaultCertsDir(userMode)
			}
			if binaryDir == "" {
				binaryDir = defaultBinaryDir(userMode)
			}
			return runInstall(cmd, installArgs{
				certsDir:  certsDir,
				binaryDir: binaryDir,
				cfgFile:   cfgFile,
				dbPath:    dbPath,
				endpoint:  endpoint,
				userMode:  userMode,
				dryRun:    dryRun,
				verbose:   verbose,
			})
		},
	}

	cmd.Flags().BoolVar(&userMode, "user", false,
		"install as a per-user service (no root/Administrator needed)")
	cmd.Flags().StringVar(&certsDir, "certs-dir", "",
		"certificate store path (default: OS-appropriate, varies with --user)")
	cmd.Flags().StringVar(&binaryDir, "binary-dir", "",
		"directory to install the kite-collector binary (default: OS-appropriate)")
	cmd.Flags().StringVar(&cfgFile, "config", "",
		"path to configuration file to pass to the service (optional)")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"path to SQLite database file to pass to the service (optional)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "",
		"OTLP endpoint override to pass to the service (optional)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"run the service with debug logging")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"print what would be done without making any changes")

	return cmd
}

func newUninstallCmd() *cobra.Command {
	var userMode bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the kite-collector service from the OS service manager",
		Long: `Stop the kite-collector service if running and unregister it.

Pass --user to target a per-user service registration.

The installed binary and certificate store are left in place; remove them
manually if desired.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			svc, _, err := newProgramService(svcOpts{
				userService: userMode,
				// Executable & certsDir are not consulted by Stop/Uninstall,
				// but Name is required so kardianos can locate the unit.
			})
			if err != nil {
				return fmt.Errorf("create service handle: %w", err)
			}
			// Best-effort stop; ignore "not running".
			_ = svc.Stop()
			if err := svc.Uninstall(); err != nil {
				return fmt.Errorf("uninstall service: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stdout, "  ✓  %s service removed\n", svcName)
			return nil
		},
	}

	cmd.Flags().BoolVar(&userMode, "user", false,
		"uninstall the per-user service registration")
	return cmd
}

// ---------------------------------------------------------------------------
// service parent command — start / stop / restart / status / run
// ---------------------------------------------------------------------------

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Control the installed kite-collector service",
	}
	cmd.AddCommand(
		newServiceControlCmd("start", "Start the kite-collector service"),
		newServiceControlCmd("stop", "Stop the kite-collector service"),
		newServiceControlCmd("restart", "Restart the kite-collector service"),
		newServiceStatusCmd(),
		newServiceRunCmd(),
	)
	return cmd
}

func newServiceControlCmd(action, short string) *cobra.Command {
	var userMode bool
	cmd := &cobra.Command{
		Use:   action,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			svc, _, err := newProgramService(svcOpts{userService: userMode})
			if err != nil {
				return fmt.Errorf("create service handle: %w", err)
			}
			return service.Control(svc, action)
		},
	}
	cmd.Flags().BoolVar(&userMode, "user", false, "target the per-user service")
	return cmd
}

func newServiceStatusCmd() *cobra.Command {
	var userMode bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print the kite-collector service status",
		RunE: func(_ *cobra.Command, _ []string) error {
			svc, _, err := newProgramService(svcOpts{userService: userMode})
			if err != nil {
				return fmt.Errorf("create service handle: %w", err)
			}
			st, statusErr := svc.Status()
			switch {
			case errors.Is(statusErr, service.ErrNotInstalled):
				fmt.Println("not installed")
				return nil
			case statusErr != nil:
				return fmt.Errorf("query service status: %w", statusErr)
			}
			switch st {
			case service.StatusRunning:
				fmt.Println("running")
			case service.StatusStopped:
				fmt.Println("stopped")
			case service.StatusUnknown:
				fmt.Println("unknown")
			default:
				fmt.Println("unknown")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&userMode, "user", false, "target the per-user service")
	return cmd
}

// newServiceRunCmd is invoked by the OS service manager (systemd ExecStart,
// launchd ProgramArguments, Windows SCM). It is hidden from `--help` to keep
// the user-facing surface clean, but remains discoverable via direct lookup.
func newServiceRunCmd() *cobra.Command {
	var (
		certsDir string
		cfgFile  string
		dbPath   string
		endpoint string
		verbose  bool
		userMode bool
	)
	cmd := &cobra.Command{
		Use:    "run",
		Short:  "Run as a managed service (invoked by the OS service manager)",
		Hidden: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if certsDir == "" {
				certsDir = defaultCertsDir(userMode)
			}
			// Self-heal: install creates this dir, but it may be missing if the
			// install was non-elevated on Windows, or an operator removed it.
			// Creating it here lets the service come up either way; if creation
			// fails (e.g. permission denied under LocalSystem), surface that
			// rather than letting the agent crash on the first cert write.
			if err := os.MkdirAll(certsDir, 0o750); err != nil {
				return fmt.Errorf("ensure certs dir %s: %w", certsDir, err)
			}
			svc, _, err := newProgramService(svcOpts{
				userService: userMode,
				certsDir:    certsDir,
				cfgFile:     cfgFile,
				dbPath:      dbPath,
				endpoint:    endpoint,
				verbose:     verbose,
			})
			if err != nil {
				return fmt.Errorf("create service: %w", err)
			}
			return svc.Run()
		},
	}
	cmd.Flags().StringVar(&certsDir, "certs-dir", "", "certificate store path")
	cmd.Flags().StringVar(&cfgFile, "config", "", "path to configuration file")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to SQLite database")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "OTLP endpoint override")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "debug logging")
	cmd.Flags().BoolVar(&userMode, "user", false, "service was installed in user mode")
	return cmd
}

// ---------------------------------------------------------------------------
// install implementation
// ---------------------------------------------------------------------------

type installArgs struct {
	certsDir  string
	binaryDir string
	cfgFile   string
	dbPath    string
	endpoint  string
	userMode  bool
	dryRun    bool
	verbose   bool
}

func runInstall(cmd *cobra.Command, a installArgs) error {
	out := cmd.OutOrStdout()

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	src, _ = filepath.Abs(src)

	dst := filepath.Join(a.binaryDir, binaryName())

	opts := svcOpts{
		userService: a.userMode,
		executable:  dst,
		certsDir:    a.certsDir,
		cfgFile:     a.cfgFile,
		dbPath:      a.dbPath,
		endpoint:    a.endpoint,
		verbose:     a.verbose,
	}
	cfg := buildSvcConfig(opts)

	if a.dryRun {
		_, _ = fmt.Fprintln(out, "-- dry-run: no files will be written --")
		_, _ = fmt.Fprintf(out, "  copy   %s → %s\n", src, dst)
		_, _ = fmt.Fprintf(out, "  mkdir  %s\n", a.certsDir)
		_, _ = fmt.Fprintf(out, "  register service %q (user=%t)\n", cfg.Name, a.userMode)
		_, _ = fmt.Fprintf(out, "    executable: %s\n", cfg.Executable)
		_, _ = fmt.Fprintf(out, "    arguments:  %v\n", cfg.Arguments)
		_, _ = fmt.Fprintf(out, "    platform:   %s\n", service.Platform())
		return nil
	}

	// Defer the post-install report so it surfaces the *current* state no
	// matter how runInstall exits: full success, mid-install failure (binary
	// copied but service registration failed, etc.), or a re-run where things
	// already exist. Captures the resolved paths so the message points at the
	// right --certs-dir, not the user's typed defaults.
	defer printPostInstall(out, dst, a.certsDir, a.userMode)

	if binErr := installBinary(src, dst); binErr != nil {
		return fmt.Errorf("install binary: %w", binErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", dst)

	if mkErr := os.MkdirAll(a.certsDir, 0o750); mkErr != nil {
		return fmt.Errorf("create certs dir %s: %w", a.certsDir, mkErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", a.certsDir)

	svc, svcErr := service.New(&program{}, cfg)
	if svcErr != nil {
		return fmt.Errorf("create service handle: %w", svcErr)
	}

	// If a previous registration exists, replace it. Ignore errors —
	// uninstall fails when nothing is installed, which is the common case.
	_ = svc.Uninstall()

	if instErr := svc.Install(); instErr != nil {
		return fmt.Errorf("install service: %w", instErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  service %q registered (%s)\n", cfg.Name, service.Platform())

	return nil
}

// ---------------------------------------------------------------------------
// Post-install state report
// ---------------------------------------------------------------------------

// installState is what the post-install report shows: the on-disk and SCM
// reality after `install` finishes (or fails midway). Probed, not assumed.
type installState struct {
	serviceState   string
	binaryPresent  bool
	certsDirExists bool
	certsEnrolled  bool
}

// enrollmentFiles are the three PEMs that `enroll` writes; all three present
// means this agent has completed enrollment.
var enrollmentFiles = []string{"ca.pem", "agent.pem", "agent-key.pem"}

// probeInstall returns the on-disk + service-manager state without assuming
// install completed successfully. Errors from the service handle are mapped
// to a short string rather than propagated, because this is a status report,
// not a control plane.
func probeInstall(binPath, certsDir string, userMode bool) installState {
	var st installState

	if _, err := os.Stat(binPath); err == nil {
		st.binaryPresent = true
	}
	if fi, err := os.Stat(certsDir); err == nil && fi.IsDir() {
		st.certsDirExists = true
		present := 0
		for _, name := range enrollmentFiles {
			if _, err := os.Stat(filepath.Join(certsDir, name)); err == nil {
				present++
			}
		}
		st.certsEnrolled = present == len(enrollmentFiles)
	}

	svc, _, err := newProgramService(svcOpts{userService: userMode})
	if err != nil {
		st.serviceState = "unknown"
		return st
	}
	s, statusErr := svc.Status()
	switch {
	case errors.Is(statusErr, service.ErrNotInstalled):
		st.serviceState = "not installed"
	case statusErr != nil:
		st.serviceState = "unknown"
	case s == service.StatusRunning:
		st.serviceState = "running"
	case s == service.StatusStopped:
		st.serviceState = "stopped"
	default:
		st.serviceState = "unknown"
	}
	return st
}

// printPostInstall renders the current-state table and a numbered next-steps
// list tailored to that state. Every command in the list is pre-filled with
// the actual binPath and certsDir so the operator can copy-paste verbatim —
// no <placeholders> for things we already know.
func printPostInstall(out io.Writer, binPath, certsDir string, userMode bool) {
	st := probeInstall(binPath, certsDir, userMode)

	check := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Current state:")
	_, _ = fmt.Fprintf(out, "  %s  binary       %s\n", check(st.binaryPresent), binPath)
	_, _ = fmt.Fprintf(out, "  %s  certs dir    %s\n", check(st.certsDirExists), certsDir)
	_, _ = fmt.Fprintf(out, "  %s  enrollment   %s\n", check(st.certsEnrolled), enrollmentLabel(st))
	_, _ = fmt.Fprintf(out, "  -  service      %s\n", st.serviceState)

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Next steps:")
	step := 1
	if !st.certsEnrolled {
		_, _ = fmt.Fprintf(out,
			"  %d. Enroll this agent (one-time) — pass the same --certs-dir the service uses:\n"+
				"       %s enroll --agent-code <code> --token <token> --certs-dir %s\n\n",
			step, binPath, certsDir)
		step++
	}
	_, _ = fmt.Fprintf(out,
		"  %d. Verify OTLP connectivity:\n"+
			"       %s check --certs-dir %s\n\n",
		step, binPath, certsDir)
	step++
	if st.serviceState != "running" {
		_, _ = fmt.Fprintf(out,
			"  %d. Start the service:\n"+
				"       %s service start%s\n\n",
			step, binPath, userFlag(userMode))
		step++
	}
	_, _ = fmt.Fprintf(out, "  %d. View logs:\n%s\n\n", step, logsHint(userMode))
}

// enrollmentLabel returns a one-word state for the enrollment row: the three
// PEMs are present, the dir is empty, or the dir is missing entirely.
func enrollmentLabel(st installState) string {
	switch {
	case st.certsEnrolled:
		return "ca.pem + agent.pem + agent-key.pem present"
	case st.certsDirExists:
		return "empty — run `enroll` to populate"
	default:
		return "certs dir missing"
	}
}

// ---------------------------------------------------------------------------
// Platform defaults
// ---------------------------------------------------------------------------

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "kite-collector.exe"
	}
	return "kite-collector"
}

// defaultBinaryDir returns the conventional location for the binary.
//
//   - Windows system: %ProgramFiles%\kite-collector
//   - Windows user:   %LOCALAPPDATA%\kite-collector
//   - Unix system:    /usr/local/bin
//   - Unix user:      ~/.local/bin
func defaultBinaryDir(userMode bool) string {
	if runtime.GOOS == "windows" {
		if userMode {
			if v := os.Getenv("LOCALAPPDATA"); v != "" {
				return filepath.Join(v, "kite-collector")
			}
		}
		if v := os.Getenv("ProgramFiles"); v != "" {
			return filepath.Join(v, "kite-collector")
		}
		return `C:\Program Files\kite-collector`
	}
	if userMode {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".local", "bin")
		}
	}
	return "/usr/local/bin"
}

// defaultCertsDir returns the conventional certificate store location.
//
//   - Windows system: %ProgramData%\kite-collector
//   - Windows user:   %LOCALAPPDATA%\kite-collector\data
//   - Unix system:    /var/lib/kite-collector
//   - Unix user:      $XDG_DATA_HOME/kite-collector  (or ~/.local/share/kite-collector)
func defaultCertsDir(userMode bool) string {
	if runtime.GOOS == "windows" {
		if userMode {
			if v := os.Getenv("LOCALAPPDATA"); v != "" {
				return filepath.Join(v, "kite-collector", "data")
			}
		}
		if v := os.Getenv("ProgramData"); v != "" {
			return filepath.Join(v, "kite-collector")
		}
		return `C:\ProgramData\kite-collector`
	}
	if userMode {
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			return filepath.Join(v, "kite-collector")
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".local", "share", "kite-collector")
		}
	}
	return "/var/lib/kite-collector"
}

func userFlag(userMode bool) string {
	if userMode {
		return " --user"
	}
	return ""
}

func logsHint(userMode bool) string {
	switch runtime.GOOS {
	case "linux":
		if userMode {
			return "       journalctl --user -fu kite-collector"
		}
		return "       journalctl -fu kite-collector"
	case "darwin":
		return "       log stream --predicate 'process == \"kite-collector\"'"
	case "windows":
		return "       Get-EventLog -LogName Application -Source kite-collector -Newest 50"
	default:
		return "       (consult your service manager's documentation)"
	}
}

// ---------------------------------------------------------------------------
// Binary copy helper
// ---------------------------------------------------------------------------

// installBinary copies src to dst atomically (write to dst.tmp, rename).
// No-ops when src and dst are the same path.
func installBinary(src, dst string) error {
	if src == dst {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("create binary dir: %w", err)
	}

	in, err := os.Open(src) //#nosec G304 -- src is os.Executable()
	if err != nil {
		return fmt.Errorf("open source binary: %w", err)
	}
	defer func() { _ = in.Close() }()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //#nosec G302,G304 -- binary must be executable; dst from trusted install path
	if err != nil {
		return fmt.Errorf("create temp binary: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("rename binary: %w", err)
	}
	return nil
}
