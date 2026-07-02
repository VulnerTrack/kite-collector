package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// Service identity. The kardianos library uses this single name as the
// systemd unit name, launchd plist label, and Windows Service name. These
// values are re-exported from internal/installer so the cmd layer and the
// dashboard installer package speak the same service identity.
const (
	svcName        = installer.SvcName
	svcDisplayName = installer.SvcDisplayName
	svcDescription = installer.SvcDescription
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

// toInstallerOptions adapts the cmd-layer svcOpts to the installer package's
// Options shape. BinaryDir is derived from executable so the installer's
// BuildSvcConfig produces the same Executable string we used in v1.
func (o svcOpts) toInstallerOptions() installer.Options {
	return installer.Options{
		UserMode:  o.userService,
		BinaryDir: filepath.Dir(o.executable),
		CertsDir:  o.certsDir,
		CfgFile:   o.cfgFile,
		DbPath:    o.dbPath,
		Endpoint:  o.endpoint,
		Verbose:   o.verbose,
	}
}

func buildSvcConfig(o svcOpts) *service.Config {
	return installer.BuildSvcConfig(o.toInstallerOptions())
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
		agentCode string
		token     string
		userMode  bool
		dryRun    bool
		verbose   bool
		noStart   bool
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
  4. Configures it to run "kite-collector service run --certs-dir {certs-dir}"
  5. If --agent-code and --token are provided, enrolls the agent inline
  6. If enrollment succeeds (or certs are already present), starts the service

One-shot usage (recommended):
  kite-collector install --agent-code <code> --token <token>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certsDir == "" {
				certsDir = defaultCertsDir(userMode)
			}
			if binaryDir == "" {
				binaryDir = defaultBinaryDir(userMode)
			}
			// Enrollment requires both code AND token; passing one
			// without the other is a flag mistake, not a partial install.
			if (agentCode == "") != (token == "") {
				return fmt.Errorf("--agent-code and --token must be set together")
			}
			return runInstall(cmd, installArgs{
				certsDir:  certsDir,
				binaryDir: binaryDir,
				cfgFile:   cfgFile,
				dbPath:    dbPath,
				endpoint:  endpoint,
				agentCode: agentCode,
				token:     token,
				userMode:  userMode,
				dryRun:    dryRun,
				verbose:   verbose,
				noStart:   noStart,
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
	cmd.Flags().StringVar(&agentCode, "agent-code", "",
		"agent code from the server; passed to enrollment inline (paired with --token)")
	cmd.Flags().StringVar(&token, "token", "",
		"enrollment token; passed to enrollment inline (paired with --agent-code)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"run the service with debug logging")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"print what would be done without making any changes")
	cmd.Flags().BoolVar(&noStart, "no-start", false,
		"register the service but do not start it (useful for CI / Ansible)")

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
	agentCode string
	token     string
	userMode  bool
	dryRun    bool
	verbose   bool
	noStart   bool
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
		if a.agentCode != "" {
			_, _ = fmt.Fprintf(out, "  enroll agent_code=%s token=<redacted> → %s\n",
				a.agentCode, a.certsDir)
		}
		_, _ = fmt.Fprintf(out, "  enable boot persistence (%s)\n", runtime.GOOS)
		if !a.noStart {
			_, _ = fmt.Fprintf(out, "  start service %q\n", cfg.Name)
		}
		return nil
	}

	// Defer the post-install report so it surfaces the *current* state no
	// matter how runInstall exits: full success, mid-install failure (binary
	// copied but service registration failed, etc.), or a re-run where things
	// already exist. Captures the resolved paths so the message points at the
	// right --certs-dir, not the user's typed defaults.
	defer printPostInstall(out, dst, a.certsDir, a.userMode)

	if binErr := installer.InstallBinary(src, dst); binErr != nil {
		return fmt.Errorf("install binary: %w", binErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", dst)

	if mkErr := os.MkdirAll(a.certsDir, 0o750); mkErr != nil {
		return fmt.Errorf("create certs dir %s: %w", a.certsDir, mkErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", a.certsDir)

	if pathErr := installer.ConfigurePath(opts.toInstallerOptions()); pathErr != nil {
		return fmt.Errorf("configure PATH: %w", pathErr)
	}
	_, _ = fmt.Fprintf(out, "  ✓  PATH configured\n")

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

	// Boot persistence is implicit on launchd (Install writes the plist
	// into the system/user LaunchDaemons dir) but on systemd and Windows
	// SCM the unit/service is registered "manual" by default. Enable
	// here so a reboot brings the service back without operator action.
	if enableErr := enableBootPersistence(a.userMode); enableErr != nil {
		// Non-fatal: the service is registered and (about to be) running.
		// Persistence is a recoverable miss — the operator can run the
		// platform's enable command later.
		_, _ = fmt.Fprintf(out, "  ✗  boot persistence: %v\n", enableErr)
	} else {
		_, _ = fmt.Fprintf(out, "  ✓  boot persistence enabled\n")
	}

	// Inline enrollment so the operator does not have to chain a second
	// command. We run enroll AFTER service registration so a failure here
	// still leaves the service registered (the operator can re-run
	// `kite-collector enroll` with the same args later) — the defer'd
	// post-install report will explain the state either way.
	enrolled := false
	if a.agentCode != "" && a.token != "" {
		if err := runEnroll(a.agentCode, a.token, a.certsDir); err != nil {
			_, _ = fmt.Fprintf(out, "  ✗  enrollment failed: %v\n", err)
			// Don't propagate — service is registered; the operator can
			// retry `kite-collector enroll` without re-running install.
		} else {
			_, _ = fmt.Fprintf(out, "  ✓  enrolled agent %q\n", a.agentCode)
			enrolled = true
		}
	}

	// Auto-start when the service has something to do — i.e. enrollment
	// just succeeded OR certs were already present from a prior install.
	// Starting an unenrolled service produces nothing but auth-error logs,
	// so we skip in that case and leave the post-install report to
	// instruct the operator.
	if a.noStart {
		return nil
	}
	st := installer.Probe(installer.Options{
		UserMode:  a.userMode,
		BinaryDir: filepath.Dir(dst),
		CertsDir:  a.certsDir,
	})
	if !enrolled && !st.CertsEnrolled {
		// No certs → starting now is just noise. Stay quiet here; the
		// post-install report tells the operator what to do next.
		return nil
	}
	if err := svc.Start(); err != nil {
		_, _ = fmt.Fprintf(out, "  ✗  service start failed: %v\n", err)
		return nil
	}
	_, _ = fmt.Fprintf(out, "  ✓  service %q started\n", cfg.Name)
	return nil
}

// ---------------------------------------------------------------------------
// Post-install state report
// ---------------------------------------------------------------------------

// printPostInstall renders the current-state table and a numbered next-steps
// list tailored to that state. Every command in the list is pre-filled with
// the actual binPath and certsDir so the operator can copy-paste verbatim —
// no <placeholders> for things we already know.
func printPostInstall(out io.Writer, binPath, certsDir string, userMode bool) {
	opts := installer.Options{
		UserMode:  userMode,
		BinaryDir: filepath.Dir(binPath),
		CertsDir:  certsDir,
	}
	st := installer.Probe(opts)

	check := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Current state:")
	_, _ = fmt.Fprintf(out, "  %s  binary       %s\n", check(st.BinaryPresent), binPath)
	_, _ = fmt.Fprintf(out, "  %s  certs dir    %s\n", check(st.CertsDirExists), certsDir)
	_, _ = fmt.Fprintf(out, "  %s  enrollment   %s\n", check(st.CertsEnrolled), enrollmentLabel(st))
	_, _ = fmt.Fprintf(out, "  -  service      %s\n", st.ServiceState)

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Next steps:")
	step := 1
	if !st.CertsEnrolled {
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
	if st.ServiceState != installer.ServiceRunning {
		_, _ = fmt.Fprintf(out,
			"  %d. Start the service:\n"+
				"       %s service start%s\n\n",
			step, binPath, userFlag(userMode))
		step++
	}
	_, _ = fmt.Fprintf(out, "  %d. View logs:\n%s\n\n", step, logsHint(userMode))
	step++
	_, _ = fmt.Fprintf(out,
		"  %d. Open the dashboard (browser opens at http://127.0.0.1:9090):\n"+
			"       %s dashboard --certs-dir %s%s\n\n",
		step, binPath, certsDir, userFlag(userMode))
}

// enrollmentLabel returns a one-word state for the enrollment row: the three
// PEMs are present, the dir is empty, or the dir is missing entirely.
func enrollmentLabel(st installer.State) string {
	switch {
	case st.CertsEnrolled:
		return "ca.pem + agent.pem + agent-key.pem present"
	case st.CertsDirExists:
		return "empty — run `enroll` to populate"
	default:
		return "certs dir missing"
	}
}

// ---------------------------------------------------------------------------
// Platform defaults — thin delegates to internal/installer so cmd and
// dashboard agree on what the canonical paths are.
// ---------------------------------------------------------------------------

func binaryName() string                    { return installer.BinaryName() }
func defaultBinaryDir(userMode bool) string { return installer.DefaultBinaryDir(userMode) }
func defaultCertsDir(userMode bool) string  { return installer.DefaultCertsDir(userMode) }

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

// enableBootPersistence makes the registered service start automatically
// at boot. kardianos/service writes the unit/plist but does not pin its
// start-on-boot setting on every backend:
//
//   - launchd writes plists into /Library/LaunchDaemons (or the user's
//     LaunchAgents), which is sufficient on its own — no-op here.
//   - systemd needs an explicit `systemctl enable` to symlink the unit
//     into the appropriate .target.wants directory.
//   - Windows SCM registers services with start type Demand (manual);
//     `sc config <name> start= auto` flips it to Auto so it survives
//     reboot.
//
// Missing platform tooling (systemctl absent on a non-systemd Linux,
// sc.exe unavailable somehow) is returned as an error so the install
// flow can report it without aborting — boot persistence is a recoverable
// miss, not a corrupt install.
func enableBootPersistence(userMode bool) error {
	ctx := context.Background()
	switch runtime.GOOS {
	case "linux":
		args := []string{"enable", svcName + ".service"}
		if userMode {
			args = append([]string{"--user"}, args...)
		}
		out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %v: %w (%s)", args, err, trimOutput(out))
		}
		return nil
	case "windows":
		// `sc config <name> start= auto` — note the literal space after
		// `start=` is required by sc.exe's parser.
		out, err := exec.CommandContext(ctx, "sc", "config", svcName, "start=", "auto").CombinedOutput()
		if err != nil {
			return fmt.Errorf("sc config %s start= auto: %w (%s)", svcName, err, trimOutput(out))
		}
		return nil
	case "darwin":
		// launchd plists written by kardianos already include RunAtLoad,
		// which is the boot-persistence signal. Nothing to do.
		return nil
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}

// trimOutput condenses subprocess output for inclusion in error
// messages: strip trailing whitespace and cap at a sensible length so
// the operator's terminal stays readable.
func trimOutput(b []byte) string {
	s := string(b)
	// Collapse runs of whitespace to a single space.
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}
