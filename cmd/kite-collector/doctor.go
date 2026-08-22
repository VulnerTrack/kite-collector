package main

// `kite-collector doctor` — staged diagnostics with remediation hints.
// Answers "status looks wrong — why?" in one run:
//
//   service       → registered + running?
//   config        → parses?
//   database      → opens? migrations current?
//   certificates  → present? expiring?
//   tcp-dial / tls-handshake / otlp-ping → can we reach the collector?
//
// Read-only (it never creates the database or mutates certs) and exits
// non-zero when any check fails, so it drops straight into CI and Ansible.
// The connectivity stages are the former `check-otlp` probes, absorbed here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/installer"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

const (
	doctorPass = "pass"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// certExpiryWarnWindow is how close to NotAfter a client certificate may get
// before doctor starts warning. Enrollment certs default to 90-day validity,
// so 30 days gives operators two comfortable renewal windows.
const certExpiryWarnWindow = 30 * 24 * time.Hour

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass / warn / fail / skip
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func newDoctorCmd() *cobra.Command {
	var (
		certsDir string
		dbPath   string
		cfgFile  string
		endpoint string
		timeout  time.Duration
		offline  bool
		userMode bool
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"check"},
		Short:   "Diagnose the agent and its connection to VulnerTrack",
		Long: `Run staged diagnostics with remediation hints:

  1. service        — registered with the OS service manager and running
  2. config         — configuration file parses
  3. database       — SQLite store opens and migrations are current
  4. certificates   — enrollment PEMs present and not expiring
  5. tcp-dial       — the OTLP collector host:port is reachable
  6. tls-handshake  — mTLS handshake with the enrollment certificates
  7. otlp-ping      — a minimal log record is accepted (HTTP 2xx)

Read-only: nothing is created or modified. Exits non-zero when any check
fails, so it can gate CI and configuration-management runs. Use --offline
to skip the network stages.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			checks := runDoctorChecks(cmd.Context(), doctorOptions{
				CertsDir:    certsDir,
				DbPath:      dbPath,
				CfgFile:     cfgFile,
				Endpoint:    endpoint,
				Timeout:     timeout,
				Offline:     offline,
				UserMode:    userMode,
				UserFlagSet: cmd.Flag("user").Changed,
			})
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(checks); err != nil {
					return fmt.Errorf("encode doctor report: %w", err)
				}
			} else {
				renderDoctorChecks(cmd, checks)
			}
			if n := countDoctorFailures(checks); n > 0 {
				return fmt.Errorf("doctor: %d check(s) failed", n)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "", "certificate store path (default: OS-appropriate)")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to SQLite database (default: {certs-dir}/kite.db)")
	cmd.Flags().StringVar(&cfgFile, "config", "", "path to configuration file (optional)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "OTLP endpoint (default: config, then https://otel.vulnertrack.io)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "per-stage network timeout")
	cmd.Flags().BoolVar(&offline, "offline", false, "skip the network connectivity stages")
	cmd.Flags().BoolVar(&userMode, "user", false, "inspect the per-user install instead of auto-detecting")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit results as JSON")

	return cmd
}

type doctorOptions struct {
	CertsDir    string
	DbPath      string
	CfgFile     string
	Endpoint    string
	Timeout     time.Duration
	Offline     bool
	UserMode    bool
	UserFlagSet bool
}

func runDoctorChecks(ctx context.Context, o doctorOptions) []doctorCheck {
	opts := statusProbeOptions(o.CertsDir, o.DbPath, o.UserMode, o.UserFlagSet)
	state := installer.Probe(opts)
	checks := make([]doctorCheck, 0, 7)

	checks = append(checks, doctorServiceCheck(state))
	checks = append(checks, doctorBinaryDriftCheck(opts))
	cfg, cfgCheck := doctorConfigCheck(o.CfgFile)
	checks = append(checks, cfgCheck)
	checks = append(checks, doctorDatabaseCheck(ctx, opts.DbPath))
	checks = append(checks, doctorCertificatesCheck(opts.CertsDir, state))

	if o.Offline {
		checks = append(checks, doctorCheck{Name: "connectivity", Status: doctorSkip, Detail: "skipped (--offline)"})
		return checks
	}

	endpoint := o.Endpoint
	if endpoint == "" && cfg != nil {
		endpoint = cfg.Streaming.OTLP.Endpoint
	}
	if endpoint == "" {
		endpoint = "https://otel.vulnertrack.io"
	}
	checks = append(checks, doctorConnectivityChecks(endpoint, opts.CertsDir, o.Timeout)...)
	return checks
}

func doctorServiceCheck(state installer.State) doctorCheck {
	c := doctorCheck{Name: "service", Detail: state.ServiceState}
	switch state.ServiceState {
	case installer.ServiceRunning:
		c.Status = doctorPass
	case installer.ServiceStopped:
		c.Status = doctorWarn
		c.Hint = "run: kite-collector service start"
	case installer.ServiceNotInstalled:
		// Not a failure: containers and ad-hoc `agent` runs have no service.
		c.Status = doctorWarn
		c.Hint = "run: kite-collector install (not needed for containerized agents)"
	default:
		c.Status = doctorWarn
		c.Detail = "service manager state unknown"
	}
	return c
}

// doctorBinaryDriftCheck detects the split-owner drift signature: the
// binary the service registration executes is not the binary `kite-collector`
// resolves to on the operator's PATH. That state means a package-manager
// upgrade updated one copy while the service kept running the other — every
// debugging session starts on the wrong binary until it's repaired.
//
// The service executable comes from the install manifest when present (it
// records adoption), falling back to the conventional install path. Both
// sides are symlink-resolved before comparing so brew's prefix-bin link and
// its Caskroom payload count as the same binary.
func doctorBinaryDriftCheck(opts installer.Options) doctorCheck {
	c := doctorCheck{Name: "binary drift"}

	registered := opts.BinaryPath()
	if m, ok := installer.ReadInstallManifest(opts); ok && m.BinaryPath != "" {
		registered = m.BinaryPath
	}
	if _, err := os.Stat(registered); err != nil {
		c.Status = doctorSkip
		c.Detail = "no installed binary at " + registered
		return c
	}

	onPath, err := exec.LookPath("kite-collector")
	if err != nil {
		c.Status = doctorSkip
		c.Detail = "kite-collector not on PATH"
		return c
	}

	regResolved, rErr := filepath.EvalSymlinks(registered)
	pathResolved, pErr := filepath.EvalSymlinks(onPath)
	if rErr != nil || pErr != nil {
		c.Status = doctorSkip
		c.Detail = "could not resolve binary paths"
		return c
	}
	if regResolved == pathResolved {
		c.Status = doctorPass
		c.Detail = "CLI and service run the same binary (" + regResolved + ")"
		return c
	}

	c.Status = doctorWarn
	c.Detail = fmt.Sprintf("service runs %s but PATH resolves to %s", regResolved, pathResolved)
	if regFi, e1 := os.Stat(regResolved); e1 == nil {
		if pathFi, e2 := os.Stat(pathResolved); e2 == nil && regFi.ModTime().Before(pathFi.ModTime()) {
			c.Detail += " (service binary is older)"
		}
	}
	c.Hint = "run: kite-collector install --repair (re-registers against the managed binary and removes the orphaned copy)"
	return c
}

// doctorConfigCheck loads the config once and shares it with the
// connectivity stage so doctor and the agent resolve the same endpoint.
func doctorConfigCheck(cfgFile string) (*config.Config, doctorCheck) {
	c := doctorCheck{Name: "config"}
	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); err != nil {
			c.Status = doctorFail
			c.Detail = "config file not found: " + cfgFile
			return nil, c
		}
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		c.Status = doctorFail
		c.Detail = err.Error()
		c.Hint = "fix the YAML or remove the file to use built-in defaults"
		return nil, c
	}
	c.Status = doctorPass
	if cfgFile == "" {
		c.Detail = "built-in defaults (no --config given)"
	} else {
		c.Detail = cfgFile
	}
	return cfg, c
}

func doctorDatabaseCheck(ctx context.Context, dbPath string) doctorCheck {
	c := doctorCheck{Name: "database", Detail: dbPath}
	fi, err := os.Stat(dbPath)
	if err != nil || fi.IsDir() {
		c.Status = doctorWarn
		c.Detail = dbPath + " not created yet"
		c.Hint = "created automatically by the first scan"
		return c
	}

	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	if err != nil {
		c.Detail = "open failed: " + err.Error()
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
			// The store is intact but this invocation lacks rights — an
			// observer limitation, not an agent fault.
			c.Status = doctorWarn
			c.Hint = "a root-installed service owns its store; re-run doctor with sudo (or --user for a per-user install)"
		} else {
			c.Status = doctorFail
			c.Hint = "the store may be corrupt or locked by another writer; check file permissions and disk space"
		}
		return c
	}
	defer func() { _ = encStore.Close() }()

	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	if !ok {
		c.Status = doctorPass
		return c
	}
	infos, err := st.MigrationStatus(ctx)
	if err != nil {
		c.Status = doctorWarn
		c.Detail = "migration status unavailable: " + err.Error()
		return c
	}
	pending := 0
	for _, info := range infos {
		if !info.Applied {
			pending++
		}
	}
	if pending > 0 {
		c.Status = doctorWarn
		c.Detail = fmt.Sprintf("%s · %d migration(s) pending", fmtByteSize(fi.Size()), pending)
		c.Hint = "applied automatically on the next run; force now with: kite-collector migrate"
		return c
	}
	c.Status = doctorPass
	c.Detail = fmt.Sprintf("%s · %d migrations applied", fmtByteSize(fi.Size()), len(infos))
	return c
}

func doctorCertificatesCheck(certsDir string, state installer.State) doctorCheck {
	c := doctorCheck{Name: "certificates", Detail: certsDir}
	present := 0
	for _, name := range installer.EnrollmentFiles {
		if _, err := os.Stat(filepath.Join(certsDir, name)); err == nil {
			present++
		}
	}
	switch {
	case present == 0:
		c.Status = doctorWarn
		c.Detail = "not enrolled (no certificates in " + certsDir + ")"
		c.Hint = "run: kite-collector enroll   (or: install --agent-code <code> --token <tok>)"
		return c
	case present < len(installer.EnrollmentFiles):
		c.Status = doctorFail
		c.Detail = fmt.Sprintf("partial enrollment: %d of %d PEMs present in %s", present, len(installer.EnrollmentFiles), certsDir)
		c.Hint = "re-run: kite-collector enroll"
		return c
	}

	notAfter, err := certNotAfter(filepath.Join(certsDir, "agent.pem"))
	if err != nil {
		c.Status = doctorFail
		c.Detail = "agent.pem unreadable: " + err.Error()
		c.Hint = "re-run: kite-collector enroll"
		return c
	}
	left := time.Until(notAfter)
	switch {
	case left <= 0:
		c.Status = doctorFail
		c.Detail = "client certificate EXPIRED " + notAfter.UTC().Format("2006-01-02")
		c.Hint = "re-enroll: kite-collector enroll"
	case left < certExpiryWarnWindow:
		c.Status = doctorWarn
		c.Detail = fmt.Sprintf("client certificate expires in %dd (%s)", int(left.Hours()/24), notAfter.UTC().Format("2006-01-02"))
		c.Hint = "renewal happens on heartbeat; if it doesn't, re-enroll"
	default:
		c.Status = doctorPass
		c.Detail = fmt.Sprintf("enrolled · cert valid until %s (%dd)", notAfter.UTC().Format("2006-01-02"), int(left.Hours()/24))
	}
	_ = state
	return c
}

// doctorConnectivityChecks maps the staged OTLP probes (formerly the
// check-otlp command) onto doctor checks.
func doctorConnectivityChecks(endpoint, certsDir string, timeout time.Duration) []doctorCheck {
	stages, err := collectOTLPStages(endpoint, certsDir, timeout)
	if err != nil {
		return []doctorCheck{{
			Name: "connectivity", Status: doctorFail, Detail: err.Error(),
		}}
	}
	ran := map[string]bool{}
	out := make([]doctorCheck, 0, 3)
	for _, s := range stages {
		ran[s.Name] = true
		c := doctorCheck{Name: s.Name, Detail: fmt.Sprintf("%s · %dms", endpoint, s.DurMS)}
		switch {
		case s.OK && s.Error != "":
			c.Status = doctorSkip
			c.Detail = s.Error // e.g. "skipped (no --certs-dir provided)"
		case s.OK:
			c.Status = doctorPass
		default:
			c.Status = doctorFail
			c.Detail = s.Error
			c.Hint = "verify the endpoint, firewall egress, and enrollment certs; re-run with --endpoint to test another collector"
		}
		out = append(out, c)
	}
	// Stages abort on first failure — surface the unreached ones as skipped
	// so the report always shows all three.
	for _, name := range []string{"tcp-dial", "tls-handshake", "otlp-ping"} {
		if !ran[name] {
			out = append(out, doctorCheck{Name: name, Status: doctorSkip, Detail: "not reached (earlier stage failed)"})
		}
	}
	return out
}

func countDoctorFailures(checks []doctorCheck) int {
	n := 0
	for _, c := range checks {
		if c.Status == doctorFail {
			n++
		}
	}
	return n
}

func renderDoctorChecks(cmd *cobra.Command, checks []doctorCheck) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, c := range checks {
		mark := map[string]string{
			doctorPass: "✔", doctorWarn: "!", doctorFail: "✖", doctorSkip: "-",
		}[c.Status]
		_, _ = fmt.Fprintf(w, "  %s %s\t%s\t%s\n", mark, c.Status, c.Name, c.Detail)
		if c.Hint != "" {
			_, _ = fmt.Fprintf(w, "  \t\t↳ %s\n", c.Hint)
		}
	}
	_ = w.Flush()
	_, _ = fmt.Fprintln(out)
}
