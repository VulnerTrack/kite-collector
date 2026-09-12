package main

// `kite-collector status` — the front door for "how is this agent doing?".
// It includes the same registration, software, identifiers, and health facts
// exposed by the dashboard's Agent profile. Read-only: it never creates the
// database, never mutates certs, never touches the network.
//
// Everything shown is derived from disk + the OS service manager, so it works
// whether or not the agent process is running.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/identity"
	"github.com/vulnertrack/kite-collector/internal/installer"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
	telresource "github.com/vulnertrack/kite-collector/internal/telemetry/resource"
)

type statusService struct {
	State      string `json:"state"` // running / stopped / not installed / unknown
	BinaryPath string `json:"binary_path,omitempty"`
	Present    bool   `json:"binary_present"`
	UserMode   bool   `json:"user_mode"`
}

type statusEnrollment struct {
	// State is "enrolled", "not enrolled", or "unknown" (the store that
	// records sign-in enrollment could not be read — typically a non-root
	// status run against a root-owned install).
	State           string `json:"state"`
	Enrolled        bool   `json:"enrolled"`
	CertsDir        string `json:"certs_dir"`
	CertNotAfter    string `json:"cert_not_after,omitempty"`
	CertDaysLeft    int    `json:"cert_days_left,omitempty"`
	FirstEnrolled   string `json:"first_enrolled_at,omitempty"`
	KeyFingerprint  string `json:"api_key_fingerprint,omitempty"`
	Warning         string `json:"warning,omitempty"`
	LastCheckPassed string `json:"last_check_passed_at,omitempty"`
	LastCheckFailed string `json:"last_check_failed_at,omitempty"`
}

type statusRegistration struct {
	EnrolledByEmail string `json:"enrolled_by_email,omitempty"`
	EnrolledByID    string `json:"enrolled_by_id,omitempty"`
	Organization    string `json:"organization,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	ClientName      string `json:"client_name,omitempty"`
	IssuedAt        string `json:"issued_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	MutualTLS       bool   `json:"mutual_tls"`
}

type statusSoftware struct {
	Name              string `json:"name"`
	DisplayVersion    string `json:"display_version"`
	Version           string `json:"version"`
	Vendor            string `json:"vendor"`
	AgentType         string `json:"agent_type"`
	BuildID           string `json:"build_id,omitempty"`
	BuiltAt           string `json:"built_at,omitempty"`
	BinaryPath        string `json:"binary_path,omitempty"`
	BinaryHash        string `json:"binary_hash,omitempty"`
	Platform          string `json:"platform"`
	Architecture      string `json:"architecture"`
	Distribution      string `json:"distribution,omitempty"`
	TelemetryContract string `json:"telemetry_contract"`
}

type statusIdentifiers struct {
	AgentID  string `json:"agent_id,omitempty"`
	HostID   string `json:"host_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
}

type statusHealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type statusScan struct {
	StartedAt     string `json:"started_at"`
	Ago           string `json:"ago"`
	Status        string `json:"status"`
	TotalMachines int    `json:"total_machines"`
	NewMachines   int    `json:"new_machines"`
}

type statusDatabase struct {
	Path    string `json:"path"`
	Size    string `json:"size,omitempty"`
	Exists  bool   `json:"exists"`
	Warning string `json:"warning,omitempty"`
}

type statusReport struct {
	Version      string              `json:"version"`
	Commit       string              `json:"commit,omitempty"`
	Service      statusService       `json:"service"`
	Enrollment   statusEnrollment    `json:"enrollment"`
	Endpoint     string              `json:"endpoint,omitempty"`
	LastScan     *statusScan         `json:"last_scan,omitempty"`
	Database     statusDatabase      `json:"database"`
	Registration statusRegistration  `json:"registration"`
	Software     statusSoftware      `json:"software"`
	Identifiers  statusIdentifiers   `json:"identifiers"`
	HealthStatus string              `json:"health_status"`
	Health       []statusHealthCheck `json:"health"`
	NextAction   string              `json:"next_action"`
}

func newStatusCmd() *cobra.Command {
	var (
		certsDir string
		dbPath   string
		cfgFile  string
		userMode bool
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show agent state at a glance",
		Long: `Show the full local agent profile: service, registration, certificate,
software and build, platform, identifiers, health, last scan, and database.

Read-only. All information comes from local disk and the OS service manager.
Use 'kite-collector doctor' when something here looks wrong.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := buildStatusReport(cmd.Context(), certsDir, dbPath, cfgFile, userMode, cmd.Flag("user").Changed)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode status report: %w", err)
				}
				return nil
			}
			renderStatusReport(cmd, report)
			return nil
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "", "certificate store path (default: OS-appropriate)")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to SQLite database (default: {certs-dir}/kite.db)")
	cmd.Flags().StringVar(&cfgFile, "config", "", "path to configuration file (optional)")
	cmd.Flags().BoolVar(&userMode, "user", false, "inspect the per-user install instead of auto-detecting")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as JSON")

	return cmd
}

// statusProbeOptions picks which install to report on. An explicit --user
// pins the mode; otherwise both modes are probed and the one with more
// evidence of a real install wins (a running service dominates; an empty
// certs directory counts for nothing). This makes "status run as a regular
// user on a host with a system-packaged service" report the system install
// instead of an empty per-user tree. Ties go to the privilege-detected
// default, matching install/enroll behavior.
func statusProbeOptions(certsDir, dbPath string, userMode, userFlagSet bool) installer.Options {
	var opts installer.Options
	switch {
	case userFlagSet:
		opts = installModeOptions(userMode)
	default:
		detected := installer.DetectDefaults().Options
		system := installModeOptions(false)
		user := installModeOptions(true)
		sysScore := installEvidenceScore(installer.Probe(system))
		usrScore := installEvidenceScore(installer.Probe(user))
		switch {
		case sysScore > usrScore:
			opts = system
		case usrScore > sysScore:
			opts = user
		default:
			opts = detected
		}
	}
	if certsDir != "" {
		opts.CertsDir = certsDir
		opts.DbPath = filepath.Join(certsDir, "kite.db")
	}
	if dbPath != "" {
		opts.DbPath = dbPath
	}
	return opts
}

func installModeOptions(userMode bool) installer.Options {
	opts := installer.DetectDefaults().Options
	opts.UserMode = userMode
	opts.CertsDir = installer.DefaultCertsDir(userMode)
	opts.BinaryDir = installer.DefaultBinaryDir(userMode)
	opts.DbPath = filepath.Join(opts.CertsDir, "kite.db")
	return opts
}

// installEvidenceScore weighs how strongly a probed state indicates a real
// install: a running service is near-conclusive, a registered-but-stopped
// service and completed enrollment are strong, a binary is weak, and a
// merely-existing directory is no evidence at all.
func installEvidenceScore(s installer.State) int {
	score := 0
	if s.BinaryPresent {
		score++
	}
	if s.CertsEnrolled {
		score += 2
	}
	switch s.ServiceState {
	case installer.ServiceRunning:
		score += 4
	case installer.ServiceStopped:
		score += 2
	}
	return score
}

func buildStatusReport(ctx context.Context, certsDir, dbPath, cfgFile string, userMode, userFlagSet bool) statusReport {
	opts := statusProbeOptions(certsDir, dbPath, userMode, userFlagSet)
	state := installer.Probe(opts)

	report := statusReport{
		Version: version,
		Commit:  commit,
		Service: statusService{
			State:      state.ServiceState,
			BinaryPath: state.BinaryPath,
			Present:    state.BinaryPresent,
			UserMode:   opts.UserMode,
		},
		Enrollment: statusEnrollment{
			Enrolled: state.CertsEnrolled,
			CertsDir: opts.CertsDir,
		},
		Database:   statusDatabase{Path: opts.DbPath},
		NextAction: state.NextAction,
	}

	// Endpoint and identity paths from config (tolerant: missing file → built-in defaults).
	var loadedCfg *config.Config
	if cfg, err := config.Load(cfgFile); err == nil && cfg != nil {
		loadedCfg = cfg
		report.Endpoint = cfg.Streaming.OTLP.Endpoint
	}

	// Registration, software, and identifier facts use the same local
	// sources as the dashboard's Agent profile page.
	certPath := filepath.Join(opts.CertsDir, "agent.pem")
	if cert, err := readStatusCertificate(certPath); err == nil {
		report.Enrollment.CertNotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		report.Enrollment.CertDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
		report.Registration.ClientName = cert.Subject.CommonName
		report.Registration.IssuedAt = cert.NotBefore.UTC().Format(time.RFC3339)
		report.Registration.ExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)
	} else if state.CertsEnrolled {
		report.Enrollment.Warning = "agent.pem unreadable: " + err.Error()
	}
	report.Registration.EnrolledByID, report.Registration.EnrolledByEmail = telresource.UserFromCertFile(certPath)
	report.Registration.OrganizationID, report.Registration.Organization = telresource.TenantOrgFromCertFile(certPath)
	report.Registration.MutualTLS = state.CertsEnrolled
	fillStatusRuntimeDetails(opts, loadedCfg, &report)

	// Database-backed facts (identity timestamps, last scan). Read-only:
	// only opened when the file already exists, and every failure degrades
	// to a warning — a root-owned store must not break `status` for a
	// regular user.
	if fi, err := os.Stat(opts.DbPath); err == nil && !fi.IsDir() {
		report.Database.Exists = true
		report.Database.Size = fmtByteSize(fi.Size())
		fillStatusFromStore(ctx, opts.DbPath, &report)
	}

	// Enrollment verdict, in evidence order: PEM certificates or a recorded
	// sign-in prove enrollment; an unreadable store means we cannot know;
	// only a readable store with no identity means "not enrolled".
	switch {
	case state.CertsEnrolled || report.Enrollment.FirstEnrolled != "":
		report.Enrollment.State = "enrolled"
		report.Enrollment.Enrolled = true
	case report.Database.Warning != "":
		report.Enrollment.State = "unknown"
	default:
		report.Enrollment.State = "not enrolled"
	}

	// A running service contradicts "next: install" — that combination just
	// means the binary is not at the kardianos default path (packaged
	// installs). Route to doctor instead of suggesting a reinstall.
	if state.ServiceState == installer.ServiceRunning &&
		(report.NextAction == installer.ActionInstall || report.Enrollment.State == "unknown") {
		report.NextAction = installer.ActionReady
	}
	report.Health = buildStatusHealth(report)
	report.HealthStatus = overallStatusHealth(report.Health)

	return report
}

// fillStatusFromStore reads identity + latest scan from the SQLite store.
// Split out so a store that cannot be opened (locked, permission-denied,
// foreign encryption key) degrades to warnings instead of failing status.
func fillStatusFromStore(ctx context.Context, dbPath string, report *statusReport) {
	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	if err != nil {
		report.Database.Warning = "could not open: " + err.Error()
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
			report.Database.Warning += " — re-run with sudo for enrollment and scan details"
		}
		return
	}
	defer func() { _ = encStore.Close() }()
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	if !ok {
		return
	}

	if identity, err := st.GetEnrolledIdentity(ctx); err == nil {
		report.Enrollment.FirstEnrolled = identity.FirstEnrolledAt.UTC().Format(time.RFC3339)
		report.Enrollment.KeyFingerprint = identity.ApiKeyFingerprint
		if identity.LastCheckPassedAt != nil {
			report.Enrollment.LastCheckPassed = identity.LastCheckPassedAt.UTC().Format(time.RFC3339)
		}
		if identity.LastCheckFailedAt != nil {
			report.Enrollment.LastCheckFailed = identity.LastCheckFailedAt.UTC().Format(time.RFC3339)
		}
	} else if !errors.Is(err, sqlite.ErrNoIdentity) && report.Enrollment.Warning == "" {
		report.Enrollment.Warning = "identity unreadable: " + err.Error()
	}

	if run, err := st.GetLatestScanRun(ctx); err == nil && run != nil {
		report.LastScan = &statusScan{
			StartedAt:     run.StartedAt.UTC().Format(time.RFC3339),
			Ago:           relativeAge(run.StartedAt),
			Status:        string(run.Status),
			TotalMachines: run.TotalMachines,
			NewMachines:   run.NewMachines,
		}
	}
}

// certNotAfter parses the first certificate in a PEM file and returns its
// NotAfter timestamp.
func certNotAfter(path string) (time.Time, error) {
	cert, err := readStatusCertificate(path)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func readStatusCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- path derived from the trusted certs-dir option
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", filepath.Base(path))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func fillStatusRuntimeDetails(opts installer.Options, cfg *config.Config, report *statusReport) {
	attrs := telresource.Build(telresource.Config{ServiceVersion: version})
	distribution := strings.TrimSpace(attrs["os.name"] + " " + attrs["os.version"])
	binaryPath, _ := os.Executable()
	binaryHash, _ := identity.ComputeBinaryHash()
	report.Software = statusSoftware{
		Name:              contract.ServiceName,
		DisplayVersion:    statusDisplayVersion(version),
		Version:           version,
		Vendor:            "VulnerTrack",
		AgentType:         contract.AgentType,
		BuildID:           commit,
		BuiltAt:           date,
		BinaryPath:        binaryPath,
		BinaryHash:        binaryHash,
		Platform:          runtime.GOOS,
		Architecture:      runtime.GOARCH,
		Distribution:      distribution,
		TelemetryContract: contract.Version,
	}

	identityDir := filepath.Dir(opts.DbPath)
	if cfg != nil && strings.TrimSpace(cfg.Identity.DataDir) != "" {
		identityDir = cfg.Identity.DataDir
	}
	report.Identifiers = statusIdentifiers{
		AgentID:  readStatusAgentID(identityDir),
		HostID:   attrs["host.id"],
		Hostname: attrs["host.name"],
		ClientID: report.Registration.ClientName,
		TenantID: report.Registration.OrganizationID,
		UserID:   report.Registration.EnrolledByID,
	}
}

func readStatusAgentID(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "identity.json")) //#nosec G304 -- path comes from the local install configuration.
	if err != nil {
		return ""
	}
	var doc struct {
		AgentID string `json:"agent_id"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return ""
	}
	return doc.AgentID
}

func statusDisplayVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

func buildStatusHealth(report statusReport) []statusHealthCheck {
	checks := make([]statusHealthCheck, 0, 6)
	serviceStatus := "warn"
	serviceDetail := report.Service.State
	if report.Service.State == installer.ServiceRunning {
		serviceStatus = "pass"
		serviceDetail = "collector service is running"
	} else if report.Service.State == installer.ServiceNotInstalled {
		serviceStatus = "fail"
	}
	checks = append(checks, statusHealthCheck{Name: "Service", Status: serviceStatus, Detail: serviceDetail})

	storeStatus, storeDetail := "warn", "database has not been created"
	if report.Database.Exists && report.Database.Warning == "" {
		storeStatus, storeDetail = "pass", "SQLite responding to queries"
	} else if report.Database.Warning != "" {
		storeStatus, storeDetail = "fail", report.Database.Warning
	}
	checks = append(checks, statusHealthCheck{Name: "Store", Status: storeStatus, Detail: storeDetail})

	identityStatus, identityDetail := "fail", report.Enrollment.State
	if report.Enrollment.Enrolled {
		identityStatus = "pass"
		identityDetail = "collector identity is enrolled"
	} else if report.Enrollment.State == "unknown" {
		identityStatus = "warn"
	}
	checks = append(checks, statusHealthCheck{Name: "Identity", Status: identityStatus, Detail: identityDetail})

	checkStatus, checkDetail := "warn", "no connection check has run yet"
	passed, passedOK := parseStatusTime(report.Enrollment.LastCheckPassed)
	failed, failedOK := parseStatusTime(report.Enrollment.LastCheckFailed)
	switch {
	case failedOK && (!passedOK || failed.After(passed)):
		checkStatus, checkDetail = "fail", "last check failed "+relativeAge(failed)
	case passedOK && time.Since(passed) <= 24*time.Hour:
		checkStatus, checkDetail = "pass", "passed "+relativeAge(passed)
	case passedOK:
		checkDetail = "last passed " + relativeAge(passed)
	}
	checks = append(checks, statusHealthCheck{Name: "Last check", Status: checkStatus, Detail: checkDetail})

	scanStatus, scanDetail := "warn", "no scan has run yet"
	if report.LastScan != nil {
		scanStatus = "pass"
		if report.LastScan.Status != "completed" {
			scanStatus = "warn"
		}
		scanDetail = report.LastScan.Status + " " + report.LastScan.Ago
	}
	checks = append(checks, statusHealthCheck{Name: "Last scan", Status: scanStatus, Detail: scanDetail})

	endpointStatus, endpointDetail := "warn", "endpoint is not configured"
	if report.Endpoint != "" {
		endpointStatus, endpointDetail = "pass", report.Endpoint
	}
	checks = append(checks, statusHealthCheck{Name: "OTLP endpoint", Status: endpointStatus, Detail: endpointDetail})
	return checks
}

func parseStatusTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func overallStatusHealth(checks []statusHealthCheck) string {
	overall := "healthy"
	for _, check := range checks {
		switch check.Status {
		case "fail":
			return "unhealthy"
		case "warn":
			overall = "degraded"
		}
	}
	return overall
}

func renderStatusReport(cmd *cobra.Command, r statusReport) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)

	versionLine := r.Version
	if r.Commit != "" {
		versionLine += " (" + shortCommit(r.Commit) + ")"
	}
	_, _ = fmt.Fprintf(w, "  Version\t%s\n", versionLine)

	mode := "system"
	if r.Service.UserMode {
		mode = "user"
	}
	svc := r.Service.State
	if !r.Service.Present && r.Service.State == installer.ServiceNotInstalled {
		svc = "not installed"
	}
	_, _ = fmt.Fprintf(w, "  Service\t%s (%s)\n", svc, mode)

	switch {
	case r.Enrollment.Enrolled && r.Enrollment.CertNotAfter != "":
		expiry := fmt.Sprintf("cert expires %s (%dd)", r.Enrollment.CertNotAfter[:10], r.Enrollment.CertDaysLeft)
		if r.Enrollment.CertDaysLeft < 0 {
			expiry = "cert EXPIRED " + r.Enrollment.CertNotAfter[:10]
		}
		_, _ = fmt.Fprintf(w, "  Enrollment\tenrolled · %s\n", expiry)
	default:
		_, _ = fmt.Fprintf(w, "  Enrollment\t%s\n", r.Enrollment.State)
	}
	if r.Enrollment.FirstEnrolled != "" {
		_, _ = fmt.Fprintf(w, "  \tfirst enrolled %s · key %s\n", r.Enrollment.FirstEnrolled[:10], r.Enrollment.KeyFingerprint)
	}
	if r.Enrollment.Warning != "" {
		_, _ = fmt.Fprintf(w, "  \t⚠ %s\n", r.Enrollment.Warning)
	}

	if r.Endpoint != "" {
		_, _ = fmt.Fprintf(w, "  Endpoint\t%s\n", r.Endpoint)
	}

	if r.LastScan != nil {
		_, _ = fmt.Fprintf(w, "  Last scan\t%s (%s) · %s · %d machines, %d new\n",
			r.LastScan.StartedAt, r.LastScan.Ago, r.LastScan.Status,
			r.LastScan.TotalMachines, r.LastScan.NewMachines)
	} else {
		_, _ = fmt.Fprintf(w, "  Last scan\tnone yet\n")
	}

	dbLine := r.Database.Path
	if r.Database.Exists {
		dbLine += " (" + r.Database.Size + ")"
	} else {
		dbLine += " (not created yet)"
	}
	_, _ = fmt.Fprintf(w, "  Database\t%s\n", dbLine)
	if r.Database.Warning != "" {
		_, _ = fmt.Fprintf(w, "  \t⚠ %s\n", r.Database.Warning)
	}

	_, _ = fmt.Fprintf(w, "  Next\t%s\n", nextActionHint(r.NextAction))

	_, _ = fmt.Fprintln(w, "\n  Registration")
	_, _ = fmt.Fprintf(w, "    State\t%s\n", r.Enrollment.State)
	_, _ = fmt.Fprintf(w, "    Enrolled by\t%s\n", statusJoinedValue(r.Registration.EnrolledByEmail, r.Registration.EnrolledByID))
	_, _ = fmt.Fprintf(w, "    Organization\t%s\n", statusJoinedValue(r.Registration.Organization, r.Registration.OrganizationID))
	_, _ = fmt.Fprintf(w, "    Client\t%s\n", statusValue(r.Registration.ClientName, "not available"))
	certificate := "not available"
	if r.Registration.ExpiresAt != "" {
		certificate = fmt.Sprintf("valid until %s (%dd left)", r.Registration.ExpiresAt[:10], r.Enrollment.CertDaysLeft)
		if r.Registration.IssuedAt != "" {
			certificate += " · issued " + r.Registration.IssuedAt[:10]
		}
	}
	_, _ = fmt.Fprintf(w, "    Certificate\t%s\n", certificate)
	reportsTo := statusValue(r.Endpoint, "not configured")
	if r.Registration.MutualTLS {
		reportsTo += " · mutual TLS"
	}
	_, _ = fmt.Fprintf(w, "    Reports to\t%s\n", reportsTo)

	_, _ = fmt.Fprintln(w, "\n  Software")
	_, _ = fmt.Fprintf(w, "    Name\t%s\n", r.Software.Name)
	_, _ = fmt.Fprintf(w, "    Version\t%s\n", r.Software.Version)
	_, _ = fmt.Fprintf(w, "    Display version\t%s\n", r.Software.DisplayVersion)
	_, _ = fmt.Fprintf(w, "    Vendor\t%s\n", r.Software.Vendor)
	_, _ = fmt.Fprintf(w, "    Agent type\t%s\n", r.Software.AgentType)
	_, _ = fmt.Fprintf(w, "    Build ID\t%s\n", statusValue(r.Software.BuildID, "not available"))
	_, _ = fmt.Fprintf(w, "    Built\t%s\n", statusValue(r.Software.BuiltAt, "not available"))
	_, _ = fmt.Fprintf(w, "    Binary\t%s\n", statusValue(r.Software.BinaryPath, "not available"))
	_, _ = fmt.Fprintf(w, "    Binary hash\t%s\n", statusValue(r.Software.BinaryHash, "not available"))
	_, _ = fmt.Fprintf(w, "    Platform\t%s/%s\n", r.Software.Platform, r.Software.Architecture)
	_, _ = fmt.Fprintf(w, "    Distribution\t%s\n", statusValue(r.Software.Distribution, "not available"))
	_, _ = fmt.Fprintf(w, "    Telemetry contract\t%s\n", r.Software.TelemetryContract)

	_, _ = fmt.Fprintln(w, "\n  Identifiers")
	_, _ = fmt.Fprintf(w, "    Agent\t%s\tagent.id, service.instance.id\n", statusValue(r.Identifiers.AgentID, "not available"))
	_, _ = fmt.Fprintf(w, "    Host\t%s\thost.id\n", statusValue(r.Identifiers.HostID, "not available"))
	_, _ = fmt.Fprintf(w, "    Hostname\t%s\thost.name\n", statusValue(r.Identifiers.Hostname, "not available"))
	_, _ = fmt.Fprintf(w, "    Client\t%s\tcertificate CN\n", statusValue(r.Identifiers.ClientID, "not available"))
	_, _ = fmt.Fprintf(w, "    Tenant\t%s\tcertificate O\n", statusValue(r.Identifiers.TenantID, "not available"))
	_, _ = fmt.Fprintf(w, "    User\t%s\tcertificate OU\n", statusValue(r.Identifiers.UserID, "not available"))

	_, _ = fmt.Fprintf(w, "\n  Health\t%s\n", strings.ToUpper(r.HealthStatus))
	for _, check := range r.Health {
		_, _ = fmt.Fprintf(w, "    [%s]\t%s\t%s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintln(out)
}

func statusValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" || value == "unknown" {
		return fallback
	}
	return value
}

func statusJoinedValue(primary, identifier string) string {
	primary = strings.TrimSpace(primary)
	identifier = strings.TrimSpace(identifier)
	switch {
	case primary != "" && identifier != "":
		return primary + " · " + identifier
	case primary != "":
		return primary
	case identifier != "":
		return identifier
	default:
		return "not available"
	}
}

// nextActionHint turns the installer's NextAction token into a copy-paste
// command, so `status` always ends with what to do next.
func nextActionHint(action string) string {
	switch action {
	case installer.ActionInstall:
		return "run: kite-collector install"
	case installer.ActionEnroll:
		return "run: kite-collector enroll"
	case installer.ActionRegisterService:
		return "run: kite-collector install (service not registered)"
	case installer.ActionStartService:
		return "run: kite-collector service start"
	case installer.ActionReady:
		return "ready"
	}
	return action
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

func fmtByteSize(n int64) string {
	const k = int64(1024)
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(k*k*k))
	}
}

func relativeAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
