// Package installer provides reusable, OS-aware install state and smart
// defaults for the kite-collector agent.
//
// It is consumed by:
//
//   - cmd/kite-collector/install.go — the CLI install subcommand
//   - internal/dashboard            — the dashboard onboarding API surface
//
// The smart-defaults flow detects the host OS, privilege level, and existing
// on-disk artifacts (binary, certs dir, enrollment PEMs) and returns a fully-
// populated Options struct so callers can present a one-click install/enroll
// experience without prompting the operator for paths they cannot know.
package installer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"
)

// EnrollmentFiles are the three PEMs that completed enrollment writes to the
// certs directory. All three present is the canonical "this agent is enrolled"
// signal — partial sets indicate a half-done flow that re-enroll should fix.
var EnrollmentFiles = []string{"ca.pem", "agent.pem", "agent-key.pem"}

// Options captures everything an install action (or a state probe) needs to
// know. Zero values are not safe — callers should derive Options from
// DetectDefaults and then override only what the operator explicitly chose.
//
// Field ordering pins strings (16B) before bools (1B) so the struct packs
// without padding — fieldalignment-clean for the linter.
type Options struct {
	BinaryDir string `json:"binary_dir"`
	CertsDir  string `json:"certs_dir"`
	CfgFile   string `json:"cfg_file,omitempty"`
	DbPath    string `json:"db_path,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserMode  bool   `json:"user_mode"`
	Verbose   bool   `json:"verbose,omitempty"`
}

// BinaryPath returns the absolute path to the installed binary given the
// configured BinaryDir. The OS-appropriate executable extension is appended.
func (o Options) BinaryPath() string {
	return filepath.Join(o.BinaryDir, BinaryName())
}

// Detected reports the runtime facts the smart-defaults logic used to derive
// suggested Options. Surfacing these lets the dashboard UI explain *why* a
// specific path or mode was suggested.
type Detected struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Hostname   string `json:"hostname,omitempty"`
	Privileged bool   `json:"privileged"`
}

// Defaults bundles the suggested Options with the Detected facts that drove
// them. Callers can render the Options as a pre-filled form and surface the
// Detected fields as the "we picked these because…" tooltip.
type Defaults struct {
	Options  Options  `json:"options"`
	Detected Detected `json:"detected"`
}

// State is the on-disk + service-manager reality at probe time. NextAction is
// the dashboard's authoritative recommendation for the next step a smooth
// onboarding flow should surface — it collapses the 4-bit state space (binary
// × certs dir × enrolled × service) into a single, UI-friendly token.
//
// Strings precede bools so the struct packs tightly.
type State struct {
	BinaryPath     string `json:"binary_path"`
	CertsDir       string `json:"certs_dir"`
	ServiceState   string `json:"service_state"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	NextAction     string `json:"next_action"`
	BinaryPresent  bool   `json:"binary_present"`
	CertsDirExists bool   `json:"certs_dir_exists"`
	CertsEnrolled  bool   `json:"certs_enrolled"`
	UserMode       bool   `json:"user_mode"`
}

// Service state literals — kept stable so dashboards and operator runbooks
// can grep on them.
const (
	ServiceRunning      = "running"
	ServiceStopped      = "stopped"
	ServiceNotInstalled = "not installed"
	ServiceUnknown      = "unknown"
)

// NextAction tokens — surfaced verbatim in the dashboard JSON contract.
const (
	ActionInstall         = "install"
	ActionEnroll          = "enroll"
	ActionRegisterService = "register_service"
	ActionStartService    = "start_service"
	ActionReady           = "ready"
)

// SvcName is the kardianos service name shared with cmd/kite-collector. It is
// declared here so the installer package can compose a service config
// without importing the cmd package (which would invert the dependency).
const (
	SvcName        = "kite-collector"
	SvcDisplayName = "Kite Collector"
	SvcDescription = "Continuous asset discovery and OTLP streaming agent"
)

// DetectDefaults returns smart, OS-aware Options + the Detected facts that
// drove them. Safe to call on any platform; never returns an error because
// "we cannot detect X" downgrades gracefully (e.g. unknown privilege → user
// mode, unknown hostname → empty string).
func DetectDefaults() Defaults {
	privileged := isPrivileged()
	userMode := !privileged
	hostname, _ := os.Hostname()
	return Defaults{
		Options: Options{
			UserMode:  userMode,
			BinaryDir: DefaultBinaryDir(userMode),
			CertsDir:  DefaultCertsDir(userMode),
		},
		Detected: Detected{
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
			Privileged: privileged,
			Hostname:   hostname,
		},
	}
}

// Probe returns the on-disk + service-manager state for the given Options.
// Errors from the service handle are mapped to ServiceUnknown rather than
// propagated — this is a status report, not a control plane.
func Probe(opts Options) State {
	st := State{
		BinaryPath: opts.BinaryPath(),
		CertsDir:   opts.CertsDir,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		UserMode:   opts.UserMode,
	}

	if _, err := os.Stat(st.BinaryPath); err == nil {
		st.BinaryPresent = true
	}
	if fi, err := os.Stat(opts.CertsDir); err == nil && fi.IsDir() {
		st.CertsDirExists = true
		present := 0
		for _, name := range EnrollmentFiles {
			if _, err := os.Stat(filepath.Join(opts.CertsDir, name)); err == nil {
				present++
			}
		}
		st.CertsEnrolled = present == len(EnrollmentFiles)
	}

	st.ServiceState = probeServiceState(opts)
	st.NextAction = NextAction(st)
	return st
}

// NextAction returns the canonical recommendation token for a given probed
// State. The order of checks matches the natural onboarding flow: install →
// register service → enroll → start service → ready. Surfacing this from a
// single helper keeps UI and JSON consumers in sync.
func NextAction(s State) string {
	if !s.BinaryPresent {
		return ActionInstall
	}
	if s.ServiceState == ServiceNotInstalled {
		return ActionRegisterService
	}
	if !s.CertsEnrolled {
		return ActionEnroll
	}
	if s.ServiceState == ServiceStopped {
		return ActionStartService
	}
	return ActionReady
}

// probeServiceState queries the OS service manager for the kite-collector
// service status. Returns one of the Service* constants.
func probeServiceState(opts Options) string {
	cfg := buildSvcConfig(opts)
	svc, err := service.New(&noopProgram{}, cfg)
	if err != nil {
		return ServiceUnknown
	}
	st, statusErr := svc.Status()
	switch {
	case errors.Is(statusErr, service.ErrNotInstalled):
		return ServiceNotInstalled
	case statusErr != nil:
		return ServiceUnknown
	case st == service.StatusRunning:
		return ServiceRunning
	case st == service.StatusStopped:
		return ServiceStopped
	default:
		return ServiceUnknown
	}
}

// noopProgram is the minimal service.Interface needed to call service.New for
// a status query. Start and Stop are never invoked in this code path.
type noopProgram struct{}

func (noopProgram) Start(service.Service) error { return nil }
func (noopProgram) Stop(service.Service) error  { return nil }

// buildSvcConfig assembles the kardianos service.Config used both by status
// queries and (in cmd/kite-collector) by the actual install. The arguments
// mirror what cmd/kite-collector/install.go wires up so service.Status finds
// the same registration the CLI install creates.
func buildSvcConfig(opts Options) *service.Config {
	args := []string{"service", "run", "--certs-dir", opts.CertsDir}
	if opts.CfgFile != "" {
		args = append(args, "--config", opts.CfgFile)
	}
	if opts.DbPath != "" {
		args = append(args, "--db", opts.DbPath)
	}
	if opts.Endpoint != "" {
		args = append(args, "--endpoint", opts.Endpoint)
	}
	if opts.Verbose {
		args = append(args, "--verbose")
	}
	return &service.Config{
		Name:        SvcName,
		DisplayName: SvcDisplayName,
		Description: SvcDescription,
		Executable:  opts.BinaryPath(),
		Arguments:   args,
		Option: service.KeyValue{
			"UserService": opts.UserMode,
			"RunAtLoad":   true,
			"KeepAlive":   true,
			"Restart":     "always",
		},
	}
}

// BuildSvcConfig is the exported wrapper around buildSvcConfig for callers
// that need the full kardianos service.Config (e.g. cmd/kite-collector when
// performing the real install). Kept exported so the cmd layer can delegate
// configuration construction to this package and avoid drift between the
// dashboard's "status probe" config and the CLI's "install" config.
func BuildSvcConfig(opts Options) *service.Config { return buildSvcConfig(opts) }

// BinaryName returns the OS-appropriate executable filename.
func BinaryName() string {
	if runtime.GOOS == "windows" {
		return "kite-collector.exe"
	}
	return "kite-collector"
}

// DefaultBinaryDir returns the conventional binary install directory.
//
//   - Windows system: %ProgramFiles%\kite-collector
//   - Windows user:   %LOCALAPPDATA%\kite-collector
//   - Unix system:    /usr/local/bin
//   - Unix user:      ~/.local/bin
func DefaultBinaryDir(userMode bool) string {
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

// DefaultCertsDir returns the conventional certificate store directory.
//
//   - Windows system: %ProgramData%\kite-collector
//   - Windows user:   %LOCALAPPDATA%\kite-collector\data
//   - Unix system:    /var/lib/kite-collector
//   - Unix user:      $XDG_DATA_HOME/kite-collector  (or ~/.local/share/kite-collector)
func DefaultCertsDir(userMode bool) string {
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

// InstallBinary copies src to dst atomically (write to dst.tmp, rename).
// No-op when src and dst are the same path.
func InstallBinary(src, dst string) error {
	if src == dst {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("create binary dir: %w", err)
	}
	in, err := os.Open(src) //#nosec G304 -- src comes from os.Executable() in cmd layer
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
