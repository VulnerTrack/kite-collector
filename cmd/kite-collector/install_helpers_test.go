package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func TestSvcOptsToInstallerOptions_MapsAllFields(t *testing.T) {
	o := svcOpts{
		executable:    "/opt/kite/kite-collector",
		certsDir:      "/etc/kite/certs",
		cfgFile:       "/etc/kite/kite.yaml",
		dbPath:        "/var/lib/kite/kite.db",
		endpoint:      "https://otel.example",
		dashboardAddr: "127.0.0.1:9191",
		userService:   true,
		verbose:       true,
	}

	got := o.toInstallerOptions()

	assert.Equal(t, installer.Options{
		UserMode:      true,
		BinaryDir:     "/opt/kite",
		CertsDir:      "/etc/kite/certs",
		CfgFile:       "/etc/kite/kite.yaml",
		DbPath:        "/var/lib/kite/kite.db",
		Endpoint:      "https://otel.example",
		DashboardAddr: "127.0.0.1:9191",
		Verbose:       true,
	}, got)
}

func TestBuildSvcConfig_FullOptions(t *testing.T) {
	cfg := buildSvcConfig(svcOpts{
		executable:  "/opt/kite/kite-collector",
		certsDir:    "/etc/kite/certs",
		cfgFile:     "/etc/kite/kite.yaml",
		endpoint:    "https://otel.example",
		userService: true,
		verbose:     true,
	})

	assert.Equal(t, "kite-collector", cfg.Name)
	assert.Equal(t, svcDisplayName, cfg.DisplayName)
	assert.Equal(t, svcDescription, cfg.Description)
	assert.Equal(t, "/opt/kite/kite-collector", cfg.Executable)
	// dbPath is derived from certsDir when omitted; dashboard-addr falls
	// back to the installer default.
	assert.Equal(t, []string{
		"service", "run",
		"--certs-dir", "/etc/kite/certs",
		"--config", "/etc/kite/kite.yaml",
		"--db", filepath.Join("/etc/kite/certs", "kite.db"),
		"--endpoint", "https://otel.example",
		"--dashboard-addr", installer.DefaultDashboardAddr,
		"--verbose",
	}, cfg.Arguments)
	assert.Equal(t, true, cfg.Option["UserService"])
	assert.Equal(t, true, cfg.Option["RunAtLoad"])
	assert.Equal(t, true, cfg.Option["KeepAlive"])
	assert.Equal(t, "always", cfg.Option["Restart"])
}

func TestBuildSvcConfig_MinimalOptionsOmitsOptionalFlags(t *testing.T) {
	cfg := buildSvcConfig(svcOpts{executable: "/usr/local/bin/kite-collector"})

	assert.Equal(t, []string{
		"service", "run",
		"--certs-dir", "",
		"--dashboard-addr", installer.DefaultDashboardAddr,
	}, cfg.Arguments)
	assert.Equal(t, false, cfg.Option["UserService"])
}

func TestNewProgramService_CopiesRuntimeFields(t *testing.T) {
	svc, prg, err := newProgramService(svcOpts{
		certsDir:      "/tmp/certs",
		cfgFile:       "/tmp/cfg.yaml",
		dbPath:        "/tmp/kite.db",
		endpoint:      "https://otel.example",
		dashboardAddr: "127.0.0.1:9292",
		verbose:       true,
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.NotNil(t, prg)
	assert.Equal(t, "/tmp/certs", prg.certsDir)
	assert.Equal(t, "/tmp/cfg.yaml", prg.cfgFile)
	assert.Equal(t, "/tmp/kite.db", prg.dbPath)
	assert.Equal(t, "https://otel.example", prg.endpoint)
	assert.Equal(t, "127.0.0.1:9292", prg.dashboardAddr)
	assert.True(t, prg.verbose)
}

func TestUserFlag(t *testing.T) {
	assert.Equal(t, " --user", userFlag(true))
	assert.Equal(t, "", userFlag(false))
}

func TestLogsHint_Linux(t *testing.T) {
	// runtime.GOOS is fixed at build time; these tests run on linux CI.
	assert.Equal(t, "       journalctl -fu kite-collector", logsHint(false))
	assert.Equal(t, "       journalctl --user -fu kite-collector", logsHint(true))
}

func TestTrimOutput(t *testing.T) {
	assert.Equal(t, "", trimOutput(nil))
	assert.Equal(t, "short output", trimOutput([]byte("short output")))

	exact := strings.Repeat("a", 200)
	assert.Equal(t, exact, trimOutput([]byte(exact)), "exactly 200 bytes must not be truncated")

	long := strings.Repeat("b", 201)
	got := trimOutput([]byte(long))
	assert.Equal(t, strings.Repeat("b", 200)+"…", got)
}

func TestEnrollmentLabel(t *testing.T) {
	assert.Equal(t, "ca.pem + agent.pem + agent-key.pem present",
		enrollmentLabel(installer.State{CertsEnrolled: true}))
	assert.Equal(t, "empty — run `install --agent-code <code>` to enroll",
		enrollmentLabel(installer.State{CertsDirExists: true}))
	assert.Equal(t, "certs dir missing", enrollmentLabel(installer.State{}))
}

func TestPlatformDefaultDelegates(t *testing.T) {
	assert.Equal(t, installer.BinaryName(), binaryName())
	assert.Equal(t, installer.DefaultBinaryDir(false), defaultBinaryDir(false))
	assert.Equal(t, installer.DefaultBinaryDir(true), defaultBinaryDir(true))
	assert.Equal(t, installer.DefaultCertsDir(false), defaultCertsDir(false))
	assert.Equal(t, installer.DefaultCertsDir(true), defaultCertsDir(true))
}

func TestEnrollmentPresent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	assert.False(t, enrollmentPresent(missing), "missing dir is not enrolled")

	partial := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(partial, "ca.pem"), []byte("x"), 0o600))
	assert.False(t, enrollmentPresent(partial), "one of three PEMs is not enrolled")

	full := t.TempDir()
	for _, name := range installer.EnrollmentFiles {
		require.NoError(t, os.WriteFile(filepath.Join(full, name), []byte("x"), 0o600))
	}
	assert.True(t, enrollmentPresent(full))
}

func TestPrintSnapPostInstall_Enrolled(t *testing.T) {
	var buf bytes.Buffer
	printSnapPostInstall(&buf, "/var/snap/kite/common/certs", true)
	out := buf.String()

	assert.Contains(t, out, "Current state:")
	assert.Contains(t, out, "  ✓  binary       /snap/bin/kite-collector")
	assert.Contains(t, out, "  ✓  certs dir    /var/snap/kite/common/certs")
	assert.Contains(t, out, "  ✓  enrollment   ca.pem + agent.pem + agent-key.pem present")
	assert.NotContains(t, out, "Enroll this collector",
		"enrolled install must not ask for enrollment")
	// Step numbering starts at 1 with the snap service step.
	assert.Contains(t, out, "  1. Enable and start the snap service:")
	assert.Contains(t, out, "  2. Verify OTLP connectivity:")
	assert.Contains(t, out, "  3. View logs:")
	assert.Contains(t, out, "  4. Open the dashboard:")
}

func TestPrintSnapPostInstall_NotEnrolledLeadsWithEnrollStep(t *testing.T) {
	var buf bytes.Buffer
	printSnapPostInstall(&buf, "/var/snap/kite/common/certs", false)
	out := buf.String()

	assert.Contains(t, out, "  ✗  enrollment   certs missing")
	assert.Contains(t, out, "  1. Enroll this collector (one-time):")
	assert.Contains(t, out, "sudo kite-collector enroll --certs-dir /var/snap/kite/common/certs")
	assert.Contains(t, out, "  2. Enable and start the snap service:")
	assert.Contains(t, out, "  5. Open the dashboard:")
}

func TestPrintPostInstall_FreshTreeReportsMissingPieces(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "kite-collector")
	certsDir := t.TempDir() // exists but empty

	var buf bytes.Buffer
	printPostInstall(&buf, binPath, certsDir, false)
	out := buf.String()

	assert.Contains(t, out, "Current state:")
	assert.Contains(t, out, "  ✗  binary       "+binPath)
	assert.Contains(t, out, "  ✓  certs dir    "+certsDir)
	assert.Contains(t, out, "  ✗  enrollment   empty — run `install --agent-code <code>` to enroll")
	assert.Contains(t, out, "  -  service      ")
	// Unenrolled → enroll is always step 1, connectivity check step 2.
	assert.Contains(t, out, "  1. Enroll this collector (one-time):")
	assert.Contains(t, out, binPath+" enroll")
	assert.Contains(t, out, "  2. Verify OTLP connectivity:")
	assert.Contains(t, out, binPath+" check --certs-dir "+certsDir)
	assert.Contains(t, out, "View logs:")
	assert.Contains(t, out, binPath+" dashboard --certs-dir "+certsDir)
	assert.NotContains(t, out, " --user", "system-mode report must not add --user")
}

func TestRunInstall_DryRunIsNonMutatingAndPrintsPlan(t *testing.T) {
	binaryDir := t.TempDir()
	certsDir := filepath.Join(t.TempDir(), "certs")
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runInstall(cmd, installArgs{
		certsDir:          certsDir,
		binaryDir:         binaryDir,
		agentCode:         "AG-42",
		token:             "pki_enroll_v1_test",
		dryRun:            true,
		noStart:           true,
		binaryDirExplicit: true,
	})
	require.NoError(t, err)

	out := buf.String()
	dst := filepath.Join(binaryDir, "kite-collector")
	assert.Contains(t, out, "-- dry-run: no files will be written --")
	assert.Contains(t, out, "→ "+dst)
	assert.Contains(t, out, "  mkdir  "+certsDir)
	assert.Contains(t, out, `register service "kite-collector" (user=false)`)
	assert.Contains(t, out, "executable: "+dst)
	assert.Contains(t, out, "enroll agent_code=AG-42 via legacy token → "+certsDir)
	assert.Contains(t, out, "enable boot persistence (linux)")
	assert.NotContains(t, out, "start service", "--no-start must suppress the start step")

	entries, err := os.ReadDir(binaryDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "dry-run must not write into --binary-dir")
	_, statErr := os.Stat(certsDir)
	assert.True(t, os.IsNotExist(statErr), "dry-run must not create the certs dir")
}

func TestRunInstall_DryRunSignInFlowAnnouncesStart(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runInstall(cmd, installArgs{
		certsDir:          filepath.Join(t.TempDir(), "certs"),
		binaryDir:         t.TempDir(),
		agentCode:         "AG-7",
		dryRun:            true,
		binaryDirExplicit: true,
	})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "via sign-in (browser + pasted code)")
	assert.Contains(t, out, `start service "kite-collector"`)
}

func TestNewInstallCmd_FlagSurface(t *testing.T) {
	cmd := newInstallCmd()
	assert.Equal(t, "install", cmd.Use)

	for _, name := range []string{
		"user", "certs-dir", "binary-dir", "config", "db", "endpoint",
		"agent-code", "token", "issuer", "client-id", "redirect-uri",
		"scope", "verbose", "dry-run", "no-start", "copy", "repair",
	} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "missing flag --%s", name)
	}
	assert.Equal(t, "openid email", cmd.Flags().Lookup("scope").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("dry-run").DefValue)
}

func TestNewUninstallCmd_Shape(t *testing.T) {
	cmd := newUninstallCmd()
	assert.Equal(t, "uninstall", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("user"))
	assert.NotNil(t, cmd.Flags().Lookup("certs-dir"))
	assert.NotNil(t, cmd.Flags().Lookup("purge"))
	assert.Equal(t, "false", cmd.Flags().Lookup("purge").DefValue)
}

func TestNewServiceCmd_RegistersControlSubcommands(t *testing.T) {
	cmd := newServiceCmd()
	assert.Equal(t, "service", cmd.Use)

	names := map[string]bool{}
	var runCmd *cobra.Command
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
		if sub.Name() == "run" {
			runCmd = sub
		}
	}
	for _, want := range []string{"start", "stop", "restart", "status", "run"} {
		assert.True(t, names[want], "missing service subcommand %q", want)
	}
	require.NotNil(t, runCmd)
	assert.True(t, runCmd.Hidden, "service run is an OS-manager entry point and must stay hidden")
	assert.Equal(t, installer.DefaultDashboardAddr,
		runCmd.Flags().Lookup("dashboard-addr").DefValue)
}

func TestControlInstalledService_UsesStatusPreflight(t *testing.T) {
	// linux build: the darwin kickstart seam is never reached, so the real
	// launchctl helper passed by controlInstalledService stays dormant.
	svc := &fakeSvc{status: service.StatusRunning}
	outcome, err := controlInstalledService(svc, "start", false)
	require.NoError(t, err)
	assert.Equal(t, outcomeAlreadyRunning, outcome)
	assert.Equal(t, 0, svc.startCalls)

	svc = &fakeSvc{statusErr: service.ErrNotInstalled}
	outcome, err = controlInstalledService(svc, "stop", false)
	require.NoError(t, err)
	assert.Equal(t, outcomeNotInstalled, outcome)

	_, err = controlInstalledService(&fakeSvc{}, "reload", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown service action "reload"`)
}

func TestRunInstall_DryRunAdoptsBrewOwnedBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("adoption classification is unix-only")
	}
	// Fake brew layout: <prefix>/Caskroom payload + <prefix>/bin symlink,
	// and pretend the install command was launched via that symlink.
	prefix := t.TempDir()
	payloadDir := filepath.Join(prefix, "Caskroom", "kite-collector", "1.0")
	require.NoError(t, os.MkdirAll(payloadDir, 0o755))
	payload := filepath.Join(payloadDir, "kite-collector")
	require.NoError(t, os.WriteFile(payload, []byte("bin"), 0o755)) //#nosec G306 -- test binary
	binDir := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	link := filepath.Join(binDir, "kite-collector")
	require.NoError(t, os.Symlink(payload, link))

	orig := installExecutablePath
	t.Cleanup(func() { installExecutablePath = orig })
	installExecutablePath = func() (string, error) { return link, nil }

	certsDir := filepath.Join(t.TempDir(), "certs")
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runInstall(cmd, installArgs{
		certsDir: certsDir,
		dryRun:   true,
		noStart:  true,
	})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "binary owned by homebrew")
	assert.Contains(t, out, "adopting "+link)
	assert.Contains(t, out, "adopt  "+link+" (managed by homebrew — no copy)")
	assert.NotContains(t, out, "copy   ", "adoption must replace the copy step")
	assert.Contains(t, out, "executable: "+link,
		"the service registration must exec brew's stable symlink")

	// --copy forces the historical behavior even for a managed binary.
	buf.Reset()
	err = runInstall(cmd, installArgs{
		certsDir:  certsDir,
		binaryDir: t.TempDir(),
		dryRun:    true,
		noStart:   true,
		forceCopy: true,
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "copy   ", "--copy must restore copy semantics")
	assert.NotContains(t, buf.String(), "adopting")
}
