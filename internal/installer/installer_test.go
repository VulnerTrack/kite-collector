package installer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectDefaults_PopulatesSmartFields asserts that DetectDefaults always
// returns a non-empty BinaryDir + CertsDir for the current GOOS and that the
// Detected facts reflect the running process. The exact paths are platform-
// dependent; the contract is "non-empty + matches the runtime constants".
func TestDetectDefaults_PopulatesSmartFields(t *testing.T) {
	d := DetectDefaults()
	assert.Equal(t, runtime.GOOS, d.Detected.OS, "Detected.OS must match runtime.GOOS")
	assert.Equal(t, runtime.GOARCH, d.Detected.Arch, "Detected.Arch must match runtime.GOARCH")
	assert.NotEmpty(t, d.Options.BinaryDir, "BinaryDir must always be populated")
	assert.NotEmpty(t, d.Options.CertsDir, "CertsDir must always be populated")
}

// TestProbe_EmptyTempDir asserts that a clean temp directory reports the
// "nothing installed" baseline that the dashboard renders as
// NextAction=install.
func TestProbe_EmptyTempDir(t *testing.T) {
	tmp := t.TempDir()
	opts := Options{
		UserMode:  true,
		BinaryDir: filepath.Join(tmp, "bin"),
		CertsDir:  filepath.Join(tmp, "certs"),
	}
	state := Probe(opts)
	assert.False(t, state.BinaryPresent, "fresh tmpdir has no binary")
	assert.False(t, state.CertsDirExists, "fresh tmpdir has no certs dir")
	assert.False(t, state.CertsEnrolled)
	assert.Equal(t, ActionInstall, state.NextAction,
		"NextAction must be install when binary is missing")
	assert.Equal(t, opts.BinaryPath(), state.BinaryPath)
}

// TestProbe_CertsEnrolled asserts that after writing the three enrollment
// PEMs the probe flips CertsEnrolled=true. Together with a present binary
// this transitions NextAction toward register_service or ready depending on
// the host's service registration.
func TestProbe_CertsEnrolled(t *testing.T) {
	tmp := t.TempDir()
	certsDir := filepath.Join(tmp, "certs")
	require.NoError(t, os.MkdirAll(certsDir, 0o700))
	for _, name := range EnrollmentFiles {
		require.NoError(t, os.WriteFile(filepath.Join(certsDir, name), []byte("test"), 0o600))
	}
	// Write a fake binary so BinaryPresent=true and NextAction skips install.
	binDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o700))
	binPath := filepath.Join(binDir, BinaryName())
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755))

	state := Probe(Options{UserMode: true, BinaryDir: binDir, CertsDir: certsDir})
	assert.True(t, state.BinaryPresent)
	assert.True(t, state.CertsDirExists)
	assert.True(t, state.CertsEnrolled, "three PEMs present → enrolled")
	// Service state depends on host installation. We don't assert a specific
	// value (CI agents have no kite-collector service registered) — only
	// that NextAction is one of the post-install states.
	assert.NotEqual(t, ActionInstall, state.NextAction)
}

// TestNextAction_StateMachine pins the priority order of NextAction so a
// future refactor can't silently change the recommended flow.
func TestNextAction_StateMachine(t *testing.T) {
	cases := []struct {
		name  string
		want  string
		state State
	}{
		{
			name:  "nothing-installed",
			state: State{},
			want:  ActionInstall,
		},
		{
			name:  "binary-only-no-service",
			state: State{BinaryPresent: true, ServiceState: ServiceNotInstalled},
			want:  ActionRegisterService,
		},
		{
			name:  "binary-and-service-no-certs",
			state: State{BinaryPresent: true, ServiceState: ServiceStopped, CertsEnrolled: false},
			want:  ActionEnroll,
		},
		{
			name:  "enrolled-but-stopped",
			state: State{BinaryPresent: true, ServiceState: ServiceStopped, CertsEnrolled: true},
			want:  ActionStartService,
		},
		{
			name:  "running-and-enrolled",
			state: State{BinaryPresent: true, ServiceState: ServiceRunning, CertsEnrolled: true},
			want:  ActionReady,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NextAction(tc.state))
		})
	}
}

// TestInstallBinary_AtomicCopy asserts that InstallBinary writes the dst
// atomically (no leftover .tmp file) and that the resulting file is
// executable on unix.
func TestInstallBinary_AtomicCopy(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))
	dst := filepath.Join(tmp, "subdir", "dst")

	require.NoError(t, InstallBinary(src, dst))

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))

	if runtime.GOOS != "windows" {
		fi, statErr := os.Stat(dst)
		require.NoError(t, statErr)
		assert.NotZero(t, fi.Mode()&0o111, "dst must be executable on unix")
	}

	_, err = os.Stat(dst + ".tmp")
	assert.True(t, os.IsNotExist(err), "no leftover .tmp file after atomic rename")
}

// TestInstallBinary_NoopWhenSameSrcDst skips work when src == dst (the case
// when the running binary is already at the target install path, e.g. a
// re-run of `install` after a no-op build).
func TestInstallBinary_NoopWhenSameSrcDst(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "kite")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o755))

	assert.NoError(t, InstallBinary(path, path))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(data), "self-copy must not corrupt the file")
}

// TestBuildSvcConfig_PropagatesOptions asserts the kardianos config the
// installer builds matches what the cmd layer used to build inline. This is
// the contract that lets the dashboard install command and the CLI install
// produce identical service registrations.
func TestBuildSvcConfig_PropagatesOptions(t *testing.T) {
	opts := Options{
		UserMode:  true,
		BinaryDir: "/opt/kc",
		CertsDir:  "/var/kc",
		CfgFile:   "/etc/kc.yaml",
		DbPath:    "/var/kc/kite.db",
		Endpoint:  "https://otel.example.test",
		Verbose:   true,
	}
	cfg := BuildSvcConfig(opts)
	assert.Equal(t, SvcName, cfg.Name)
	assert.Equal(t, opts.BinaryPath(), cfg.Executable)
	assert.Contains(t, cfg.Arguments, "--certs-dir")
	assert.Contains(t, cfg.Arguments, "/var/kc")
	assert.Contains(t, cfg.Arguments, "--config")
	assert.Contains(t, cfg.Arguments, "--endpoint")
	assert.Contains(t, cfg.Arguments, "--verbose")
	assert.Equal(t, true, cfg.Option["UserService"])
}
