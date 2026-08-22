package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func checkByName(t *testing.T, checks []doctorCheck, name string) doctorCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not in %+v", name, checks)
	return doctorCheck{}
}

func TestDoctorConfigCheck(t *testing.T) {
	// No file given → built-in defaults pass.
	_, c := doctorConfigCheck("")
	assert.Equal(t, doctorPass, c.Status)
	assert.Contains(t, c.Detail, "built-in defaults")

	// Named file missing → fail (an explicit config that doesn't exist is
	// an operator mistake, not a default).
	_, c = doctorConfigCheck(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.Equal(t, doctorFail, c.Status)

	// Invalid YAML → fail with the parse error surfaced.
	bad := filepath.Join(t.TempDir(), "kite.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("discovery: [not: valid"), 0o600))
	_, c = doctorConfigCheck(bad)
	assert.Equal(t, doctorFail, c.Status)
	assert.NotEmpty(t, c.Detail)
}

func TestDoctorCertificatesCheck(t *testing.T) {
	state := installer.State{}

	// No PEMs at all → warn with the enroll hint (fresh host, not broken).
	c := doctorCertificatesCheck(t.TempDir(), state)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Contains(t, c.Hint, "enroll")

	// Partial enrollment → fail (a half-written cert dir IS broken).
	partial := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(partial, "ca.pem"), []byte("x"), 0o600))
	c = doctorCertificatesCheck(partial, state)
	assert.Equal(t, doctorFail, c.Status)

	// Healthy certs → pass with days-left detail.
	healthy := t.TempDir()
	writeTestEnrollmentPEMs(t, healthy, time.Now().Add(80*24*time.Hour))
	c = doctorCertificatesCheck(healthy, state)
	assert.Equal(t, doctorPass, c.Status)
	assert.Contains(t, c.Detail, "valid until")

	// Expiring soon → warn.
	soon := t.TempDir()
	writeTestEnrollmentPEMs(t, soon, time.Now().Add(5*24*time.Hour))
	c = doctorCertificatesCheck(soon, state)
	assert.Equal(t, doctorWarn, c.Status)

	// Expired → fail with the re-enroll hint.
	expired := t.TempDir()
	writeTestEnrollmentPEMs(t, expired, time.Now().Add(-time.Hour))
	c = doctorCertificatesCheck(expired, state)
	assert.Equal(t, doctorFail, c.Status)
	assert.Contains(t, c.Detail, "EXPIRED")
}

func TestDoctorDatabaseCheck_MissingIsAWarnNotAFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kite.db")
	c := doctorDatabaseCheck(context.Background(), dbPath)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Contains(t, c.Hint, "first scan")
	_, err := os.Stat(dbPath)
	assert.True(t, os.IsNotExist(err), "doctor must be read-only and never create the DB")
}

func TestDoctorConnectivityChecks_PlainHTTPEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/logs" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	checks := doctorConnectivityChecks(srv.URL, t.TempDir(), 3*time.Second)
	require.Len(t, checks, 3)
	assert.Equal(t, doctorPass, checkByName(t, checks, "tcp-dial").Status)
	assert.Equal(t, doctorSkip, checkByName(t, checks, "tls-handshake").Status, "no certs → mTLS stage skipped")
	assert.Equal(t, doctorPass, checkByName(t, checks, "otlp-ping").Status)
}

func TestDoctorConnectivityChecks_UnreachableEndpoint(t *testing.T) {
	checks := doctorConnectivityChecks("http://127.0.0.1:1", t.TempDir(), 500*time.Millisecond)
	require.Len(t, checks, 3)
	assert.Equal(t, doctorFail, checkByName(t, checks, "tcp-dial").Status)
	assert.Equal(t, doctorSkip, checkByName(t, checks, "tls-handshake").Status)
	assert.Equal(t, doctorSkip, checkByName(t, checks, "otlp-ping").Status)
	assert.Contains(t, checkByName(t, checks, "otlp-ping").Detail, "not reached")
}

func TestRunDoctorChecks_OfflineSkipsNetworkStages(t *testing.T) {
	checks := runDoctorChecks(context.Background(), doctorOptions{
		CertsDir: t.TempDir(),
		DbPath:   filepath.Join(t.TempDir(), "kite.db"),
		Offline:  true,
		Timeout:  time.Second,
	})
	last := checks[len(checks)-1]
	assert.Equal(t, "connectivity", last.Name)
	assert.Equal(t, doctorSkip, last.Status)
	for _, c := range checks {
		assert.NotContains(t, []string{"tcp-dial", "tls-handshake", "otlp-ping"}, c.Name,
			"offline run must not include network stages")
	}
}

func TestCountDoctorFailures(t *testing.T) {
	checks := []doctorCheck{
		{Status: doctorPass}, {Status: doctorWarn}, {Status: doctorSkip}, {Status: doctorFail}, {Status: doctorFail},
	}
	assert.Equal(t, 2, countDoctorFailures(checks))
	assert.Equal(t, 0, countDoctorFailures(checks[:3]), "warn and skip never fail the run")
}

func TestDoctorBinaryDriftCheck(t *testing.T) {
	binDir := t.TempDir()
	certsDir := t.TempDir()
	registered := filepath.Join(binDir, "kite-collector")
	require.NoError(t, os.WriteFile(registered, []byte("service"), 0o755)) //#nosec G306 -- test binary
	opts := installer.Options{BinaryDir: binDir, CertsDir: certsDir}

	// PATH resolves to the same file → pass.
	t.Setenv("PATH", binDir)
	c := doctorBinaryDriftCheck(opts)
	assert.Equal(t, doctorPass, c.Status, "detail: %s", c.Detail)

	// PATH resolves to a different, newer binary → warn with repair hint.
	otherDir := t.TempDir()
	other := filepath.Join(otherDir, "kite-collector")
	require.NoError(t, os.WriteFile(other, []byte("cli, different"), 0o755)) //#nosec G306 -- test binary
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(other, future, future))
	t.Setenv("PATH", otherDir)
	c = doctorBinaryDriftCheck(opts)
	assert.Equal(t, doctorWarn, c.Status)
	assert.Contains(t, c.Detail, "service binary is older")
	assert.Contains(t, c.Hint, "install --repair")

	// The manifest's recorded path is authoritative over the conventional
	// default: point it at the PATH binary and drift disappears.
	require.NoError(t, installer.WriteInstallManifest(opts, installer.InstallManifest{
		BinaryPath: other, Owner: "homebrew",
	}))
	c = doctorBinaryDriftCheck(opts)
	assert.Equal(t, doctorPass, c.Status, "detail: %s", c.Detail)

	// No binary on PATH → skip, never a failure.
	t.Setenv("PATH", t.TempDir())
	c = doctorBinaryDriftCheck(opts)
	assert.Equal(t, doctorSkip, c.Status)
}
