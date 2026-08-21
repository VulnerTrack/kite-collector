package dashboard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
)

// runReachProbe: 2xx-4xx from /healthz passes (the platform answers 401
// to unauthenticated probes — reachability is what is being measured),
// 5xx and transport errors fail, and the Date header is handed back for
// the clock probe.
func TestRunReachProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/healthz", r.URL.Path)
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, dateHdr := runReachProbe(context.Background(), srv.Client(), srv.URL+"/")
	assert.Equal(t, "pass", res.Result, "401 still proves reachability")
	assert.Equal(t, "HTTP 401", res.Diagnostic)
	assert.NotEmpty(t, dateHdr)

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()
	res, _ = runReachProbe(context.Background(), bad.Client(), bad.URL)
	assert.Equal(t, "fail", res.Result)
	assert.Contains(t, res.Diagnostic, "HTTP 502")

	res, _ = runReachProbe(context.Background(), &http.Client{Timeout: 200 * time.Millisecond},
		"http://127.0.0.1:1")
	assert.Equal(t, "fail", res.Result, "connection refused fails the probe")
}

func TestRunClockProbe(t *testing.T) {
	assert.Equal(t, "skip", runClockProbe("").Result, "no Date header skips, not fails")
	assert.Equal(t, "fail", runClockProbe("not a date").Result)

	now := runClockProbe(time.Now().UTC().Format(http.TimeFormat))
	assert.Equal(t, "pass", now.Result)

	skewed := runClockProbe(time.Now().Add(-5 * time.Minute).UTC().Format(http.TimeFormat))
	assert.Equal(t, "fail", skewed.Result)
	assert.Contains(t, skewed.Diagnostic, "> 60s")
}

// runOTLPProbe: only 200/202 pass, the API key travels as X-API-Key, and
// the body is the minimal OTLP log envelope.
func TestRunOTLPProbe(t *testing.T) {
	var gotKey, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/logs", r.URL.Path)
		gotKey = r.Header.Get("X-API-Key")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	res := runOTLPProbe(context.Background(), srv.Client(), srv.URL, "key-1")
	assert.Equal(t, "pass", res.Result)
	assert.Equal(t, "HTTP 202", res.Diagnostic)
	assert.Equal(t, "key-1", gotKey)
	assert.Equal(t, "application/json", gotCT)

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer rejecting.Close()
	res = runOTLPProbe(context.Background(), rejecting.Client(), rejecting.URL, "")
	assert.Equal(t, "fail", res.Result)
	assert.Contains(t, res.Diagnostic, "HTTP 403")

	res = runOTLPProbe(context.Background(), &http.Client{Timeout: 200 * time.Millisecond},
		"http://127.0.0.1:1", "")
	assert.Equal(t, "fail", res.Result)
}

// onboardingTLSConfig: a fully-populated certs dir flips PKI on with the
// canonical file names; missing any one file leaves the passed config
// untouched, and havePKI re-verifies the files actually exist.
func TestOnboardingTLSConfig(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"agent.pem", "agent-key.pem", "ca.pem"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("pem"), 0o600))
	}
	cfg, havePKI := onboardingTLSConfig(onboardingDeps{CertsDir: dir})
	assert.True(t, havePKI)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, filepath.Join(dir, "agent.pem"), cfg.CertFile)
	assert.Equal(t, filepath.Join(dir, "ca.pem"), cfg.CAFile)

	partial := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(partial, "agent.pem"), []byte("pem"), 0o600))
	cfg, havePKI = onboardingTLSConfig(onboardingDeps{CertsDir: partial})
	assert.False(t, havePKI, "a partial certs dir must not enable PKI")
	assert.False(t, cfg.Enabled)

	// Pre-enabled config pointing at files that vanished: havePKI false.
	cfg, havePKI = onboardingTLSConfig(onboardingDeps{TLSConfig: config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(partial, "gone.pem"),
		KeyFile:  filepath.Join(partial, "gone-key.pem"),
	}})
	assert.True(t, cfg.Enabled, "the config passes through")
	assert.False(t, havePKI, "but missing files disqualify PKI")
}

func TestOnboardingProbeClient(t *testing.T) {
	injected := &http.Client{}
	got, err := onboardingProbeClient(onboardingDeps{ProbeClient: injected}, config.TLSConfig{})
	require.NoError(t, err)
	assert.Same(t, injected, got, "an injected client is used verbatim")

	got, err = onboardingProbeClient(onboardingDeps{}, config.TLSConfig{})
	require.NoError(t, err)
	assert.Equal(t, 8*time.Second, got.Timeout)

	_, err = onboardingProbeClient(onboardingDeps{}, config.TLSConfig{
		Enabled: true,
		CAFile:  "/no/such/ca.pem",
	})
	require.Error(t, err, "an unreadable CA file must surface, not silently degrade")
}

// buildTLSConfig: CA loading, the insecure escape hatch, and the
// VerifyConnection callback's no-certificate rejection.
func TestBuildTLSConfig(t *testing.T) {
	t.Setenv("KITE_INSECURE_SKIP_VERIFY", "")

	cfg, err := buildTLSConfig(config.TLSConfig{})
	require.NoError(t, err)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.NotNil(t, cfg.VerifyConnection)
	assert.EqualValues(t, 0x0303, cfg.MinVersion, "TLS 1.2 floor")

	_, err = buildTLSConfig(config.TLSConfig{CAFile: "/no/such/ca.pem"})
	require.Error(t, err)

	// VerifyConnection rejects an empty peer chain outright.
	err = cfg.VerifyConnection(tlsConnState(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificate")

	t.Setenv("KITE_INSECURE_SKIP_VERIFY", "true")
	insecure, err := buildTLSConfig(config.TLSConfig{})
	require.NoError(t, err)
	assert.True(t, insecure.InsecureSkipVerify)
	assert.NoError(t, insecure.VerifyConnection(tlsConnState(nil)),
		"the opt-in escape hatch bypasses verification entirely")
}

// tlsConnState builds a minimal tls.ConnectionState for the verify hook.
func tlsConnState(certs []*x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: certs}
}
