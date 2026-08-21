package emitter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/hostmetrics"
)

// ---------------------------------------------------------------------------
// TLS fixtures
// ---------------------------------------------------------------------------

// tlsTestPKI is a three-tier chain (root → intermediate → leaf) generated
// in-process for buildTLSConfig tests. No real endpoints are involved.
type tlsTestPKI struct {
	caFile       string
	certFile     string // leaf certificate (also usable as a client cert)
	keyFile      string
	leaf         *x509.Certificate
	intermediate *x509.Certificate
	untrusted    *x509.Certificate // self-signed, NOT in the CA file
}

func mustIssueCert(
	t *testing.T,
	template, parent *x509.Certificate,
	pub *ecdsa.PublicKey,
	parentKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTLSTestPKI(t *testing.T) *tlsTestPKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()

	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	rootKey, intermediateKey, leafKey, untrustedKey := newKey(), newKey(), newKey(), newKey()

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kite Test Root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := mustIssueCert(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Kite Test Intermediate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intermediate := mustIssueCert(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "otelcol"},
		DNSNames:     []string{"otelcol.internal"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leaf := mustIssueCert(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)

	untrustedTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	untrusted := mustIssueCert(t, untrustedTemplate, untrustedTemplate, &untrustedKey.PublicKey, untrustedKey)

	writePEM := func(name, blockType string, der []byte) string {
		path := filepath.Join(dir, name)
		data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)

	return &tlsTestPKI{
		caFile:       writePEM("ca.pem", "CERTIFICATE", root.Raw),
		certFile:     writePEM("client.pem", "CERTIFICATE", leaf.Raw),
		keyFile:      writePEM("client-key.pem", "PRIVATE KEY", leafKeyDER),
		leaf:         leaf,
		intermediate: intermediate,
		untrusted:    untrusted,
	}
}

// ---------------------------------------------------------------------------
// TLS construction
// ---------------------------------------------------------------------------

func TestNewOTLP_TLSEnabledBuildsTransport(t *testing.T) {
	pki := newTLSTestPKI(t)
	o, err := NewOTLP(OTLPConfig{
		Endpoint: "https://otel.example",
		TLS:      TLSConfig{Enabled: true, CAFile: pki.caFile},
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, "https://otel.example/v1/logs", o.endpoint)
}

func TestNewOTLP_TLSSetupFailureSurfaces(t *testing.T) {
	_, err := NewOTLP(OTLPConfig{
		Endpoint: "https://otel.example",
		TLS:      TLSConfig{Enabled: true, CAFile: filepath.Join(t.TempDir(), "missing.pem")},
	}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp: tls setup")
	assert.Contains(t, err.Error(), "read CA file")
}

func TestNewOTLPMetrics_TLSEnabledBuildsTransport(t *testing.T) {
	pki := newTLSTestPKI(t)
	e, err := NewOTLPMetrics(OTLPConfig{
		Endpoint: "https://otel.example",
		TLS:      TLSConfig{Enabled: true, CAFile: pki.caFile},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://otel.example/v1/metrics", e.endpoint)
}

func TestNewOTLPMetrics_TLSSetupFailureSurfaces(t *testing.T) {
	_, err := NewOTLPMetrics(OTLPConfig{
		Endpoint: "https://otel.example",
		TLS:      TLSConfig{Enabled: true, CAFile: filepath.Join(t.TempDir(), "missing.pem")},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp metrics: tls setup")
}

func TestBuildTLSConfig_LoadsClientCertificate(t *testing.T) {
	pki := newTLSTestPKI(t)
	cfg, err := buildTLSConfig(TLSConfig{
		Enabled:  true,
		CAFile:   pki.caFile,
		CertFile: pki.certFile,
		KeyFile:  pki.keyFile,
	})
	require.NoError(t, err)
	assert.Len(t, cfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestBuildTLSConfig_ClientCertificateLoadFailure(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("not a certificate"), 0o600))

	_, err := buildTLSConfig(TLSConfig{Enabled: true, CertFile: junk, KeyFile: junk})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load client certificate")
}

func TestBuildTLSConfig_VerifyConnection(t *testing.T) {
	pki := newTLSTestPKI(t)
	cfg, err := buildTLSConfig(TLSConfig{Enabled: true, CAFile: pki.caFile})
	require.NoError(t, err)
	require.NotNil(t, cfg.VerifyConnection)

	t.Run("no peer certificate", func(t *testing.T) {
		err := cfg.VerifyConnection(tls.ConnectionState{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server presented no certificate")
	})

	t.Run("full verification with matching hostname", func(t *testing.T) {
		err := cfg.VerifyConnection(tls.ConnectionState{
			ServerName:       "otelcol.internal",
			PeerCertificates: []*x509.Certificate{pki.leaf, pki.intermediate},
		})
		assert.NoError(t, err)
	})

	t.Run("private PKI name mismatch falls back to chain-only", func(t *testing.T) {
		err := cfg.VerifyConnection(tls.ConnectionState{
			ServerName:       "public.example.com",
			PeerCertificates: []*x509.Certificate{pki.leaf, pki.intermediate},
		})
		assert.NoError(t, err, "CA-chain-only fallback must accept internal-name certs")
	})

	t.Run("untrusted certificate rejected", func(t *testing.T) {
		err := cfg.VerifyConnection(tls.ConnectionState{
			ServerName:       "rogue",
			PeerCertificates: []*x509.Certificate{pki.untrusted},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verify peer certificate")
	})
}

// ---------------------------------------------------------------------------
// Endpoint validation edge
// ---------------------------------------------------------------------------

func TestNewOTLP_UnparseableEndpoint(t *testing.T) {
	_, err := NewOTLP(OTLPConfig{Endpoint: "http://[::1"}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid endpoint")
}

// ---------------------------------------------------------------------------
// Emitter lifecycle
// ---------------------------------------------------------------------------

func TestOTLPEmitter_EmitAfterShutdownFails(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	require.NoError(t, em.Shutdown(context.Background()))

	err := em.Emit(context.Background(), makeEvent(t, model.EventMachineDiscovered, model.SeverityLow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "emitter is shut down")
	assert.Empty(t, *reqs, "a closed emitter must not reach the collector")
}

func TestOTLPEmitter_EmitBatchEmptyIsNoop(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	require.NoError(t, em.EmitBatch(context.Background(), nil))
	assert.Empty(t, *reqs, "empty batch must not produce a request")
}

func TestOTLPEmitter_ShutdownIsIdempotent(t *testing.T) {
	endpoint, _ := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	require.NoError(t, em.Shutdown(context.Background()))
	require.NoError(t, em.Shutdown(context.Background()), "second shutdown must be a no-op")
}

func TestOTLPMetrics_ShutdownIsIdempotent(t *testing.T) {
	srv, _ := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)
	require.NoError(t, e.Shutdown(context.Background()))
	require.NoError(t, e.Shutdown(context.Background()))
}

// ---------------------------------------------------------------------------
// Retry behaviour edges
// ---------------------------------------------------------------------------

func TestOTLP_RetryExhaustionSurfacesLastError(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusServiceUnavailable)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	err := em.Emit(context.Background(), makeEvent(t, model.EventMachineDiscovered, model.SeverityLow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted 3 retry attempts")
	assert.Contains(t, err.Error(), "server returned 503")
	assert.Len(t, *reqs, 3, "the full retry budget must be spent on 5xx")
}

func TestOTLP_ContextCancelledDuringBackoff(t *testing.T) {
	endpoint, _ := startCaptureServer(t, http.StatusServiceUnavailable)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := em.Emit(ctx, makeEvent(t, model.EventMachineDiscovered, model.SeverityLow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled during retry backoff")
}

func TestOTLP_RetryOn429ThenSucceeds(t *testing.T) {
	endpoint, reqs := startSequenceServer(t, []int{http.StatusTooManyRequests, http.StatusOK})
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	require.NoError(t, em.Emit(context.Background(),
		makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)))
	assert.Len(t, *reqs, 2, "429 must be retried exactly once before the 200")
}

func TestOTLPMetrics_ContextCancelledDuringBackoff(t *testing.T) {
	srv, _ := captureServer(t, http.StatusServiceUnavailable)
	e := newMetricsEmitter(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := e.EmitBatch(ctx, sampleBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp metrics: context cancelled during retry backoff")
}

func TestOTLPMetrics_RetryOn429ThenSucceeds(t *testing.T) {
	endpoint, reqs := startSequenceServer(t, []int{http.StatusTooManyRequests, http.StatusOK})
	e := newMetricsEmitter(t, endpoint)

	require.NoError(t, e.EmitBatch(context.Background(), sampleBatch()))
	assert.Len(t, *reqs, 2)
}

// TestOTLPMetrics_TerminalURLErrorSkipsRetry mirrors the logs emitter's
// terminal-URL contract for the metrics path: a malformed endpoint must fail
// once, not spin through the whole retry budget.
func TestOTLPMetrics_TerminalURLErrorSkipsRetry(t *testing.T) {
	srv, _ := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)
	e.endpoint = "otel.vulnertrack.io/v1/metrics" // scheme-less → unsupported protocol scheme

	err := e.EmitBatch(context.Background(), sampleBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol scheme")
	assert.NotContains(t, err.Error(), "exhausted",
		"URL-shape error must be terminal; retry loop should not have run")
}

// ---------------------------------------------------------------------------
// EmitSnapshot timestamp defaulting
// ---------------------------------------------------------------------------

func TestOTLPMetrics_EmitSnapshotZeroCollectedAtUsesNow(t *testing.T) {
	srv, captured := captureServer(t, http.StatusOK)
	e := newMetricsEmitter(t, srv.URL)

	before := time.Now().UTC()
	require.NoError(t, e.EmitSnapshot(context.Background(),
		hostmetrics.Snapshot{Samples: sampleBatch()}))
	after := time.Now().UTC()

	var payload otlpMetricsPayload
	require.NoError(t, json.Unmarshal(captured.Load().Body, &payload))
	require.Len(t, payload.ResourceMetrics, 1)
	require.Len(t, payload.ResourceMetrics[0].ScopeMetrics, 1)
	metrics := payload.ResourceMetrics[0].ScopeMetrics[0].Metrics
	require.NotEmpty(t, metrics)
	require.NotNil(t, metrics[0].Gauge)
	require.NotEmpty(t, metrics[0].Gauge.DataPoints)

	nanos, err := strconv.ParseInt(metrics[0].Gauge.DataPoints[0].TimeUnixNano, 10, 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, nanos, before.UnixNano(), "zero CollectedAt must default to now")
	assert.LessOrEqual(t, nanos, after.UnixNano())
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

func TestTransientError_UnwrapExposesCause(t *testing.T) {
	sentinel := errors.New("collector melted")
	te := &transientError{err: sentinel}

	assert.Equal(t, "collector melted", te.Error())
	assert.Same(t, sentinel, te.Unwrap())
	assert.ErrorIs(t, te, sentinel)
}

func TestBackoffDelay_ExponentialWithCap(t *testing.T) {
	base := 100 * time.Millisecond
	maxDelay := time.Second

	assert.Equal(t, 100*time.Millisecond, backoffDelay(1, base, maxDelay))
	assert.Equal(t, 200*time.Millisecond, backoffDelay(2, base, maxDelay))
	assert.Equal(t, 400*time.Millisecond, backoffDelay(3, base, maxDelay))
	assert.Equal(t, maxDelay, backoffDelay(5, base, maxDelay), "delay must be capped at maxDelay")
}

func TestContractMachineType_FoldsOntoContractSet(t *testing.T) {
	tests := []struct {
		in   model.MachineType
		want string
	}{
		{model.MachineTypeServer, "server"},
		{model.MachineTypeWorkstation, "workstation"},
		{model.MachineTypeContainer, "container"},
		{model.MachineTypeVirtualMachine, "vm"},
		{model.MachineTypeCloudInstance, "vm"},
		{model.MachineTypeNetworkDevice, "network-device"},
		{model.MachineTypeIOTDevice, "iot"},
		{model.MachineTypeAppliance, "unknown"},
		{model.MachineTypeSoftwareProject, "unknown"},
		{model.MachineTypeRepository, "unknown"},
		{model.MachineType("hologram"), "unknown"},
		{model.MachineType(""), "unknown"},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			assert.Equal(t, tt.want, contractMachineType(tt.in))
		})
	}
}
