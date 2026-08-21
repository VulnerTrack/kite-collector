package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
)

// testLogger returns a logger that discards output, keeping test logs quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestState_String_AllValues(t *testing.T) {
	t.Parallel()

	cases := map[State]string{
		StateHealthy:     "healthy",
		StateDegraded:    "degraded",
		StateUnreachable: "unreachable",
		StateUntrusted:   "untrusted",
		State(42):        "unknown",
	}
	for state, want := range cases {
		assert.Equal(t, want, state.String())
	}
}

// writeKeyPairPEM writes a self-signed cert + key PEM pair into dir and
// returns their paths.
func writeKeyPairPEM(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "kite-manager-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func TestBuildMTLSConfig_HappyPath(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPairPEM(t, t.TempDir())
	tc, err := buildMTLSConfig(config.TLSConfig{CertFile: certPath, KeyFile: keyPath})
	require.NoError(t, err)
	require.Len(t, tc.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS13), tc.MinVersion, "mTLS must require TLS 1.3")
	assert.Nil(t, tc.RootCAs, "no CA file means the system pool")
}

func TestBuildMTLSConfig_WithCAFile(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPairPEM(t, t.TempDir())
	tc, err := buildMTLSConfig(config.TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   certPath, // the self-signed cert doubles as its own CA
	})
	require.NoError(t, err)
	assert.NotNil(t, tc.RootCAs, "a CA file must yield a dedicated root pool")
}

func TestBuildMTLSConfig_BadKeypair(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not pem"), 0o600))

	tc, err := buildMTLSConfig(config.TLSConfig{CertFile: bad, KeyFile: bad})
	require.Error(t, err)
	assert.Nil(t, tc)
	assert.Contains(t, err.Error(), "load mTLS keypair")
}

func TestBuildMTLSConfig_MissingCAFile(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPairPEM(t, t.TempDir())
	tc, err := buildMTLSConfig(config.TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   filepath.Join(t.TempDir(), "absent-ca.pem"),
	})
	require.Error(t, err)
	assert.Nil(t, tc)
	assert.Contains(t, err.Error(), "read CA file")
}

func TestBuildMTLSConfig_CAWithoutCertificates(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPairPEM(t, t.TempDir())
	emptyCA := filepath.Join(t.TempDir(), "empty-ca.pem")
	require.NoError(t, os.WriteFile(emptyCA, []byte("no certs here"), 0o600))

	tc, err := buildMTLSConfig(config.TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   emptyCA,
	})
	require.Error(t, err)
	assert.Nil(t, tc)
	assert.Contains(t, err.Error(), "CA file contains no valid certificates")
}

func TestManagerConnect_InsecureEndpoint(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep, err := m.connect(config.EndpointConfig{
		Name:    "plain",
		Address: "127.0.0.1:1", // never dialed: grpc.NewClient is lazy
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ep.Conn.Close() })

	assert.Equal(t, StateHealthy, ep.State, "new connections start healthy")
	assert.NotNil(t, ep.Conn)
	assert.NotNil(t, ep.Client)
	assert.WithinDuration(t, time.Now(), ep.LastSeen, 5*time.Second)
}

func TestManagerConnect_TLSWithoutClientCert(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep, err := m.connect(config.EndpointConfig{
		Name:    "tls-only",
		Address: "127.0.0.1:1",
		TLS:     config.TLSConfig{Enabled: true},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ep.Conn.Close() })
	assert.Equal(t, StateHealthy, ep.State)
}

func TestManagerConnect_MTLS(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPairPEM(t, t.TempDir())
	m := &Manager{logger: testLogger()}
	ep, err := m.connect(config.EndpointConfig{
		Name:    "mtls",
		Address: "127.0.0.1:1",
		TLS:     config.TLSConfig{CertFile: certPath, KeyFile: keyPath},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ep.Conn.Close() })
	assert.Equal(t, StateHealthy, ep.State)
}

func TestManagerConnect_BadMTLSFilesFail(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep, err := m.connect(config.EndpointConfig{
		Name:    "broken",
		Address: "127.0.0.1:1",
		TLS: config.TLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	})
	require.Error(t, err)
	assert.Nil(t, ep)
}

func TestManagerConnect_UnparsableTargetFails(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	// The double percent is an invalid URL escape, one of the few target
	// shapes grpc.NewClient rejects eagerly.
	ep, err := m.connect(config.EndpointConfig{
		Name:    "bad-target",
		Address: "dns://%%bad/host",
	})
	require.Error(t, err)
	assert.Nil(t, ep)
	assert.Contains(t, err.Error(), "dial dns://%%bad/host")
}

func TestNewManager_SortsByPriorityAndKeepsFailedAsUnreachable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configs := []config.EndpointConfig{
		{
			Name:     "good-secondary",
			Address:  "127.0.0.1:1",
			Priority: 2,
			Routes:   []string{"machines"},
		},
		{
			Name:     "broken-primary",
			Address:  "127.0.0.1:1",
			Priority: 1,
			Routes:   []string{"machines"},
			TLS: config.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
		},
	}

	m, err := NewManager(ctx, configs, nil) // nil logger must default, not panic
	require.NoError(t, err)
	t.Cleanup(m.Close)

	infos := m.List()
	require.Len(t, infos, 2)
	assert.Equal(t, "broken-primary", infos[0].Name, "endpoints must be sorted by priority")
	assert.Equal(t, "unreachable", infos[0].State,
		"a failed connection is kept as unreachable for later recovery")
	assert.Equal(t, "good-secondary", infos[1].Name)
	assert.Equal(t, "healthy", infos[1].State)

	// Routing must skip the unreachable primary despite its better priority.
	ep := m.ForRoute("machines")
	require.NotNil(t, ep)
	assert.Equal(t, "good-secondary", ep.Config.Name)
}

func TestNewManager_EmptyConfigs(t *testing.T) {
	t.Parallel()

	m, err := NewManager(context.Background(), nil, testLogger())
	require.NoError(t, err)
	t.Cleanup(m.Close)
	assert.Empty(t, m.List())
	assert.Nil(t, m.ForRoute("machines"))
}

func TestAllForRoute_OrderingAndFiltering(t *testing.T) {
	t.Parallel()

	m := &Manager{
		logger: testLogger(),
		endpoints: []*Endpoint{
			{
				Config: config.EndpointConfig{Name: "primary", Priority: 1, Routes: []string{"machines", "findings"}},
				State:  StateHealthy,
			},
			{
				Config: config.EndpointConfig{Name: "degraded-mid", Priority: 2, Routes: []string{"machines"}},
				State:  StateDegraded,
			},
			{
				Config: config.EndpointConfig{Name: "down", Priority: 3, Routes: []string{"machines"}},
				State:  StateUnreachable,
			},
			{
				Config: config.EndpointConfig{Name: "untrusted", Priority: 4, Routes: []string{"machines"}},
				State:  StateUntrusted,
			},
			{
				Config: config.EndpointConfig{Name: "other-route", Priority: 5, Routes: []string{"heartbeat"}},
				State:  StateHealthy,
			},
		},
	}

	got := m.AllForRoute("machines")
	require.Len(t, got, 2, "unreachable, untrusted, and non-matching endpoints must be excluded")
	assert.Equal(t, "primary", got[0].Config.Name)
	assert.Equal(t, "degraded-mid", got[1].Config.Name, "degraded endpoints still serve as fallbacks")

	assert.Empty(t, m.AllForRoute("no-such-route"))
}

func TestManagerClose_NilCancelAndNilConns(t *testing.T) {
	t.Parallel()

	m := &Manager{
		logger: testLogger(),
		endpoints: []*Endpoint{
			{Config: config.EndpointConfig{Name: "never-connected"}, State: StateUnreachable},
		},
	}
	assert.NotPanics(t, m.Close, "Close must tolerate a manager that never started health checks")
}
