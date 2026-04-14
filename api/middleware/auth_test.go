package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Context extraction helpers
// ---------------------------------------------------------------------------

func TestTenantIDFromContext_Empty(t *testing.T) {
	r := newTestRequest(t)
	assert.Equal(t, "", TenantIDFromContext(r.Context()))
}

func TestAgentIDFromContext_Empty(t *testing.T) {
	r := newTestRequest(t)
	assert.Equal(t, "", AgentIDFromContext(r.Context()))
}

// ---------------------------------------------------------------------------
// APIKeyAuth
// ---------------------------------------------------------------------------

func TestAPIKeyAuth_ValidKey(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyAuth(inner, "secret-key")
	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.Header.Set("X-API-Key", "secret-key")

	handler.ServeHTTP(w, r)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPIKeyAuth_MissingKey(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := APIKeyAuth(inner, "secret-key")
	w := httptest.NewRecorder()
	r := newTestRequest(t)

	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAPIKeyAuth_WrongKey(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := APIKeyAuth(inner, "secret-key")
	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.Header.Set("X-API-Key", "wrong-key")

	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// MTLSOrAPIKey — context injection from mTLS certificate
// ---------------------------------------------------------------------------

func TestMTLSOrAPIKey_ExtractsAgentAndTenantFromCert(t *testing.T) {
	var gotAgentID, gotTenantID string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = AgentIDFromContext(r.Context())
		gotTenantID = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := MTLSOrAPIKey(inner, "")

	cert := makeSelfSignedCert(t, "019abc12-test-agent-id", "019def78-test-tenant-id")

	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "019abc12-test-agent-id", gotAgentID)
	assert.Equal(t, "019def78-test-tenant-id", gotTenantID)
}

func TestMTLSOrAPIKey_FallsBackToAPIKey(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := MTLSOrAPIKey(inner, "my-api-key")

	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.Header.Set("X-API-Key", "my-api-key")

	handler.ServeHTTP(w, r)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMTLSOrAPIKey_RejectsWithoutAuth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	handler := MTLSOrAPIKey(inner, "my-api-key")

	w := httptest.NewRecorder()
	r := newTestRequest(t)

	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuth_ExtractsContext(t *testing.T) {
	var gotAgentID, gotTenantID string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = AgentIDFromContext(r.Context())
		gotTenantID = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := MTLSAuth(inner)
	cert := makeSelfSignedCert(t, "agent-uuid", "tenant-uuid")

	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "agent-uuid", gotAgentID)
	assert.Equal(t, "tenant-uuid", gotTenantID)
}

func TestMTLSAuth_RejectsExpiredCert(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	handler := MTLSAuth(inner)

	// Create an expired certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired-agent"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := newTestRequest(t)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestRequest creates a GET / request with context.Background (satisfies noctx).
func newTestRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	return r
}

// makeSelfSignedCert creates a self-signed certificate with the given CN and
// Organization for testing middleware context extraction.
func makeSelfSignedCert(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
