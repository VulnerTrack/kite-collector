package middleware

import (
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

// These tests pin the read-path tenancy contract: a request's tenant scope is
// derived solely and reliably from the mTLS client certificate Organization,
// and never leaks between requests or from the API-key fallback.

// mkCert builds a parsed leaf certificate with the given CN and Organizations.
// The auth middleware only reads Subject fields, NotAfter, and SerialNumber,
// so a bare (unsigned) certificate struct is sufficient and keeps the test
// fast. NotAfter is in the future so the not-expired check passes.
func mkCert(cn string, orgs ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

// serveWithCert runs handler through MTLSAuth with a request presenting cert
// and returns the recorder plus the tenant/agent the inner handler observed.
func serveWithCert(t *testing.T, cert *x509.Certificate) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	var gotTenant, gotAgent string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = TenantIDFromContext(r.Context())
		gotAgent = AgentIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := newTestRequest(t)
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	w := httptest.NewRecorder()
	MTLSAuth(inner).ServeHTTP(w, r)
	return w, gotTenant, gotAgent
}

func TestMTLSAuth_TenantFromOrganization(t *testing.T) {
	w, tenant, agent := serveWithCert(t, mkCert("agent-uuid", "tenant-uuid"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tenant-uuid", tenant)
	assert.Equal(t, "agent-uuid", agent)
}

func TestMTLSAuth_MultipleOrganizations_UsesFirst(t *testing.T) {
	_, tenant, _ := serveWithCert(t, mkCert("agent", "tenant-first", "tenant-second"))
	assert.Equal(t, "tenant-first", tenant,
		"tenant must be the first Organization, deterministically")
}

func TestMTLSAuth_NoOrganization_AllowsWithEmptyTenant(t *testing.T) {
	w, tenant, agent := serveWithCert(t, mkCert("agent-only")) // no Organization
	assert.Equal(t, http.StatusOK, w.Code, "a cert without Organization is still authenticated")
	assert.Empty(t, tenant, "no Organization -> no tenant scope")
	assert.Equal(t, "agent-only", agent)
}

func TestMTLSAuth_NoClientCertificate_Rejected(t *testing.T) {
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler must not run without a client certificate")
	})
	r := newTestRequest(t) // r.TLS == nil
	w := httptest.NewRecorder()
	MTLSAuth(inner).ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMTLSAuth_TenantIsolation_RequestsDoNotBleed(t *testing.T) {
	_, alpha, _ := serveWithCert(t, mkCert("agent-a", "tenant-alpha"))
	_, beta, _ := serveWithCert(t, mkCert("agent-b", "tenant-beta"))
	assert.Equal(t, "tenant-alpha", alpha)
	assert.Equal(t, "tenant-beta", beta)
}

func TestMTLSAuth_TenantValueUsedVerbatim(t *testing.T) {
	// The value that scopes queries downstream is the raw CA-attested
	// Organization; sanitizeLog only affects the debug log line, not the
	// tenant placed in the request context.
	_, tenant, _ := serveWithCert(t, mkCert("agent", "019def78-0000-7000-8000-000000000abc"))
	assert.Equal(t, "019def78-0000-7000-8000-000000000abc", tenant)
}

// The API-key fallback authenticates the caller but must NOT grant any tenant
// scope — tenancy is a certificate-only property. This prevents an API key
// from acting across tenants.
func TestMTLSOrAPIKey_APIKeyAuth_GrantsNoTenant(t *testing.T) {
	var gotTenant, gotAgent string
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotTenant = TenantIDFromContext(r.Context())
		gotAgent = AgentIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := newTestRequest(t)
	r.Header.Set("X-API-Key", "shared-key")
	w := httptest.NewRecorder()
	MTLSOrAPIKey(inner, "shared-key").ServeHTTP(w, r)

	require.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, gotTenant, "API-key auth must not carry a tenant scope")
	assert.Empty(t, gotAgent, "API-key auth carries no agent identity")
}

// When both a client cert and an API key are present, the certificate's tenant
// takes precedence — auth must not silently drop tenancy in favour of the key.
func TestMTLSOrAPIKey_CertPreferredOverAPIKey_KeepsTenant(t *testing.T) {
	var gotTenant string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := newTestRequest(t)
	r.Header.Set("X-API-Key", "shared-key")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{mkCert("agent", "tenant-cert")}}
	w := httptest.NewRecorder()
	MTLSOrAPIKey(inner, "shared-key").ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tenant-cert", gotTenant)
}
