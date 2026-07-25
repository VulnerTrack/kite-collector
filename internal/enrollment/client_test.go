package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/identity"
)

// stubDoer is an httpDoer returning a canned response/error, so Enroll's error
// paths can be exercised without a live PKI server.
type stubDoer struct {
	resp *http.Response
	err  error
	req  *http.Request
}

func (d *stubDoer) Do(req *http.Request) (*http.Response, error) {
	d.req = req
	return d.resp, d.err
}

func issueEnrollmentResponse(
	t *testing.T,
	csrPEM string,
	overridePublicKey *ecdsa.PublicKey,
) *http.Response {
	t.Helper()

	csrBlock, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, csrBlock)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "VulnerTrack Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader,
		caTemplate,
		caTemplate,
		&caKey.PublicKey,
		caKey,
	)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	publicKey := csr.PublicKey
	if overridePublicKey != nil {
		publicKey = overridePublicKey
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   csr.Subject.CommonName,
			Organization: []string{"org-test"},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		caCert,
		publicKey,
		caKey,
	)
	require.NoError(t, err)

	responseBody, err := json.Marshal(map[string]string{
		"status":              "enrolled",
		"certificate_id":      "cert-1",
		"ca_certificate":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		"client_certificate":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		"certificate_expires": leafTemplate.NotAfter.UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	return &http.Response{
		StatusCode: http.StatusCreated,
		Status:     "201 Created",
		Body:       io.NopCloser(strings.NewReader(string(responseBody))),
	}
}

func TestEnroll_NetworkFailurePropagatesCause(t *testing.T) {
	c := NewClient(nil)
	doer := &stubDoer{err: errors.New("dial tcp 203.0.113.1:443: connect: connection refused")}
	c.http = doer

	_, err := c.Enroll(context.Background(), "agent-1", "token")
	require.Error(t, err)
	require.NotNil(t, doer.req)
	assert.Equal(t, "Bearer token", doer.req.Header.Get("Authorization"))

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "enrollment failure must surface a *kiteerrors.Error")
	assert.Equal(t, "KITE-E017", ke.Code)
	assert.Equal(t, "connect", ke.Context["phase"])
	assert.Contains(t, err.Error(), "connection refused", "underlying cause must be preserved")
}

func TestEnroll_PKIRejectionSurfacesStatusAndBody(t *testing.T) {
	c := NewClient(nil)
	c.http = &stubDoer{resp: &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid enrollment token"}`)),
	}}

	_, err := c.Enroll(context.Background(), "agent-1", "bad-token")
	require.Error(t, err)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "PKI rejection must surface a *kiteerrors.Error")
	assert.Equal(t, "KITE-E017", ke.Code)
	assert.Equal(t, http.StatusUnauthorized, ke.Context["http_status"])
	assert.Contains(t, err.Error(), "PKI server returned 401", "status must be preserved as the cause")
	assert.Contains(t, err.Error(), "invalid enrollment token", "server body must be surfaced for diagnosis")
}

func TestEnroll_UsesBearerJWTAndPKIRequestContract(t *testing.T) {
	var requestBody map[string]string
	doer := &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "Bearer signed-jwt", req.Header.Get("Authorization"))
		require.NoError(t, json.NewDecoder(req.Body).Decode(&requestBody))
		return issueEnrollmentResponse(t, requestBody["csr_pem"], nil), nil
	}}
	c := NewClient(nil)
	c.http = doer

	result, err := c.Enroll(context.Background(), "kite-machine-1", "signed-jwt")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "kite-machine-1", requestBody["agent_code"])
	assert.Contains(t, requestBody["machine_fingerprint"], "sha256:")
	assert.Contains(t, requestBody["csr_pem"], "BEGIN CERTIFICATE REQUEST")
	assert.NotContains(t, requestBody, "token")
	assert.NotContains(t, requestBody, "client_key")
	assert.NotContains(t, requestBody["csr_pem"], "PRIVATE KEY")
	assert.Contains(t, string(result.ClientKey), "BEGIN PRIVATE KEY")
}

func TestEnroll_RejectsCertificateForDifferentPrivateKey(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	c := NewClient(nil)
	c.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		return issueEnrollmentResponse(t, body["csr_pem"], &otherKey.PublicKey), nil
	}}

	result, err := c.Enroll(context.Background(), "kite-machine-1", "signed-jwt")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "does not match generated private key")
}

func TestStoreCertificates(t *testing.T) {
	dir := t.TempDir()

	result := &Result{
		CACertificate:     []byte("--- CA CERT ---"),
		ClientCertificate: []byte("--- CLIENT CERT ---"),
		ClientKey:         []byte("--- CLIENT KEY ---"),
	}

	err := StoreCertificates(dir, result)
	require.NoError(t, err)

	// Verify files exist with correct content.
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.CACertificate, ca)

	cert, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientCertificate, cert)

	key, err := os.ReadFile(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientKey, key)

	// Verify private key has restrictive permissions.
	info, err := os.Stat(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
}

func TestMachineFingerprint(t *testing.T) {
	fp := identity.MachineFingerprint()
	assert.NotEmpty(t, fp)
}
