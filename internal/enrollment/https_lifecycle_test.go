package enrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type callbackDoer struct {
	do func(*http.Request) (*http.Response, error)
}

func (d *callbackDoer) Do(req *http.Request) (*http.Response, error) {
	return d.do(req)
}

func writeAgentMaterial(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "kite-agent-1",
			Organization: []string{"org-a"},
		},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), certPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent-key.pem"), keyPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o644))
	return dir, key
}

func renewedCertificateResponse(t *testing.T, csrPEM, organization string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Renewal Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
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

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   "kite-agent-1",
			Organization: []string{organization},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(180 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		caCert,
		csr.PublicKey,
		caKey,
	)
	require.NoError(t, err)

	response, err := json.Marshal(renewHTTPResponse{
		Status:             "renewed",
		CACertificate:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		ClientCertificate:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		CertificateExpires: leafTemplate.NotAfter.UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	return string(response)
}

func TestHeartbeatHTTPSSignsCertificateProof(t *testing.T) {
	dir, key := writeAgentMaterial(t)
	client := NewClient(nil)
	client.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, heartbeatURL, req.URL.String())
		assert.Empty(t, req.Header.Get("Authorization"))
		var proof agentProof
		require.NoError(t, json.NewDecoder(req.Body).Decode(&proof))
		assert.Equal(t, "kite-agent-1", proof.AgentCode)
		assert.NotEmpty(t, proof.CertificatePEM)
		assert.NotEmpty(t, proof.Nonce)

		signature, err := base64.StdEncoding.DecodeString(proof.Signature)
		require.NoError(t, err)
		message := canonicalProofMessage(
			"heartbeat",
			proof.AgentCode,
			proof.Timestamp,
			proof.Nonce,
			"",
		)
		digest := sha256.Sum256(message)
		assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature))
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(assertReader(`{"status":"ok"}`)),
		}, nil
	}}

	require.NoError(t, client.HeartbeatHTTPS(context.Background(), dir))
}

func TestRenewHTTPSBindsSignatureToCSRAndReplacesCertificate(t *testing.T) {
	dir, key := writeAgentMaterial(t)
	client := NewClient(nil)
	client.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, renewURL, req.URL.String())
		var payload agentRenewRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
		block, _ := pem.Decode([]byte(payload.CSRPEM))
		require.NotNil(t, block)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "kite-agent-1", csr.Subject.CommonName)
		require.NoError(t, csr.CheckSignature())

		certPEM, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
		require.NoError(t, err)
		certBlock, _ := pem.Decode(certPEM)
		require.NotNil(t, certBlock)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		require.NoError(t, err)
		fingerprint := sha256.Sum256(cert.Raw)
		assert.Equal(t, base64Hex(fingerprint[:]), payload.CurrentCertificateFingerprint)
		assert.NotEmpty(t, payload.SignedAt)

		message := canonicalRenewalProofMessage(
			payload.CurrentCertificateFingerprint,
			payload.AgentCode,
			payload.SignedAt,
			payload.CSRPEM,
		)
		signature, err := base64.StdEncoding.DecodeString(payload.ProofSignature)
		require.NoError(t, err)
		digest := sha256.Sum256(message)
		assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Body: io.NopCloser(assertReader(
				renewedCertificateResponse(t, payload.CSRPEM, "org-a"),
			)),
		}, nil
	}}

	require.NoError(t, client.RenewHTTPS(context.Background(), dir))
	cert, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	assert.Contains(t, string(cert), "BEGIN CERTIFICATE")
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	assert.Contains(t, string(ca), "BEGIN CERTIFICATE")
}

func TestRenewHTTPSRejectsOrganizationChangeBeforeWriting(t *testing.T) {
	dir, _ := writeAgentMaterial(t)
	currentCert, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	currentCA, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)

	client := NewClient(nil)
	client.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		var payload agentRenewRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Body: io.NopCloser(assertReader(
				renewedCertificateResponse(t, payload.CSRPEM, "other-org"),
			)),
		}, nil
	}}

	err = client.RenewHTTPS(context.Background(), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization does not match")
	afterCert, readErr := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, readErr)
	afterCA, readErr := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, readErr)
	assert.Equal(t, currentCert, afterCert)
	assert.Equal(t, currentCA, afterCA)
}

func TestRunHTTPSLifecycle_CancelledContextReturnsAfterInitialChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := NewClient(nil)
	client.http = &callbackDoer{do: func(*http.Request) (*http.Response, error) {
		t.Fatal("missing credential files must prevent outbound lifecycle requests")
		return nil, nil
	}}

	done := make(chan struct{})
	go func() {
		client.RunHTTPSLifecycle(ctx, t.TempDir())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTPS lifecycle did not honor context cancellation")
	}
}

func assertReader(value string) io.Reader {
	return &stringReader{value: []byte(value)}
}

type stringReader struct {
	value []byte
}

func (r *stringReader) Read(p []byte) (int, error) {
	if len(r.value) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.value)
	r.value = r.value[n:]
	return n, nil
}

func base64Hex(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}
