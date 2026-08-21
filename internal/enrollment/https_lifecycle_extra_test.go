package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errReader fails every Read so response-body error paths are reachable.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failure injected") }

// staticSigner is a crypto.Signer of a type signMessage does not support;
// its Sign always fails so CSR-construction error paths are reachable too.
type staticSigner struct{ pub crypto.PublicKey }

func (s staticSigner) Public() crypto.PublicKey { return s.pub }

func (s staticSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signing backend unavailable")
}

// selfSignedCertPEM builds a self-signed certificate for key with the given
// common name, returning it PEM-encoded.
func selfSignedCertPEM(t *testing.T, cn string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8KeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// -------------------------------------------------------------------------
// parsePrivateSigner
// -------------------------------------------------------------------------

func TestParsePrivateSigner_SEC1ECKey(t *testing.T) {
	key := newECDSAKey(t)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	signer, err := parsePrivateSigner(keyPEM)
	require.NoError(t, err)
	ecKey, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "SEC1 keys must parse to *ecdsa.PrivateKey")
	assert.True(t, ecKey.PublicKey.Equal(&key.PublicKey))
}

func TestParsePrivateSigner_PKCS1RSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	signer, err := parsePrivateSigner(keyPEM)
	require.NoError(t, err)
	rsaKey, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok, "PKCS1 keys must parse to *rsa.PrivateKey")
	assert.True(t, rsaKey.PublicKey.Equal(&key.PublicKey))
}

func TestParsePrivateSigner_RejectsNonSignerPKCS8Key(t *testing.T) {
	// X25519 parses as *ecdh.PrivateKey, which is not a crypto.Signer, so
	// the PKCS8 branch's type assertion must fall through to a clean error.
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = parsePrivateSigner(keyPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent private key format")
}

func TestParsePrivateSigner_NoPEMBlock(t *testing.T) {
	_, err := parsePrivateSigner([]byte("not pem at all"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

func TestParsePrivateSigner_GarbageDER(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	_, err := parsePrivateSigner(keyPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent private key format")
}

// -------------------------------------------------------------------------
// loadAgentMaterial
// -------------------------------------------------------------------------

func TestLoadAgentMaterial_ErrorPaths(t *testing.T) {
	key := newECDSAKey(t)
	goodCert := selfSignedCertPEM(t, "kite-agent-1", key)
	goodKey := pkcs8KeyPEM(t, key)
	otherKey := newECDSAKey(t)

	tests := []struct {
		name    string
		cert    []byte // nil = do not write agent.pem
		key     []byte // nil = do not write agent-key.pem
		wantErr string
	}{
		{name: "missing certificate", wantErr: "read agent certificate"},
		{name: "missing key", cert: goodCert, wantErr: "read agent private key"},
		{
			name: "certificate not PEM", cert: []byte("junk"), key: goodKey,
			wantErr: "agent certificate contains no PEM block",
		},
		{
			name: "certificate bad DER",
			cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
			key:  goodKey, wantErr: "parse agent certificate",
		},
		{
			name: "certificate without common name",
			cert: selfSignedCertPEM(t, "", key), key: goodKey,
			wantErr: "agent certificate has no common name",
		},
		{
			name: "unparseable key", cert: goodCert,
			key:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}),
			wantErr: "unsupported agent private key format",
		},
		{
			name: "key does not match certificate", cert: goodCert,
			key:     pkcs8KeyPEM(t, otherKey),
			wantErr: "agent certificate and private key do not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.cert != nil {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), tt.cert, 0o644))
			}
			if tt.key != nil {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "agent-key.pem"), tt.key, 0o600))
			}
			_, err := loadAgentMaterial(dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// -------------------------------------------------------------------------
// signMessage / signProof
// -------------------------------------------------------------------------

func TestSignMessage_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	message := []byte("kite-pki-v1 proof")

	signature, err := signMessage(key, message)
	require.NoError(t, err)

	digest := sha256.Sum256(message)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
}

func TestSignMessage_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("kite-pki-v1 proof")

	signature, err := signMessage(priv, message)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, message, signature))
}

func TestSignMessage_UnsupportedKeyType(t *testing.T) {
	_, err := signMessage(staticSigner{}, []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent signing key type")
}

func TestSignProof_SigningFailurePropagates(t *testing.T) {
	material := &agentMaterial{
		signer:         staticSigner{},
		certificatePEM: []byte("cert"),
		agentCode:      "kite-agent-1",
	}
	_, err := signProof(material, "heartbeat", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent signing key type")
}

// -------------------------------------------------------------------------
// postAgentRequest
// -------------------------------------------------------------------------

func TestPostAgentRequest_ErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("marshal failure", func(t *testing.T) {
		c := NewClient(nil)
		err := c.postAgentRequest(ctx, "http://127.0.0.1:0", make(chan int), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "marshal agent request")
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		c := NewClient(nil)
		err := c.postAgentRequest(ctx, ":", map[string]string{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create agent request")
	})

	t.Run("transport failure", func(t *testing.T) {
		c := NewClient(nil)
		c.http = &stubDoer{err: errors.New("dial tcp: connection refused")}
		err := c.postAgentRequest(ctx, "https://pki.invalid/pki/x", map[string]string{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send agent request")
		assert.Contains(t, err.Error(), "connection refused")
	})

	t.Run("body read failure", func(t *testing.T) {
		c := NewClient(nil)
		c.http = &stubDoer{resp: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(errReader{}),
		}}
		err := c.postAgentRequest(ctx, "https://pki.invalid/pki/x", map[string]string{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read agent response")
	})

	t.Run("non-2xx status", func(t *testing.T) {
		c := NewClient(nil)
		c.http = &stubDoer{resp: &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Body:       io.NopCloser(bytes.NewReader([]byte("backend down"))),
		}}
		err := c.postAgentRequest(ctx, "https://pki.invalid/pki/x", map[string]string{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKI returned 502 Bad Gateway: backend down")
	})

	t.Run("decode failure", func(t *testing.T) {
		c := NewClient(nil)
		c.http = &stubDoer{resp: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(bytes.NewReader([]byte("{"))),
		}}
		var out map[string]string
		err := c.postAgentRequest(ctx, "https://pki.invalid/pki/x", map[string]string{}, &out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode agent response")
	})
}

func TestPostAgentRequest_NilDoerFallsBackToDefaultClient(t *testing.T) {
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{} // zero value: nil logger, nil http
	var out struct {
		Status string `json:"status"`
	}
	require.NoError(t, c.postAgentRequest(context.Background(), srv.URL, map[string]string{"k": "v"}, &out))
	assert.Equal(t, "ok", out.Status)
	assert.Equal(t, "application/json", gotContentType)
}

// -------------------------------------------------------------------------
// HeartbeatHTTPS
// -------------------------------------------------------------------------

func TestHeartbeatHTTPS_NotEnrolledFails(t *testing.T) {
	client := NewClient(nil)
	client.http = &callbackDoer{do: func(*http.Request) (*http.Response, error) {
		t.Fatal("no request must leave the agent without credentials")
		return nil, nil
	}}
	err := client.HeartbeatHTTPS(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read agent certificate")
}

func TestHeartbeatHTTPS_ServerRejectionSurfaces(t *testing.T) {
	dir, _ := writeAgentMaterial(t)
	client := NewClient(nil)
	client.http = &stubDoer{resp: &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       io.NopCloser(bytes.NewReader([]byte("revoked"))),
	}}
	err := client.HeartbeatHTTPS(context.Background(), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKI returned 403 Forbidden: revoked")
}

// -------------------------------------------------------------------------
// generateRenewalCSR
// -------------------------------------------------------------------------

func TestGenerateRenewalCSR_SigningFailure(t *testing.T) {
	key := newECDSAKey(t)
	material := &agentMaterial{
		agentCode:   "kite-agent-1",
		certificate: &x509.Certificate{Subject: pkix.Name{Organization: []string{"org-a"}}},
		signer:      staticSigner{pub: &key.PublicKey},
	}
	_, err := generateRenewalCSR(material)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create renewal CSR")
}

// -------------------------------------------------------------------------
// RenewHTTPS error paths
// -------------------------------------------------------------------------

func TestRenewHTTPS_NotEnrolledFails(t *testing.T) {
	client := NewClient(nil)
	client.http = &callbackDoer{do: func(*http.Request) (*http.Response, error) {
		t.Fatal("no request must leave the agent without credentials")
		return nil, nil
	}}
	err := client.RenewHTTPS(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read agent certificate")
}

func TestRenewHTTPS_IncompleteResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "status not renewed", body: `{"status":"pending"}`},
		{
			name: "missing client certificate",
			body: `{"status":"renewed","ca_certificate":"ca"}`,
		},
		{
			name: "missing CA certificate",
			body: `{"status":"renewed","client_certificate":"cert"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, _ := writeAgentMaterial(t)
			client := NewClient(nil)
			client.http = &stubDoer{resp: &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}}
			err := client.RenewHTTPS(context.Background(), dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "incomplete renewal response")
		})
	}
}

func renewingDoer(t *testing.T) *callbackDoer {
	t.Helper()
	return &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		var payload agentRenewRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Body: io.NopCloser(assertReader(
				renewedCertificateResponse(t, payload.CSRPEM, "org-a"),
			)),
		}, nil
	}}
}

func TestRenewHTTPS_UnwritableCertsDirFailsBeforeReplacing(t *testing.T) {
	dir, _ := writeAgentMaterial(t)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	client := NewClient(nil)
	client.http = renewingDoer(t)

	err := client.RenewHTTPS(context.Background(), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temporary credential")
}

func TestRenewHTTPS_CAWriteFailureSurfaces(t *testing.T) {
	dir, _ := writeAgentMaterial(t)
	// Replace ca.pem with a directory: agent.pem is written first, then the
	// rename over ca.pem must fail.
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.pem")))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "ca.pem"), 0o700))

	client := NewClient(nil)
	client.http = renewingDoer(t)

	err := client.RenewHTTPS(context.Background(), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace credential")
}

// -------------------------------------------------------------------------
// validateRenewalResponse
// -------------------------------------------------------------------------

// newRenewalMaterialFixture builds a CA plus a helper minting agent leaf
// certificates (CN kite-agent-1, org-a, ClientAuth) for the same agent key,
// so replacement-vs-echo and lifetime rules can be exercised directly.
func newRenewalMaterialFixture(t *testing.T) (*agentMaterial, string, func(serial int64, notAfter time.Time) string) {
	t.Helper()
	now := time.Now()
	caKey := newECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fixture CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	agentKey := newECDSAKey(t)
	issueLeaf := func(serial int64, notAfter time.Time) string {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{
				CommonName:   "kite-agent-1",
				Organization: []string{"org-a"},
			},
			NotBefore:   now.Add(-time.Minute),
			NotAfter:    notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, issueErr := x509.CreateCertificate(rand.Reader, template, caCert, &agentKey.PublicKey, caKey)
		require.NoError(t, issueErr)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	currentPEM := issueLeaf(10, now.Add(90*24*time.Hour))
	block, _ := pem.Decode([]byte(currentPEM))
	require.NotNil(t, block)
	current, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return &agentMaterial{
		signer:         agentKey,
		certificate:    current,
		certificatePEM: []byte(currentPEM),
		agentCode:      "kite-agent-1",
	}, caPEM, issueLeaf
}

func TestValidateRenewalResponse_RejectsEchoedCurrentCertificate(t *testing.T) {
	material, caPEM, _ := newRenewalMaterialFixture(t)
	err := validateRenewalResponse(material, renewHTTPResponse{
		Status:            "renewed",
		CACertificate:     caPEM,
		ClientCertificate: string(material.certificatePEM),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "current certificate instead of a replacement")
}

func TestValidateRenewalResponse_RejectsNonExtendingLifetime(t *testing.T) {
	material, caPEM, issueLeaf := newRenewalMaterialFixture(t)
	for _, notAfter := range []time.Time{
		material.certificate.NotAfter.Add(-30 * 24 * time.Hour), // shorter
		material.certificate.NotAfter,                           // equal (boundary)
	} {
		err := validateRenewalResponse(material, renewHTTPResponse{
			Status:            "renewed",
			CACertificate:     caPEM,
			ClientCertificate: issueLeaf(11, notAfter),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not extend certificate lifetime")
	}
}

func TestValidateRenewalResponse_AcceptsExtendedReplacement(t *testing.T) {
	material, caPEM, issueLeaf := newRenewalMaterialFixture(t)
	err := validateRenewalResponse(material, renewHTTPResponse{
		Status:            "renewed",
		CACertificate:     caPEM,
		ClientCertificate: issueLeaf(12, material.certificate.NotAfter.Add(24*time.Hour)),
	})
	require.NoError(t, err)
}

func TestValidateRenewalResponse_GarbageCertificateFails(t *testing.T) {
	material, caPEM, _ := newRenewalMaterialFixture(t)
	err := validateRenewalResponse(material, renewHTTPResponse{
		Status:            "renewed",
		CACertificate:     caPEM,
		ClientCertificate: "garbage",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response contains no client certificate")
}

// -------------------------------------------------------------------------
// atomicWrite
// -------------------------------------------------------------------------

func TestAtomicWrite_WritesContentModeAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.pem")

	require.NoError(t, atomicWrite(path, []byte("credential-bytes"), 0o640))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "credential-bytes", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "temp file must be renamed away, not left behind")
	assert.Equal(t, "cred.pem", entries[0].Name())
}

func TestAtomicWrite_ReadOnlyDirFails(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := atomicWrite(filepath.Join(dir, "cred.pem"), []byte("x"), 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temporary credential")
}

func TestAtomicWrite_TargetIsDirectoryFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cred.pem")
	require.NoError(t, os.Mkdir(target, 0o700))

	err := atomicWrite(target, []byte("x"), 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace credential")
}

// -------------------------------------------------------------------------
// RunHTTPSLifecycle — initial heartbeat + renewal check paths
// -------------------------------------------------------------------------

// writeAgentMaterialWithValidity is writeAgentMaterial with explicit
// certificate validity bounds, so the 2/3-lifetime renewal rule can be put
// on either side of its threshold.
func writeAgentMaterialWithValidity(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	dir := t.TempDir()
	key := newECDSAKey(t)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "kite-agent-1",
			Organization: []string{"org-a"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.pem"), certPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "agent-key.pem"), pkcs8KeyPEM(t, key), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o644))
	return dir
}

// lifecycleDoer answers heartbeats with 200 and renewals via renew, failing
// the test when renew is nil but a renewal request arrives anyway.
func lifecycleDoer(t *testing.T, renew func(req *http.Request) (*http.Response, error)) *callbackDoer {
	t.Helper()
	return &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case heartbeatURL:
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(assertReader(`{"status":"ok"}`)),
			}, nil
		case renewURL:
			if renew == nil {
				t.Error("renewal must not be attempted for a fresh certificate")
				return nil, errors.New("unexpected renewal")
			}
			return renew(req)
		default:
			t.Errorf("unexpected lifecycle request to %s", req.URL)
			return nil, errors.New("unexpected request")
		}
	}}
}

func runLifecycleOnce(t *testing.T, client *Client, certsDir string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // initial heartbeat + cert check still run; the loop exits at once

	done := make(chan struct{})
	go func() {
		client.RunHTTPSLifecycle(ctx, certsDir)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTPS lifecycle did not honor context cancellation")
	}
}

func TestRunHTTPSLifecycle_RenewsExpiringCertificate(t *testing.T) {
	now := time.Now()
	dir := writeAgentMaterialWithValidity(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	before, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)

	var buf bytes.Buffer
	client := NewClient(slog.New(slog.NewJSONHandler(&buf, nil)))
	client.http = lifecycleDoer(t, func(req *http.Request) (*http.Response, error) {
		var payload agentRenewRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Body: io.NopCloser(assertReader(
				renewedCertificateResponse(t, payload.CSRPEM, "org-a"),
			)),
		}, nil
	})

	runLifecycleOnce(t, client, dir)

	assert.Contains(t, buf.String(), `"code":"enrollment.https.renewal_completed"`)
	after, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	assert.NotEqual(t, string(before), string(after),
		"renewal must replace the on-disk agent certificate")
}

func TestRunHTTPSLifecycle_RenewalFailureIsLoggedNotFatal(t *testing.T) {
	now := time.Now()
	dir := writeAgentMaterialWithValidity(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))

	var buf bytes.Buffer
	client := NewClient(slog.New(slog.NewJSONHandler(&buf, nil)))
	client.http = lifecycleDoer(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Body:       io.NopCloser(assertReader(`{"error":"boom"}`)),
		}, nil
	})

	runLifecycleOnce(t, client, dir)
	assert.Contains(t, buf.String(), `"code":"enrollment.https.renewal_failed"`)
}

func TestRunHTTPSLifecycle_FreshCertificateSkipsRenewal(t *testing.T) {
	now := time.Now()
	dir := writeAgentMaterialWithValidity(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	var buf bytes.Buffer
	client := NewClient(slog.New(slog.NewJSONHandler(&buf, nil)))
	client.http = lifecycleDoer(t, nil) // renewal request would fail the test

	runLifecycleOnce(t, client, dir)
	assert.NotContains(t, buf.String(), "enrollment.https.renewal_failed")
	assert.NotContains(t, buf.String(), "enrollment.https.renewal_completed")
}

func TestRunHTTPSLifecycle_ZeroValueClientUsesDefaultLogger(t *testing.T) {
	now := time.Now()
	dir := writeAgentMaterialWithValidity(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	client := &Client{http: lifecycleDoer(t, nil)} // nil logger exercises the default
	runLifecycleOnce(t, client, dir)
}
