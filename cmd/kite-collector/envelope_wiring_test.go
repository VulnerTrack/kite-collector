package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/envelope"
	"github.com/vulnertrack/kite-collector/internal/identity"
)

// writeAgentPEMs mimics what `kite install` leaves under the certs dir.
func writeAgentPEMs(t *testing.T, dir string) (certFile, keyFile string, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-code-1", Organization: []string{"tenant-1"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "agent.pem")
	keyFile = filepath.Join(dir, "agent-key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile, leaf
}

func TestBuildOTLPSealer_PrefersClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, leaf := writeAgentPEMs(t, dir)
	id, err := identity.LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	otlp := config.OTLPConfig{
		TLS:        config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
		Encryption: config.EncryptionConfig{Enabled: true, ServerJWKURL: "https://otel.example.com/.well-known/jwks.json"},
	}
	sealer, err := buildOTLPSealer(otlp, id)
	require.NoError(t, err)
	assert.True(t, sealer.SignsWithCertificate(), "cert wins over identity key when both exist")
	assert.Equal(t, envelope.CertificateKeyID(leaf), sealer.SignerKeyID())
	assert.Equal(t, "ES256", sealer.Algorithm())
}

func TestBuildOTLPSealer_FallsBackToIdentityKey(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	otlp := config.OTLPConfig{
		Encryption: config.EncryptionConfig{Enabled: true, ServerJWKURL: "https://otel.example.com/.well-known/jwks.json"},
	}
	sealer, err := buildOTLPSealer(otlp, id)
	require.NoError(t, err)
	assert.False(t, sealer.SignsWithCertificate())
	assert.Equal(t, id.AgentID.String(), sealer.SignerKeyID(), "receiver looks the key up by agent id")
	assert.Equal(t, "EdDSA", sealer.Algorithm())
}

func TestBuildOTLPSealer_FailsClosed(t *testing.T) {
	otlp := config.OTLPConfig{
		Encryption: config.EncryptionConfig{Enabled: true, ServerJWKURL: "https://otel.example.com/.well-known/jwks.json"},
	}
	_, err := buildOTLPSealer(otlp, nil)
	require.Error(t, err, "no cert and no identity: refuse rather than send plaintext")

	// A configured but unreadable certificate is an error too — never fall
	// through to the identity key when the operator pointed at a cert.
	otlp.TLS = config.TLSConfig{Enabled: true, CertFile: "/nonexistent/agent.pem", KeyFile: "/nonexistent/agent-key.pem"}
	dir := t.TempDir()
	id, err := identity.LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	_, err = buildOTLPSealer(otlp, id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client certificate")
}

func TestBuildOTLPSigner_SignsWithClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, leaf := writeAgentPEMs(t, dir)
	id, err := identity.LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	otlp := config.OTLPConfig{
		TLS:     config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
		Signing: config.SigningConfig{Enabled: true},
	}
	signer, err := buildOTLPSigner(otlp, id)
	require.NoError(t, err)
	assert.True(t, signer.SignsWithCertificate(), "the enrolled cert is the signing credential")
	assert.Equal(t, envelope.CertificateKeyID(leaf), signer.SignerKeyID())
	assert.Equal(t, "ES256", signer.Algorithm())

	// Sign-only: it must not be able to produce an envelope, because no
	// receiver key was configured.
	body := []byte(`{"resourceLogs":[]}`)
	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)
	opened, err := envelope.VerifyDetached(sig.Compact, body, nil)
	require.NoError(t, err)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, leaf.Raw, opened.Certificates[0].Raw)

	_, err = signer.Seal(t.Context(), body, "application/json")
	require.Error(t, err)
}

func TestBuildOTLPSigner_OmitCertificateChain(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, leaf := writeAgentPEMs(t, dir)

	signer, err := buildOTLPSigner(config.OTLPConfig{
		TLS:     config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
		Signing: config.SigningConfig{Enabled: true, OmitCertificateChain: true},
	}, nil)
	require.NoError(t, err)
	assert.False(t, signer.SignsWithCertificate(), "no x5c travels")
	assert.Equal(t, envelope.CertificateKeyID(leaf), signer.SignerKeyID(),
		"kid still names the certificate the receiver should look up")

	body := []byte(`{"resourceLogs":[]}`)
	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)
	_, err = envelope.VerifyDetached(sig.Compact, body, leaf.PublicKey)
	require.NoError(t, err, "a receiver holding the cert verifies without the chain")
}

func TestBuildOTLPSigner_FallsBackToIdentityKey(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	signer, err := buildOTLPSigner(config.OTLPConfig{Signing: config.SigningConfig{Enabled: true}}, id)
	require.NoError(t, err)
	assert.False(t, signer.SignsWithCertificate())
	assert.Equal(t, id.AgentID.String(), signer.SignerKeyID())
	assert.Equal(t, "EdDSA", signer.Algorithm())
}

// Signing that cannot find a credential must stop the agent, not degrade
// to unsigned telemetry.
func TestBuildOTLPSigner_NoCredentialFailsLoudly(t *testing.T) {
	_, err := buildOTLPSigner(config.OTLPConfig{Signing: config.SigningConfig{Enabled: true}}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "streaming.otlp.signing")
}

// A half-rotated certs directory must fail at start-up rather than
// produce signatures nobody can verify.
func TestBuildOTLPSigner_RejectsMismatchedCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certFile, _, _ := writeAgentPEMs(t, dir)
	other := t.TempDir()
	_, otherKey, _ := writeAgentPEMs(t, other)

	_, err := buildOTLPSigner(config.OTLPConfig{
		TLS:     config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: otherKey},
		Signing: config.SigningConfig{Enabled: true},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not match")
}
