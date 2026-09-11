package envelope

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// receiverKeys is a server-side ECDH keypair in both JWK shapes.
type receiverKeys struct {
	public  jose.JSONWebKey
	private jose.JSONWebKey
}

func newReceiver(t *testing.T, kid string) receiverKeys {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return receiverKeys{
		public:  jose.JSONWebKey{Key: k.Public(), KeyID: kid, Algorithm: string(KeyAlgorithm), Use: "enc"},
		private: jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: string(KeyAlgorithm), Use: "enc"},
	}
}

// selfSignedCert issues a self-signed leaf for signer so tests can exercise
// the x5c path without a CA.
func selfSignedCert(t *testing.T, signer crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"tenant-1"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestSealer_CertificateSigned_ES256_RoundTrip(t *testing.T) {
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := selfSignedCert(t, agentKey, "agent-abc")
	recv := newReceiver(t, "server-2026-09")

	sealer, err := NewSealer(SigningKey{Key: agentKey, Certificates: []*x509.Certificate{leaf}}, StaticKey(recv.public))
	require.NoError(t, err)
	assert.Equal(t, "ES256", sealer.Algorithm())
	assert.True(t, sealer.SignsWithCertificate())
	assert.Equal(t, CertificateKeyID(leaf), sealer.SignerKeyID(), "kid defaults to the leaf fingerprint")

	plaintext := []byte(`{"resourceLogs":[]}`)
	sealed, err := sealer.Seal(context.Background(), plaintext, "application/json")
	require.NoError(t, err)
	assert.Equal(t, "server-2026-09", sealed.KeyID)
	assert.Equal(t, CertificateKeyID(leaf), sealed.SignerKeyID)
	assert.Equal(t, "ES256", sealed.Algorithm)
	assert.Equal(t, 4, countDots(sealed.Compact), "compact JWE has five segments")

	// Receiver path 1: verify with the key it already trusts.
	opened, err := Open(sealed.Compact, recv.private, agentKey.Public())
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened.Payload)
	assert.Equal(t, "application/json", opened.ContentType)
	assert.Equal(t, CertificateKeyID(leaf), opened.SignerKeyID)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, leaf.Raw, opened.Certificates[0].Raw, "x5c carries the leaf DER verbatim")
	assert.Equal(t, "agent-abc", opened.Certificates[0].Subject.CommonName)

	// Receiver path 2: no pre-registered key — verify against the x5c leaf.
	opened, err = Open(sealed.Compact, recv.private, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened.Payload)
}

func TestSealer_IdentityKey_EdDSA_NoX5c(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	recv := newReceiver(t, "k1")

	key, err := SigningKeyFromEd25519(priv, "018f9c2a-7b3d-7a01-8c2e-0123456789ab")
	require.NoError(t, err)
	sealer, err := NewSealer(key, StaticKey(recv.public))
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", sealer.Algorithm())
	assert.False(t, sealer.SignsWithCertificate())

	sealed, err := sealer.Seal(context.Background(), []byte("hello"), "")
	require.NoError(t, err)

	opened, err := Open(sealed.Compact, recv.private, pub)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), opened.Payload)
	assert.Equal(t, "018f9c2a-7b3d-7a01-8c2e-0123456789ab", opened.SignerKeyID)
	assert.Empty(t, opened.ContentType)
	assert.Nil(t, opened.Certificates)

	// Without x5c there is nothing to fall back to.
	_, err = Open(sealed.Compact, recv.private, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no x5c chain")
}

func TestSealer_RejectsMismatchedVerificationKey(t *testing.T) {
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := selfSignedCert(t, agentKey, "agent")
	recv := newReceiver(t, "k1")
	sealer, err := NewSealer(SigningKey{Key: agentKey, Certificates: []*x509.Certificate{leaf}}, StaticKey(recv.public))
	require.NoError(t, err)
	sealed, err := sealer.Seal(context.Background(), []byte("x"), "")
	require.NoError(t, err)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = Open(sealed.Compact, recv.private, other.Public())
	assert.Error(t, err)
}

func TestSealer_TamperedCiphertextFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	recv := newReceiver(t, "k1")
	sealer, err := NewSealer(SigningKey{Key: priv, KeyID: "a"}, StaticKey(recv.public))
	require.NoError(t, err)
	sealed, err := sealer.Seal(context.Background(), []byte("payload"), "")
	require.NoError(t, err)

	// Flip a byte inside the ciphertext segment (4th of 5).
	b := []byte(sealed.Compact)
	dots := 0
	for i, c := range b {
		if c == '.' {
			dots++
			continue
		}
		if dots == 3 {
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			break
		}
	}
	_, err = Open(string(b), recv.private, priv.Public())
	assert.Error(t, err)
}

func TestSealer_AlgorithmByKeyType(t *testing.T) {
	recv := newReceiver(t, "k1")

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	s, err := NewSealer(SigningKey{Key: p384, KeyID: "p384"}, StaticKey(recv.public))
	require.NoError(t, err)
	assert.Equal(t, "ES384", s.Algorithm())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s, err = NewSealer(SigningKey{Key: rsaKey, KeyID: "rsa"}, StaticKey(recv.public))
	require.NoError(t, err)
	assert.Equal(t, "RS256", s.Algorithm())
	sealed, err := s.Seal(context.Background(), []byte("r"), "")
	require.NoError(t, err)
	opened, err := Open(sealed.Compact, recv.private, rsaKey.Public())
	require.NoError(t, err)
	assert.Equal(t, []byte("r"), opened.Payload)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, err = NewSealer(SigningKey{Key: weakRSA, KeyID: "weak"}, StaticKey(recv.public))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")

	_, err = NewSealer(SigningKey{}, StaticKey(recv.public))
	assert.Error(t, err, "nil key rejected")
	_, err = NewSealer(SigningKey{Key: p384, KeyID: "x"}, nil)
	assert.Error(t, err, "nil provider rejected")
}

func TestSealer_ProviderErrorPropagates(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	boom := errors.New("jwks down")
	sealer, err := NewSealer(SigningKey{Key: priv, KeyID: "a"}, providerFunc(func(context.Context) (jose.JSONWebKey, error) {
		return jose.JSONWebKey{}, boom
	}))
	require.NoError(t, err)
	_, err = sealer.Seal(context.Background(), []byte("x"), "")
	require.ErrorIs(t, err, boom)
}

func TestSealer_RefusesPrivateReceiverKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	recv := newReceiver(t, "k1")
	sealer, err := NewSealer(SigningKey{Key: priv, KeyID: "a"}, StaticKey(recv.private))
	require.NoError(t, err)
	_, err = sealer.Seal(context.Background(), []byte("x"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a public key")

	_, err = sealer.SealWithKey([]byte("x"), "", jose.JSONWebKey{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoadSigningKey_FromEnrollmentPEMs(t *testing.T) {
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := selfSignedCert(t, agentKey, "agent-code-1")

	keyDER, err := x509.MarshalPKCS8PrivateKey(agentKey)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "agent.pem")
	keyFile := filepath.Join(dir, "agent-key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	key, err := LoadSigningKey(certFile, keyFile)
	require.NoError(t, err)
	assert.Equal(t, CertificateKeyID(leaf), key.KeyID)
	require.Len(t, key.Certificates, 1)
	assert.Equal(t, "agent-code-1", key.Certificates[0].Subject.CommonName)

	// SEC 1 "EC PRIVATE KEY" encoding is accepted too.
	ecDER, err := x509.MarshalECPrivateKey(agentKey)
	require.NoError(t, err)
	_, err = SigningKeyFromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
	)
	require.NoError(t, err)

	// Mismatched pair is refused.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	require.NoError(t, err)
	_, err = SigningKeyFromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not match")

	// Missing files surface the path.
	_, err = LoadSigningKey(filepath.Join(dir, "nope.pem"), keyFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nope.pem")
}

func TestSigningKeyFromEd25519_Validation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = SigningKeyFromEd25519(priv[:10], "id")
	assert.Error(t, err)
	_, err = SigningKeyFromEd25519(priv, "")
	assert.Error(t, err)
}

type providerFunc func(context.Context) (jose.JSONWebKey, error)

func (f providerFunc) GetEncryptionKey(ctx context.Context) (jose.JSONWebKey, error) { return f(ctx) }
