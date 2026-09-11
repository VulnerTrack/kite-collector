package envelope

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certSigner is the production shape: a sign-only sealer holding the
// enrolled client certificate and its key.
func certSigner(t *testing.T, opts ...Option) (*Sealer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := selfSignedCert(t, key, "agent-code-1")
	s, err := NewSigner(SigningKey{Key: key, Certificates: []*x509.Certificate{leaf}}, opts...)
	require.NoError(t, err)
	return s, leaf
}

func TestSignDetached_RoundTripAgainstCertificate(t *testing.T) {
	signer, leaf := certSigner(t)
	body := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"machine.discovered"}}]}]}]}`)

	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)

	assert.Equal(t, "ES256", sig.Algorithm)
	assert.Equal(t, CertificateKeyID(leaf), sig.SignerKeyID, "kid is the cert fingerprint the PKI already shows")
	assert.NotEmpty(t, sig.Nonce)
	assert.WithinDuration(t, time.Now(), sig.IssuedAt, time.Minute)

	// Detached serialization: three segments, middle one empty, because
	// the payload travels as the untouched HTTP body.
	parts := strings.Split(sig.Compact, ".")
	require.Len(t, parts, 3)
	assert.Empty(t, parts[1], "payload segment must be detached, not duplicated into the header")

	opened, err := VerifyDetached(sig.Compact, body, leaf.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, body, opened.Payload)
	assert.Equal(t, "application/json", opened.ContentType)
	assert.Equal(t, CertificateKeyID(leaf), opened.SignerKeyID)
	assert.Equal(t, sig.Nonce, opened.Nonce)
	assert.Equal(t, sig.IssuedAt, opened.IssuedAt)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, leaf.Raw, opened.Certificates[0].Raw, "x5c lets the receiver verify without a key registry")
}

func TestVerifyDetached_WithoutKeyUsesEmbeddedChain(t *testing.T) {
	signer, leaf := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)

	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)

	opened, err := VerifyDetached(sig.Compact, body, nil)
	require.NoError(t, err)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, leaf.Raw, opened.Certificates[0].Raw)
}

// The whole point of integrity: one changed byte in the body must not
// verify, even though the signature itself is untouched.
func TestVerifyDetached_TamperedBodyFails(t *testing.T) {
	signer, leaf := certSigner(t)
	body := []byte(`{"severityNumber":9,"body":{"stringValue":"unauthorized.machine"}}`)

	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)

	tampered := []byte(`{"severityNumber":1,"body":{"stringValue":"unauthorized.machine"}}`)
	_, err = VerifyDetached(sig.Compact, tampered, leaf.PublicKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify")
}

// Authenticity: a signature from some other key must not verify as this
// agent, even over an untouched body.
func TestVerifyDetached_ForeignSignerFails(t *testing.T) {
	signer, _ := certSigner(t)
	_, otherLeaf := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)

	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)

	_, err = VerifyDetached(sig.Compact, body, otherLeaf.PublicKey)
	require.Error(t, err)
}

func TestVerifyDetached_TruncatedSignatureFails(t *testing.T) {
	signer, leaf := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)
	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)

	for name, bad := range map[string]string{
		"empty":          "",
		"no dots":        "not-a-jws",
		"dropped sig":    sig.Compact[:strings.LastIndexByte(sig.Compact, '.')],
		"flipped sig":    sig.Compact[:len(sig.Compact)-2] + "AA",
		"header garbage": "!!!.." + strings.Split(sig.Compact, ".")[2],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyDetached(bad, body, leaf.PublicKey)
			assert.Error(t, err)
		})
	}
}

func TestSignDetached_IdentityKeyHasNoChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := SigningKeyFromEd25519(priv, "0199f0c2-0000-7000-8000-000000000001")
	require.NoError(t, err)
	signer, err := NewSigner(key)
	require.NoError(t, err)

	body := []byte(`{"resourceLogs":[]}`)
	sig, err := signer.SignDetached(body, "application/json")
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", sig.Algorithm)
	assert.Equal(t, "0199f0c2-0000-7000-8000-000000000001", sig.SignerKeyID)

	opened, err := VerifyDetached(sig.Compact, body, pub)
	require.NoError(t, err)
	assert.Empty(t, opened.Certificates)

	// Without a chain there is nothing to fall back to: the receiver must
	// already know this agent's key.
	_, err = VerifyDetached(sig.Compact, body, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no x5c chain")
}

func TestSignDetached_OmitCertificateChainShrinksSignature(t *testing.T) {
	full, leaf := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)
	withChain, err := full.SignDetached(body, "application/json")
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	lean, err := NewSigner(
		SigningKey{Key: key, Certificates: []*x509.Certificate{selfSignedCert(t, key, "agent-code-1")}},
		WithoutCertificateChain(),
	)
	require.NoError(t, err)
	withoutChain, err := lean.SignDetached(body, "application/json")
	require.NoError(t, err)

	assert.Less(t, len(withoutChain.Compact), len(withChain.Compact))
	assert.NotEmpty(t, withoutChain.SignerKeyID, "kid still identifies the certificate")

	// x5t#S256 survives so a receiver holding the cert can still find it.
	hdr := decodeProtected(t, withoutChain.Compact)
	assert.Empty(t, hdr["x5c"])
	assert.NotEmpty(t, hdr["x5t#S256"])

	assert.NotEmpty(t, decodeProtected(t, withChain.Compact)["x5c"])
	assert.Equal(t, CertificateKeyID(leaf), withChain.SignerKeyID)
}

// A signature has to fit in an HTTP header line; proxies cap those.
func TestSignDetached_FitsInHeaderBudget(t *testing.T) {
	signer, _ := certSigner(t)
	sig, err := signer.SignDetached(make([]byte, 1<<20), "application/json")
	require.NoError(t, err)
	assert.Less(t, len(sig.Compact), maxSignatureHeaderBytes,
		"signature size is independent of body size; only the chain drives it")
}

// Replay defence depends on the nonce actually being fresh per signature.
func TestSignDetached_NonceIsUniquePerSignature(t *testing.T) {
	signer, _ := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)

	seen := make(map[string]bool, 64)
	for range 64 {
		sig, err := signer.SignDetached(body, "application/json")
		require.NoError(t, err)
		require.False(t, seen[sig.Nonce], "nonce %q reused", sig.Nonce)
		seen[sig.Nonce] = true
	}
}

// A sign-only sealer must fail loudly rather than pretend to encrypt.
func TestSigner_CannotSeal(t *testing.T) {
	signer, _ := certSigner(t)
	_, err := signer.Seal(t.Context(), []byte("x"), "application/json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign but not encrypt")
}

// The enveloped path stamps the same freshness claims, so a receiver can
// apply one replay policy to both modes.
func TestSeal_CarriesFreshnessClaims(t *testing.T) {
	recv := newReceiver(t, "otel-gw-1")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := selfSignedCert(t, key, "agent-code-1")
	sealer, err := NewSealer(SigningKey{Key: key, Certificates: []*x509.Certificate{leaf}}, StaticKey(recv.public))
	require.NoError(t, err)

	sealed, err := sealer.Seal(t.Context(), []byte(`{"resourceLogs":[]}`), "application/json")
	require.NoError(t, err)

	opened, err := Open(sealed.Compact, recv.private, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, opened.Nonce)
	assert.WithinDuration(t, time.Now(), opened.IssuedAt, time.Minute)
}

func decodeProtected(t *testing.T, compact string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[0])
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(raw, &hdr))
	return hdr
}
