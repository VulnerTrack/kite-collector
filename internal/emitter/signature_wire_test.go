package emitter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/envelope"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// certSigner builds the sign-only credential production gets from
// agent.pem / agent-key.pem: no receiver key, so bodies are signed but
// never encrypted.
func certSigner(t *testing.T, opts ...envelope.Option) (*envelope.Sealer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "agent-code-42", Organization: []string{"tenant-7"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	s, err := envelope.NewSigner(envelope.SigningKey{Key: key, Certificates: []*x509.Certificate{leaf}}, opts...)
	require.NoError(t, err)
	return s, leaf
}

// The defining property of the signed mode: the body a stock OTLP
// receiver parses is byte-for-byte what it would have received unsigned,
// and the signature covers exactly those bytes.
func TestOTLPEmitter_Signed_BodyStaysPlainOTLPJSON(t *testing.T) {
	signer, leaf := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached}, "1.2.3")
	require.NoError(t, err)
	assert.False(t, em.Sealed(), "signed is not encrypted")
	assert.True(t, em.Signed())
	assert.Equal(t, ProtectionDetached, em.Protection())

	evt := makeEvent(t, model.EventMachineDiscovered, model.SeverityMedium)
	require.NoError(t, em.EmitBatch(context.Background(), []model.MachineEvent{evt}))

	reqs := captured()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, "/v1/logs", got.Path)
	assert.Equal(t, ContentTypeJSON, got.ContentType, "a stock OTLP receiver must still accept this")
	assert.Equal(t, envelope.CertificateKeyID(leaf), got.Signer)
	require.NotEmpty(t, got.Signature)

	var payload otlpLogsPayload
	require.NoError(t, json.Unmarshal(got.Body, &payload), "body is ordinary OTLP/JSON")
	require.Len(t, payload.ResourceLogs, 1)

	// The receiving half: verify against the embedded chain, exactly as a
	// gateway holding only the PKI CA would.
	opened, err := envelope.VerifyDetached(got.Signature, got.Body, nil)
	require.NoError(t, err)
	assert.Equal(t, ContentTypeJSON, opened.ContentType)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, "agent-code-42", opened.Certificates[0].Subject.CommonName)
	assert.Equal(t, []string{"tenant-7"}, opened.Certificates[0].Subject.Organization,
		"tenant stays server-authoritative: it is read off the verified cert, never off the body")
	assert.NotEmpty(t, opened.Nonce)
	assert.WithinDuration(t, time.Now(), opened.IssuedAt, time.Minute)
}

// Integrity end to end: a proxy that rewrites one attribute in the body
// breaks verification, even though it never touched the header.
func TestOTLPEmitter_Signed_TamperedBodyFailsVerification(t *testing.T) {
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached}, "1.2.3")
	require.NoError(t, err)
	require.NoError(t, em.EmitBatch(context.Background(),
		[]model.MachineEvent{makeEvent(t, model.EventUnauthorizedMachineDetected, model.SeverityCritical)}))

	got := captured()[0]
	_, err = envelope.VerifyDetached(got.Signature, got.Body, nil)
	require.NoError(t, err, "untouched body verifies")

	tampered := append([]byte(nil), got.Body...)
	tampered[len(tampered)/2] ^= 0x01
	_, err = envelope.VerifyDetached(got.Signature, tampered, nil)
	require.Error(t, err, "one flipped byte must not verify")
}

func TestOTLPEmitter_Signed_RetriesResendTheSameSignature(t *testing.T) {
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusServiceUnavailable)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached}, "1.2.3")
	require.NoError(t, err)
	em.retry = retryConfig{maxAttempts: 3, baseDelay: time.Millisecond, maxDelay: time.Millisecond}

	err = em.EmitBatch(context.Background(), []model.MachineEvent{makeEvent(t, model.EventMachineRemoved, model.SeverityHigh)})
	require.Error(t, err)

	reqs := captured()
	require.Len(t, reqs, 3)
	for _, r := range reqs[1:] {
		assert.Equal(t, reqs[0].Body, r.Body)
		assert.Equal(t, reqs[0].Signature, r.Signature,
			"the batch is signed once; a retry is the same bytes, not a fresh nonce")
	}
}

func TestOTLPMetricsEmitter_Signed(t *testing.T) {
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	me, err := NewOTLPMetrics(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached})
	require.NoError(t, err)
	require.NoError(t, me.EmitBatch(context.Background(), sampleBatch()))

	reqs := captured()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/v1/metrics", reqs[0].Path)
	assert.Equal(t, ContentTypeJSON, reqs[0].ContentType)
	assert.Contains(t, string(reqs[0].Body), "resourceMetrics")

	opened, err := envelope.VerifyDetached(reqs[0].Signature, reqs[0].Body, nil)
	require.NoError(t, err)
	assert.Equal(t, reqs[0].Body, opened.Payload)
}

func TestAggregateEmitter_SignedFlush(t *testing.T) {
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	inner, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached}, "1.2.3")
	require.NoError(t, err)
	agg := NewAggregate(inner)
	require.NoError(t, agg.Emit(context.Background(), makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)))
	require.NoError(t, agg.Flush(context.Background()))

	reqs := captured()
	require.Len(t, reqs, 1)
	assert.Equal(t, ContentTypeJSON, reqs[0].ContentType)
	_, err = envelope.VerifyDetached(reqs[0].Signature, reqs[0].Body, nil)
	require.NoError(t, err, "the scan-summary aggregate is signed like any other batch")
}

// Every batch gets its own nonce, so a receiver caching nonces can tell a
// replayed batch from a new one.
func TestOTLPEmitter_Signed_EachBatchGetsAFreshNonce(t *testing.T) {
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionDetached}, "1.2.3")
	require.NoError(t, err)
	evt := makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)
	require.NoError(t, em.EmitBatch(context.Background(), []model.MachineEvent{evt}))
	require.NoError(t, em.EmitBatch(context.Background(), []model.MachineEvent{evt}))

	reqs := captured()
	require.Len(t, reqs, 2)
	first, err := envelope.VerifyDetached(reqs[0].Signature, reqs[0].Body, nil)
	require.NoError(t, err)
	second, err := envelope.VerifyDetached(reqs[1].Signature, reqs[1].Body, nil)
	require.NoError(t, err)
	assert.NotEqual(t, first.Nonce, second.Nonce)
}

func TestPrepareWire_Modes(t *testing.T) {
	signer, _ := certSigner(t)
	body := []byte(`{"resourceLogs":[]}`)

	t.Run("none leaves the body alone", func(t *testing.T) {
		w, err := prepareWire(context.Background(), signer, ProtectionNone, body)
		require.NoError(t, err)
		assert.Equal(t, body, w.body)
		assert.Equal(t, ContentTypeJSON, w.contentType)
		assert.Empty(t, w.headers)
	})

	t.Run("nil sealer leaves the body alone", func(t *testing.T) {
		w, err := prepareWire(context.Background(), nil, ProtectionDetached, body)
		require.NoError(t, err)
		assert.Equal(t, body, w.body)
		assert.Empty(t, w.headers)
	})

	t.Run("unknown mode is refused, not guessed", func(t *testing.T) {
		_, err := prepareWire(context.Background(), signer, ProtectionMode("armored"), body)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "armored")
	})

	// A sign-only credential cannot seal; asking it to must fail loudly
	// rather than fall back to sending plaintext.
	t.Run("envelope mode with a sign-only key fails closed", func(t *testing.T) {
		_, err := prepareWire(context.Background(), signer, ProtectionEnvelope, body)
		require.Error(t, err)
	})
}

func TestOTLPEmitter_SignFailure_IsReportedNotSent(t *testing.T) {
	// A chain too large for the header budget is the one signing failure
	// that does not need a broken key: the batch must not go out unsigned.
	signer, _ := certSigner(t)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: signer, Protection: ProtectionMode("bogus")}, "1.2.3")
	require.NoError(t, err)
	err = em.EmitBatch(context.Background(), []model.MachineEvent{makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)})
	require.Error(t, err)
	assert.Empty(t, captured(), "nothing leaves the process unprotected when protection fails")
}
