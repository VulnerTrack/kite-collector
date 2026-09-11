package emitter

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/envelope"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// sealedRequest is one captured POST with the headers the envelope adds.
type sealedRequest struct {
	Path        string
	ContentType string
	KeyID       string
	Signer      string
	Signature   string
	Body        []byte
}

func startSealedCaptureServer(t *testing.T, status int) (string, func() []sealedRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		captured []sealedRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		captured = append(captured, sealedRequest{
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			KeyID:       r.Header.Get(HeaderEnvelopeKeyID),
			Signer:      r.Header.Get(HeaderEnvelopeSigner),
			Signature:   r.Header.Get(HeaderEnvelopeSignature),
			Body:        body,
		})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []sealedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]sealedRequest(nil), captured...)
	}
}

// receiver is the platform side of the envelope: an ECDH keypair whose
// public half the agent fetches and whose private half opens envelopes.
type receiver struct {
	public  jose.JSONWebKey
	private jose.JSONWebKey
}

func newReceiver(t *testing.T) receiver {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return receiver{
		public:  jose.JSONWebKey{Key: k.Public(), KeyID: "otel-gw-2026-09", Algorithm: string(envelope.KeyAlgorithm), Use: "enc"},
		private: jose.JSONWebKey{Key: k, KeyID: "otel-gw-2026-09", Algorithm: string(envelope.KeyAlgorithm), Use: "enc"},
	}
}

// certSealer builds a sealer signing with a self-signed client certificate,
// the shape production gets from agent.pem / agent-key.pem.
func certSealer(t *testing.T, recv receiver) (*envelope.Sealer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "agent-code-42", Organization: []string{"tenant-7"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	s, err := envelope.NewSealer(envelope.SigningKey{Key: key, Certificates: []*x509.Certificate{leaf}}, envelope.StaticKey(recv.public))
	require.NoError(t, err)
	return s, leaf
}

func TestOTLPEmitter_SealedBatch_IsJOSEAndOpensToOTLPJSON(t *testing.T) {
	recv := newReceiver(t)
	sealer, leaf := certSealer(t, recv)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: sealer}, "1.2.3")
	require.NoError(t, err)
	assert.True(t, em.Sealed())

	evt := makeEvent(t, model.EventMachineDiscovered, model.SeverityMedium)
	require.NoError(t, em.EmitBatch(context.Background(), []model.MachineEvent{evt}))

	reqs := captured()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, "/v1/logs", got.Path)
	assert.Equal(t, ContentTypeJOSE, got.ContentType)
	assert.Equal(t, "otel-gw-2026-09", got.KeyID, "receiver kid travels as a routing header")
	assert.Equal(t, envelope.CertificateKeyID(leaf), got.Signer, "signer header is the cert fingerprint")
	assert.NotContains(t, string(got.Body), "resourceLogs", "body must not be readable OTLP JSON")

	// The receiver, holding only its private JWK and the CA, recovers the
	// exact OTLP/JSON the plain path would have sent.
	opened, err := envelope.Open(string(got.Body), recv.private, nil)
	require.NoError(t, err)
	assert.Equal(t, ContentTypeJSON, opened.ContentType)
	require.Len(t, opened.Certificates, 1)
	assert.Equal(t, "agent-code-42", opened.Certificates[0].Subject.CommonName)

	var payload otlpLogsPayload
	require.NoError(t, json.Unmarshal(opened.Payload, &payload))
	require.Len(t, payload.ResourceLogs, 1)
	require.Len(t, payload.ResourceLogs[0].ScopeLogs, 1)
	require.Len(t, payload.ResourceLogs[0].ScopeLogs[0].LogRecords, 1)
	rec := payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	assert.Equal(t, "018f9c2a7b3d7a018c2e0123456789ab", rec.TraceID)
}

func TestOTLPEmitter_NilSealer_StaysPlainJSON(t *testing.T) {
	url, captured := startSealedCaptureServer(t, http.StatusOK)
	em, err := NewOTLP(OTLPConfig{Endpoint: url}, "1.2.3")
	require.NoError(t, err)
	assert.False(t, em.Sealed())

	require.NoError(t, em.EmitBatch(context.Background(), []model.MachineEvent{makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)}))
	reqs := captured()
	require.Len(t, reqs, 1)
	assert.Equal(t, ContentTypeJSON, reqs[0].ContentType)
	assert.Empty(t, reqs[0].KeyID)
	assert.Empty(t, reqs[0].Signer)
	assert.Contains(t, string(reqs[0].Body), "resourceLogs")
}

func TestOTLPEmitter_SealedRetry_ResendsSameCiphertext(t *testing.T) {
	recv := newReceiver(t)
	sealer, _ := certSealer(t, recv)
	url, captured := startSealedCaptureServer(t, http.StatusServiceUnavailable)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: sealer}, "1.2.3")
	require.NoError(t, err)
	em.retry = retryConfig{maxAttempts: 3, baseDelay: time.Millisecond, maxDelay: time.Millisecond}

	err = em.EmitBatch(context.Background(), []model.MachineEvent{makeEvent(t, model.EventMachineRemoved, model.SeverityHigh)})
	require.Error(t, err)

	reqs := captured()
	require.Len(t, reqs, 3, "three attempts")
	for _, r := range reqs[1:] {
		assert.Equal(t, reqs[0].Body, r.Body, "the batch is sealed once; retries resend the same envelope")
	}
}

func TestOTLPEmitter_SealFailure_IsReportedNotSent(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	boom := errors.New("jwks unreachable")
	sealer, err := envelope.NewSealer(
		envelope.SigningKey{Key: priv, KeyID: "agent-1"},
		keyProviderFunc(func(context.Context) (jose.JSONWebKey, error) { return jose.JSONWebKey{}, boom }),
	)
	require.NoError(t, err)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	em, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: sealer}, "1.2.3")
	require.NoError(t, err)
	err = em.EmitBatch(context.Background(), []model.MachineEvent{makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)})
	require.ErrorIs(t, err, boom)
	assert.Empty(t, captured(), "nothing leaves the process in plaintext when sealing fails")
}

func TestOTLPMetricsEmitter_SealedBatch(t *testing.T) {
	recv := newReceiver(t)
	sealer, _ := certSealer(t, recv)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	me, err := NewOTLPMetrics(OTLPConfig{Endpoint: url, Sealer: sealer})
	require.NoError(t, err)
	require.NoError(t, me.EmitBatch(context.Background(), sampleBatch()))

	reqs := captured()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/v1/metrics", reqs[0].Path)
	assert.Equal(t, ContentTypeJOSE, reqs[0].ContentType)

	opened, err := envelope.Open(string(reqs[0].Body), recv.private, nil)
	require.NoError(t, err)
	assert.Contains(t, string(opened.Payload), "resourceMetrics")
}

func TestAggregateEmitter_SealedFlush(t *testing.T) {
	recv := newReceiver(t)
	sealer, _ := certSealer(t, recv)
	url, captured := startSealedCaptureServer(t, http.StatusOK)

	inner, err := NewOTLP(OTLPConfig{Endpoint: url, Sealer: sealer}, "1.2.3")
	require.NoError(t, err)
	agg := NewAggregate(inner)
	require.NoError(t, agg.Emit(context.Background(), makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)))
	require.NoError(t, agg.Flush(context.Background()))

	reqs := captured()
	require.Len(t, reqs, 1)
	assert.Equal(t, ContentTypeJOSE, reqs[0].ContentType)
	opened, err := envelope.Open(string(reqs[0].Body), recv.private, nil)
	require.NoError(t, err)
	assert.Contains(t, string(opened.Payload), "resourceLogs")
}

type keyProviderFunc func(context.Context) (jose.JSONWebKey, error)

func (f keyProviderFunc) GetEncryptionKey(ctx context.Context) (jose.JSONWebKey, error) {
	return f(ctx)
}
