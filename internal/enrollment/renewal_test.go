package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
)

type renewalRPCClient struct {
	kitev1.CollectorServiceClient
	request  *kitev1.RenewRequest
	response *kitev1.RenewResponse
	err      error
}

func (c *renewalRPCClient) RenewCertificate(
	_ context.Context,
	req *kitev1.RenewRequest,
	_ ...grpc.CallOption,
) (*kitev1.RenewResponse, error) {
	c.request = req
	return c.response, c.err
}

func TestShouldRenew(t *testing.T) {
	now := time.Now()

	tests := []struct {
		notBefore time.Time
		notAfter  time.Time
		name      string
		want      bool
	}{
		{
			name:      "fresh certificate - no renewal",
			notBefore: now.Add(-1 * time.Hour),
			notAfter:  now.Add(89 * time.Hour), // 90h total, 1h elapsed = 1.1%
			want:      false,
		},
		{
			name:      "past 2/3 lifetime - should renew",
			notBefore: now.Add(-70 * time.Hour),
			notAfter:  now.Add(20 * time.Hour), // 90h total, 70h elapsed = 77%
			want:      true,
		},
		{
			name:      "exactly at 2/3 - should renew",
			notBefore: now.Add(-60 * time.Hour),
			notAfter:  now.Add(30 * time.Hour), // 90h total, 60h = 66.7%
			want:      true,
		},
		{
			name:      "expired - should renew",
			notBefore: now.Add(-100 * time.Hour),
			notAfter:  now.Add(-10 * time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRenew(tt.notBefore, tt.notAfter)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateCSR(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	csrDER, err := generateCSR("test-agent-123", priv)
	require.NoError(t, err)
	require.NotEmpty(t, csrDER)

	// Parse the CSR to verify it's valid.
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	assert.Equal(t, "test-agent-123", csr.Subject.CommonName)
	assert.Equal(t, x509.PureEd25519, csr.SignatureAlgorithm)
}

func TestParseCertExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	notAfter := time.Now().Add(89 * time.Hour).UTC().Truncate(time.Second)

	certDER, err := GenerateSelfSignedCert(priv, pub, notBefore, notAfter)
	require.NoError(t, err)

	nb, na, err := ParseCertExpiry(certDER)
	require.NoError(t, err)

	assert.Equal(t, notBefore, nb)
	assert.Equal(t, notAfter, na)
}

func TestParseCertExpiry_PEMEncoded(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	notAfter := time.Now().Add(89 * time.Hour).UTC().Truncate(time.Second)

	certDER, err := GenerateSelfSignedCert(priv, pub, notBefore, notAfter)
	require.NoError(t, err)

	// Wrap in PEM encoding.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	require.NotEmpty(t, certPEM)

	nb, na, err := ParseCertExpiry(certPEM)
	require.NoError(t, err)

	assert.Equal(t, notBefore, nb)
	assert.Equal(t, notAfter, na)
}

func TestRenew_RPCSuccessCarriesSignedCSR(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	client := &renewalRPCClient{response: &kitev1.RenewResponse{
		Status:               "renewed",
		ClientCertificate:    []byte("renewed-certificate"),
		CertificateExpiresAt: 123456789,
	}}

	result, err := Renew(context.Background(), client, "kite-agent-rpc", privateKey)

	require.NoError(t, err)
	assert.Equal(t, "renewed", result.Status)
	assert.Equal(t, []byte("renewed-certificate"), result.ClientCertificate)
	assert.Equal(t, int64(123456789), result.ExpiresAt)
	require.NotNil(t, client.request)
	assert.Equal(t, "kite-agent-rpc", client.request.AgentId)
	csr, err := x509.ParseCertificateRequest(client.request.Csr)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	assert.Equal(t, "kite-agent-rpc", csr.Subject.CommonName)
}

func TestRenew_RPCFailurePreservesCause(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rpcErr := errors.New("fleet manager unavailable")
	client := &renewalRPCClient{err: rpcErr}

	result, err := Renew(context.Background(), client, "kite-agent-rpc", privateKey)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, rpcErr)
	assert.Contains(t, err.Error(), "renew RPC")
}

func TestCertExpiryMonitor_ChecksEveryEndpointAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		mu      sync.Mutex
		checked []string
	)
	monitor := NewCertExpiryMonitor(time.Millisecond, func(_ context.Context, endpoint string) error {
		mu.Lock()
		checked = append(checked, endpoint)
		count := len(checked)
		mu.Unlock()
		if count >= 2 {
			cancel()
		}
		if endpoint == "secondary" {
			return errors.New("simulated endpoint failure")
		}
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	done := make(chan struct{})
	go func() {
		monitor.Run(ctx, []string{"primary", "secondary"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("certificate monitor did not stop after cancellation")
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, checked, "primary")
	assert.Contains(t, checked, "secondary")
}

func TestParseCertExpiry_RejectsInvalidData(t *testing.T) {
	_, _, err := ParseCertExpiry([]byte("not a certificate"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}
