package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The default chain runs every platform source read-only: absent
// keychains and empty PEM roots degrade to skips, never an error.
func TestNewChainCollector_SmokeRunOnRealHost(t *testing.T) {
	chain := NewChainCollector()
	assert.Equal(t, "certificate-sources", chain.Name())

	certs, err := chain.Collect(context.Background())
	require.NoError(t, err, "per-source failures are logged, not returned")
	for _, c := range certs {
		assert.NotEmpty(t, c.FingerprintSHA256)
	}
}

func TestChainCollector_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewChainCollector().(*chainCollector).Collect(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}

func TestKeyUsageLists(t *testing.T) {
	got := keyUsageList(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign)
	assert.Contains(t, got, "digital-signature")
	assert.Contains(t, got, "cert-sign")
	assert.Len(t, got, 2, "only the set bits render")
	assert.Empty(t, keyUsageList(0))

	ext := extKeyUsageList([]x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel,
		x509.ExtKeyUsageIPSECUser,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	})
	assert.Len(t, ext, 14, "every known extended usage maps to a token")
	assert.Contains(t, ext, "server-auth")
	assert.Contains(t, ext, "ocsp-signing")
	assert.Empty(t, extKeyUsageList(nil))
}

// isSelfSigned demands an actual self-signature, not merely matching DNs.
func TestIsSelfSigned(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kite-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	assert.True(t, isSelfSigned(ca), "a real self-signed CA is self-signed")

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	assert.False(t, isSelfSigned(leaf), "a CA-issued leaf is not self-signed")
}

func TestJoinDN(t *testing.T) {
	assert.Equal(t, "CN=x, O=acme", JoinDN("CN=x", "O=acme"))
	assert.Equal(t, "", JoinDN())
}
