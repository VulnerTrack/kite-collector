package enrollment

import (
	"encoding/pem"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertExpiryMonitor_DefaultsNilLogger(t *testing.T) {
	m := NewCertExpiryMonitor(time.Minute, nil, nil)
	require.NotNil(t, m)
	assert.NotNil(t, m.logger, "nil logger must fall back to slog.Default")
	assert.Equal(t, time.Minute, m.interval)
}

func TestNewCertExpiryMonitor_KeepsProvidedLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewCertExpiryMonitor(30*time.Second, nil, logger)
	assert.Same(t, logger, m.logger)
	assert.Equal(t, 30*time.Second, m.interval)
}

func TestParseCertExpiry_PEMWithBadDER(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
	_, _, err := ParseCertExpiry(certPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse certificate")
}
