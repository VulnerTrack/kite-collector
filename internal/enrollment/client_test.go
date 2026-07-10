package enrollment

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/identity"
)

// stubDoer is an httpDoer returning a canned response/error, so Enroll's error
// paths can be exercised without a live PKI server.
type stubDoer struct {
	resp *http.Response
	err  error
}

func (d stubDoer) Do(*http.Request) (*http.Response, error) { return d.resp, d.err }

func TestEnroll_NetworkFailurePropagatesCause(t *testing.T) {
	c := NewClient(nil)
	c.http = stubDoer{err: errors.New("dial tcp 203.0.113.1:443: connect: connection refused")}

	_, err := c.Enroll(context.Background(), "agent-1", "token")
	require.Error(t, err)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "enrollment failure must surface a *kiteerrors.Error")
	assert.Equal(t, "KITE-E017", ke.Code)
	assert.Equal(t, "connect", ke.Context["phase"])
	assert.Contains(t, err.Error(), "connection refused", "underlying cause must be preserved")
}

func TestEnroll_PKIRejectionSurfacesStatusAndBody(t *testing.T) {
	c := NewClient(nil)
	c.http = stubDoer{resp: &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid enrollment token"}`)),
	}}

	_, err := c.Enroll(context.Background(), "agent-1", "bad-token")
	require.Error(t, err)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "PKI rejection must surface a *kiteerrors.Error")
	assert.Equal(t, "KITE-E017", ke.Code)
	assert.Equal(t, http.StatusUnauthorized, ke.Context["http_status"])
	assert.Contains(t, err.Error(), "PKI server returned 401", "status must be preserved as the cause")
	assert.Contains(t, err.Error(), "invalid enrollment token", "server body must be surfaced for diagnosis")
}

func TestStoreCertificates(t *testing.T) {
	dir := t.TempDir()

	result := &Result{
		CACertificate:     []byte("--- CA CERT ---"),
		ClientCertificate: []byte("--- CLIENT CERT ---"),
		ClientKey:         []byte("--- CLIENT KEY ---"),
	}

	err := StoreCertificates(dir, result)
	require.NoError(t, err)

	// Verify files exist with correct content.
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.CACertificate, ca)

	cert, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientCertificate, cert)

	key, err := os.ReadFile(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, result.ClientKey, key)

	// Verify private key has restrictive permissions.
	info, err := os.Stat(filepath.Join(dir, "agent-key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestMachineFingerprint(t *testing.T) {
	fp := identity.MachineFingerprint()
	assert.NotEmpty(t, fp)
}
