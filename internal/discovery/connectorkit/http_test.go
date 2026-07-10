package connectorkit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeClient_PrivateAllowed(t *testing.T) {
	// A literal loopback IP resolves without real DNS, so this stays offline.
	client, u, err := SafeClient("test", "https://127.0.0.1:9443", true)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, u)
	assert.Equal(t, "127.0.0.1:9443", u.Host)
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestSafeClient_PrivateRejected(t *testing.T) {
	_, _, err := SafeClient("device42", "https://127.0.0.1:9443", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device42:", "error is attributed to the source")
}

func TestSafeClient_HTTPRejected(t *testing.T) {
	// SafeClient never opts into AllowHTTP — plaintext is always rejected.
	_, _, err := SafeClient("test", "http://127.0.0.1", true)
	require.Error(t, err)
}

func TestSafeClient_InvalidScheme(t *testing.T) {
	_, _, err := SafeClient("test", "ftp://example.com", false)
	require.Error(t, err)
}
