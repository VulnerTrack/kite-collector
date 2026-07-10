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

func TestSafeClientWithTimeout_CustomTimeout(t *testing.T) {
	// RFC-0137 R1: the timeout variant honours the caller-supplied bound
	// (Entra's request_timeout_seconds) instead of the 30s default.
	client, u, err := SafeClientWithTimeout("entra", "https://127.0.0.1:9443", true, 60*time.Second)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, u)
	assert.Equal(t, 60*time.Second, client.Timeout)
}

func TestSafeClientWithTimeout_NonPositiveFallsBackToDefault(t *testing.T) {
	// A zero or negative timeout must never yield a client with Timeout: 0
	// (Finding F4) — it falls back to the shared 30s default.
	client, _, err := SafeClientWithTimeout("entra", "https://127.0.0.1:9443", true, 0)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, client.Timeout)

	client, _, err = SafeClientWithTimeout("entra", "https://127.0.0.1:9443", true, -5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestSafeClientWithTimeout_SSRFStillRejected(t *testing.T) {
	// The timeout variant applies the same SSRF validation as SafeClient: a
	// private target with allowPrivate=false is rejected and attributed.
	_, _, err := SafeClientWithTimeout("entra", "https://127.0.0.1:9443", false, 60*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entra:", "error is attributed to the source")
}
