package vps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryBackoff(t *testing.T) {
	assert.Equal(t, 1*time.Second, retryBackoff(1))
	assert.Equal(t, 2*time.Second, retryBackoff(2))
	assert.Equal(t, 4*time.Second, retryBackoff(3))
	// Verify cap at maxRetryDelay.
	assert.LessOrEqual(t, retryBackoff(100), maxRetryDelay)
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	assert.Equal(t, 5*time.Second, parseRetryAfter("5"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("invalid"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("0"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-1"))
}

func TestToJSON(t *testing.T) {
	assert.Equal(t, `{"key":"val"}`, toJSON(map[string]any{"key": "val"}))
	assert.Equal(t, `{}`, toJSON(map[string]any{}))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "ab", truncate("abcde", 2))
	assert.Equal(t, "", truncate("", 10))
}

func TestDoWithRetry_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newClient("test", srv.URL, bearerAuth("tok"))
	var out map[string]any
	err := c.get(context.Background(), "/test", &out)
	require.NoError(t, err)
	assert.Equal(t, true, out["ok"])
}

func TestDoWithRetry_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token"}`))
	}))
	defer srv.Close()

	c := newClient("test", srv.URL, bearerAuth("bad"))
	var out map[string]any
	err := c.get(context.Background(), "/test", &out)
	require.Error(t, err)

	var authErr *authError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, 401, authErr.statusCode)
}

func TestDoWithRetry_ServerError_Exhausted(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	c := newClient("test", srv.URL, bearerAuth("tok"))
	var out map[string]any
	err := c.get(context.Background(), "/test", &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
	assert.Equal(t, maxRetryAttempts, calls)
}

func TestDoWithRetry_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClient("test", srv.URL, bearerAuth("tok"))
	var out map[string]any
	err := c.get(ctx, "/test", &out)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
