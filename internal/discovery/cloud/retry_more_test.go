package cloud

// retry_more_test.go: exact-value coverage for authError.Error, the backoff
// schedule, Retry-After HTTP-date parsing, body draining, and the doWithRetry
// terminal branches (non-retryable 4xx, exhausted attempts).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthErrorError(t *testing.T) {
	e := &authError{statusCode: 403, body: "denied"}
	assert.Equal(t, "authentication/authorization error (403): denied", e.Error())
}

func TestAuthErrorError_TruncatesLongBody(t *testing.T) {
	long := strings.Repeat("x", 250)
	e := &authError{statusCode: 401, body: long}
	assert.Equal(t,
		"authentication/authorization error (401): "+strings.Repeat("x", 200)+"...",
		e.Error())
}

func TestRetryBackoff_Schedule(t *testing.T) {
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{6, 30 * time.Second}, // 32s capped at defaultMaxDelay
		{10, 30 * time.Second},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, retryBackoff(tc.attempt), "attempt=%d", tc.attempt)
	}
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	future := time.Now().UTC().Add(10 * time.Second).Format(http.TimeFormat)
	d := parseRetryAfter(future)
	assert.Greater(t, d, 5*time.Second)
	assert.LessOrEqual(t, d, 10*time.Second)

	past := time.Now().UTC().Add(-time.Hour).Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), parseRetryAfter(past), "past HTTP-date must yield 0")
}

func TestParseRetryAfter_NegativeSeconds(t *testing.T) {
	assert.Equal(t, time.Duration(0), parseRetryAfter("-3"))
}

func TestDrainBody(t *testing.T) {
	t.Run("nil body", func(t *testing.T) {
		assert.Equal(t, "", drainBody(&http.Response{}, 100))
	})
	t.Run("truncates at exactly maxLen", func(t *testing.T) {
		resp := &http.Response{Body: io.NopCloser(strings.NewReader("abcdefgh"))}
		assert.Equal(t, "abcde", drainBody(resp, 5))
	})
	t.Run("shorter than maxLen returned whole", func(t *testing.T) {
		resp := &http.Response{Body: io.NopCloser(strings.NewReader("ok"))}
		assert.Equal(t, "ok", drainBody(resp, 5))
	})
}

func TestDoWithRetry_NonRetryable4xx(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no such thing"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 404")
	assert.Contains(t, err.Error(), "no such thing")
	assert.Equal(t, int32(1), callCount.Load(), "client errors must not be retried")
}

func TestDoWithRetry_ExhaustsAttemptsOn500(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted 3 retry attempts")
	assert.Contains(t, err.Error(), "server error (500)")
	assert.Contains(t, err.Error(), "boom")
	assert.Equal(t, int32(3), callCount.Load(), "must attempt exactly defaultMaxAttempts times")
}

func TestDoWithRetry_401ReturnsAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("token expired"))
	}))
	defer srv.Close()

	ctx := context.Background()
	resp, err := doWithRetry(ctx, "test", func() (*http.Response, error) {
		return doGet(ctx, srv.URL)
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)

	var ae *authError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, 401, ae.statusCode)
	assert.Equal(t, "token expired", ae.body)
}
