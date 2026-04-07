package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// RecoveryMiddleware tests
// ---------------------------------------------------------------------------

func TestRecoveryMiddleware_CatchesPanic(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_rest_panics",
	}, []string{"component"})

	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("handler panic")
	})

	handler := RecoveryMiddleware(counter, panicking)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var body errorBody
	err := json.NewDecoder(w.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "internal server error", body.Error)

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "rest"}))
	assert.Equal(t, float64(1), val)
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	normal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	handler := RecoveryMiddleware(nil, normal)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRecoveryMiddleware_NilCounter(t *testing.T) {
	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("no counter")
	})

	handler := RecoveryMiddleware(nil, panicking)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// MaxBytesMiddleware tests
// ---------------------------------------------------------------------------

func TestMaxBytesMiddleware_RejectsOversizedBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	handler := MaxBytesMiddleware(10, inner) // 10-byte limit
	body := strings.NewReader("this body is definitely longer than ten bytes")
	req := httptest.NewRequest("POST", "/test", body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestMaxBytesMiddleware_AllowsSmallBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"body": string(data)})
	})

	handler := MaxBytesMiddleware(100, inner)
	body := strings.NewReader("small")
	req := httptest.NewRequest("POST", "/test", body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMaxBytesMiddleware_ZeroLimitPassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	handler := MaxBytesMiddleware(0, inner)

	// With zero limit, the middleware should be a no-op.
	req := httptest.NewRequest("POST", "/test", strings.NewReader("anything"))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// ResponseBoundingMiddleware tests
// ---------------------------------------------------------------------------

func TestResponseBoundingMiddleware_TruncatesLargeResponse(t *testing.T) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_truncations",
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write 100 bytes.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	})

	handler := ResponseBoundingMiddleware(50, counter, inner) // 50-byte limit
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 50, w.Body.Len(), "response should be truncated to 50 bytes")

	val := testutil.ToFloat64(counter)
	assert.Equal(t, float64(1), val, "truncation counter should be incremented")
}

func TestResponseBoundingMiddleware_AllowsSmallResponse(t *testing.T) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_truncations_small",
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("small"))
	})

	handler := ResponseBoundingMiddleware(1000, counter, inner)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "small", w.Body.String())

	val := testutil.ToFloat64(counter)
	assert.Equal(t, float64(0), val, "truncation counter should not be incremented")
}

func TestResponseBoundingMiddleware_ZeroLimitPassesThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	})

	handler := ResponseBoundingMiddleware(0, nil, inner)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, 1000, w.Body.Len(), "no truncation with zero limit")
}

func TestResponseBoundingMiddleware_NilCounter(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	})

	handler := ResponseBoundingMiddleware(20, nil, inner)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, 20, w.Body.Len(), "truncation should work without counter")
}

func TestResponseBoundingMiddleware_MultipleWrites(t *testing.T) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_truncations_multi",
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("aaaa")) // 4 bytes
		_, _ = w.Write([]byte("bbbb")) // 4 bytes
		_, _ = w.Write([]byte("cccc")) // 4 bytes — should be fully truncated
	})

	handler := ResponseBoundingMiddleware(8, counter, inner)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, 8, w.Body.Len(), "should truncate at 8 bytes across writes")
	assert.Equal(t, "aaaabbbb", w.Body.String())

	val := testutil.ToFloat64(counter)
	assert.Equal(t, float64(1), val, "counter incremented once on truncation")
}
