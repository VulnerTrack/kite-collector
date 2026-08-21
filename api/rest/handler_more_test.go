package rest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
	"github.com/vulnertrack/kite-collector/internal/store"
	storesqlite "github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func moreTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// erroringIncidentStore forces the incidents query error path.
type erroringIncidentStore struct {
	*mockStore
}

func (e *erroringIncidentStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	return nil, errors.New("db exploded")
}

// fakeScanReader scripts the RFC-0124 audit tables.
type fakeScanReader struct {
	events []storesqlite.NetworkScanEventRow
	ports  []storesqlite.NetworkOpenPortRow
	guards []storesqlite.SafetyGuardEventRow
	err    error
}

func (f *fakeScanReader) ListNetworkScanEvents(_ context.Context, _ storesqlite.NetworkScanEventFilter) ([]storesqlite.NetworkScanEventRow, error) {
	return f.events, f.err
}

func (f *fakeScanReader) ListNetworkOpenPorts(_ context.Context, _ storesqlite.NetworkOpenPortFilter) ([]storesqlite.NetworkOpenPortRow, error) {
	return f.ports, f.err
}

func (f *fakeScanReader) ListSafetyGuardEvents(_ context.Context, _ storesqlite.SafetyGuardEventFilter) ([]storesqlite.SafetyGuardEventRow, error) {
	return f.guards, f.err
}

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Handler() wires the middleware chain; with an API key configured every
// route requires the key (or mTLS), without one it stays open.
func TestHandlerChain_APIKeyGate(t *testing.T) {
	h := New(newMockStore(), moreTestLogger())
	h.SetMaxRequestBytes(1 << 20)
	h.SetMaxResponseBytes(1 << 20)
	h.SetResponseTruncations(prometheus.NewCounter(prometheus.CounterOpts{Name: "test_truncations_total"}))
	h.SetPanicsRecovered(prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_rest_panics_total"}, []string{"component"}))

	open := h.Handler()
	assert.Equal(t, http.StatusOK, get(t, open, "/api/v1/health", nil).Code,
		"no API key configured → open")

	h.SetAPIKey("s3cret")
	gated := h.Handler()
	assert.Equal(t, http.StatusUnauthorized,
		get(t, gated, "/api/v1/health", nil).Code,
		"key configured, none provided → 401")
	assert.Equal(t, http.StatusUnauthorized,
		get(t, gated, "/api/v1/health", map[string]string{"X-API-Key": "wrong"}).Code)
	assert.Equal(t, http.StatusOK,
		get(t, gated, "/api/v1/health", map[string]string{"X-API-Key": "s3cret"}).Code,
		"exact key match passes")
}

func TestListIncidents(t *testing.T) {
	h := New(newMockStore(), moreTestLogger())
	mux := h.Mux()

	rec := get(t, mux, "/api/v1/runtime-incidents", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, "[]", rec.Body.String(), "no incidents must serialise as [], not null")

	assert.Equal(t, http.StatusBadRequest,
		get(t, mux, "/api/v1/runtime-incidents?since=yesterday", nil).Code,
		"non-RFC3339 since is rejected")
	assert.Equal(t, http.StatusBadRequest,
		get(t, mux, "/api/v1/runtime-incidents?scan_run_id=not-a-uuid", nil).Code)
	assert.Equal(t, http.StatusOK,
		get(t, mux, "/api/v1/runtime-incidents?since=2026-08-01T00:00:00Z&limit=5000&offset=-3", nil).Code,
		"valid since plus out-of-range limit/offset clamp instead of erroring")

	broken := New(&erroringIncidentStore{newMockStore()}, moreTestLogger())
	rec = get(t, broken.Mux(), "/api/v1/runtime-incidents", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "db exploded",
		"internal error details must not leak to the client")
}

func TestSourceHealthEndpoints(t *testing.T) {
	h := New(newMockStore(), moreTestLogger())
	mux := h.Mux()

	rec := get(t, mux, "/api/v1/source-health", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, "[]", rec.Body.String(), "no breaker wired → empty list")
	assert.Equal(t, http.StatusNotFound,
		get(t, mux, "/api/v1/source-health/wazuh", nil).Code,
		"no breaker wired → any source is not found")

	cb := safety.NewCircuitBreaker(safety.DefaultCircuitBreakerConfig())
	cb.RecordFailure("wazuh", "credentials rejected")
	h.SetCircuitBreaker(cb)
	mux = h.Mux()

	rec = get(t, mux, "/api/v1/source-health", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "wazuh")

	rec = get(t, mux, "/api/v1/source-health/wazuh", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "wazuh")

	assert.Equal(t, http.StatusNotFound,
		get(t, mux, "/api/v1/source-health/never-registered", nil).Code)
}

// The RFC-0124 audit routes only exist when a reader is wired; each then
// serves data, the [] empty shape, 400 on bad since, and opaque 500s.
func TestNetworkScanReaderEndpoints(t *testing.T) {
	bare := New(newMockStore(), moreTestLogger()).Mux()
	for _, p := range []string{
		"/api/v1/network-scan-events",
		"/api/v1/network-open-ports",
		"/api/v1/safety-guard-events",
	} {
		assert.Equal(t, http.StatusNotFound, get(t, bare, p, nil).Code,
			"%s must not exist without a reader", p)
	}

	h := New(newMockStore(), moreTestLogger())
	h.SetNetworkScanReader(&fakeScanReader{
		events: []storesqlite.NetworkScanEventRow{{ScanID: "scan-1"}},
		ports:  []storesqlite.NetworkOpenPortRow{{ScanID: "scan-1"}, {ScanID: "scan-2"}},
		guards: []storesqlite.SafetyGuardEventRow{{GuardType: "ip_count_cap"}},
	})
	mux := h.Mux()

	rec := get(t, mux, "/api/v1/network-scan-events", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "scan-1")

	rec = get(t, mux, "/api/v1/network-open-ports?scan_id=scan-1", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "scan-2")

	rec = get(t, mux, "/api/v1/safety-guard-events?guard_type=ip_count_cap", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ip_count_cap")

	for _, p := range []string{
		"/api/v1/network-scan-events?since=bogus",
		"/api/v1/network-open-ports?since=bogus",
		"/api/v1/safety-guard-events?since=bogus",
	} {
		assert.Equal(t, http.StatusBadRequest, get(t, mux, p, nil).Code, p)
	}

	empty := New(newMockStore(), moreTestLogger())
	empty.SetNetworkScanReader(&fakeScanReader{})
	for _, p := range []string{
		"/api/v1/network-scan-events",
		"/api/v1/network-open-ports",
		"/api/v1/safety-guard-events",
	} {
		rec := get(t, empty.Mux(), p, nil)
		require.Equal(t, http.StatusOK, rec.Code, p)
		assert.JSONEq(t, "[]", rec.Body.String(), "%s empty shape", p)
	}

	failing := New(newMockStore(), moreTestLogger())
	failing.SetNetworkScanReader(&fakeScanReader{err: errors.New("disk on fire")})
	for _, p := range []string{
		"/api/v1/network-scan-events",
		"/api/v1/network-open-ports",
		"/api/v1/safety-guard-events",
	} {
		rec := get(t, failing.Mux(), p, nil)
		assert.Equal(t, http.StatusInternalServerError, rec.Code, p)
		assert.NotContains(t, rec.Body.String(), "disk on fire",
			"%s must not leak internal errors", p)
	}
}

func TestParamClamping(t *testing.T) {
	assert.Equal(t, 50, parseIntParam("", 50), "empty falls back")
	assert.Equal(t, 50, parseIntParam("abc", 50), "garbage falls back")
	assert.Equal(t, 7, parseIntParam("7", 50))

	assert.Equal(t, maxLimit, clampLimit(maxLimit+1), "limit clamps at the cap")
	assert.Equal(t, maxLimit, clampLimit(maxLimit))
	assert.Equal(t, defaultLimit, clampLimit(0), "non-positive limit falls back to default")
	assert.Equal(t, defaultLimit, clampLimit(-1))

	assert.Equal(t, 0, clampOffset(-5), "negative offsets clamp to zero")
	assert.Equal(t, 123, clampOffset(123))
}
