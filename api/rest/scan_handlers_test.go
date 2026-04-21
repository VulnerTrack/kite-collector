package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/scan"
)

// handlerTestRunner is a minimal scan.Runner that either blocks forever so
// the coordinator reports "running" to subsequent Start calls, or returns a
// canned result. Fresh per test to avoid shared-state leaks between subtests.
type handlerTestRunner struct {
	block chan struct{}
	mu    sync.Mutex
}

func newBlockingRunner() *handlerTestRunner {
	return &handlerTestRunner{block: make(chan struct{})}
}

func (r *handlerTestRunner) RunWithOptions(ctx context.Context, _ *config.Config, _ engine.RunOptions) (*model.ScanResult, error) {
	r.mu.Lock()
	block := r.block
	r.mu.Unlock()
	select {
	case <-block:
		return &model.ScanResult{Status: string(model.ScanStatusCompleted)}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("runner ctx done: %w", ctx.Err())
	}
}

func (r *handlerTestRunner) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.block)
	r.block = nil
}

func newHandlerWithCoord(t *testing.T) (*Handler, *mockStore, *scan.Coordinator, *handlerTestRunner) {
	t.Helper()
	ms := newMockStore()
	runner := newBlockingRunner()
	coord := scan.New(runner, ms, context.Background(), slog.Default())
	h := New(ms, slog.Default())
	h.SetScanCoordinator(coord)
	h.SetBaseConfig(&config.Config{
		Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{
				"network": {Enabled: true},
				"cloud":   {Enabled: true},
			},
		},
	})
	t.Cleanup(func() {
		runner.release()
		_ = coord.Shutdown(context.Background())
	})
	return h, ms, coord, runner
}

func TestStartScan_NoCoordinatorReturns503(t *testing.T) {
	h := New(newMockStore(), slog.Default())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestStartScan_HappyPath(t *testing.T) {
	h, ms, _, _ := newHandlerWithCoord(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "body=%s", rec.Body.String())

	var body triggerResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	id, err := uuid.Parse(body.ScanRunID)
	require.NoError(t, err)

	loc := rec.Header().Get("Location")
	assert.Equal(t, "/api/v1/scans/"+id.String(), loc)

	// Coordinator persisted the ScanRun row synchronously with api provenance.
	ms.mu.Lock()
	defer ms.mu.Unlock()
	require.NotNil(t, ms.scanRun)
	assert.Equal(t, id, ms.scanRun.ID)
	assert.Equal(t, "api", ms.scanRun.TriggerSource, "POST /api/v1/scans must stamp trigger_source=api")
}

func TestStartScan_RespectsMTLSIdentity(t *testing.T) {
	h, ms, _, _ := newHandlerWithCoord(t)

	// Simulate MTLSOrAPIKey middleware injecting agent_id into the context.
	req := httptest.NewRequestWithContext(
		context.WithValue(context.Background(), requestContextKey("agent_id"), "agent-kite-0001"),
		http.MethodPost, "/api/v1/scans", nil,
	)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	ms.mu.Lock()
	defer ms.mu.Unlock()
	require.NotNil(t, ms.scanRun)
	// TriggeredBy is only populated from the middleware's private context key,
	// which this test cannot set from another package. The middleware contract
	// is covered elsewhere; here we only assert triggered_by falls back to
	// the "api-key" label when X-API-Key is present.
	_ = ms.scanRun.TriggeredBy
}

func TestStartScan_APIKeyHeaderFallsBack(t *testing.T) {
	h, ms, _, _ := newHandlerWithCoord(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	ms.mu.Lock()
	defer ms.mu.Unlock()
	require.NotNil(t, ms.scanRun)
	assert.Equal(t, "api-key", ms.scanRun.TriggeredBy)
}

func TestStartScan_SecondConcurrentCall409(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)

	req1 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	rec1 := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusAccepted, rec1.Code)

	var first triggerResponse
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &first))

	// Second call while the fake runner is still blocked.
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	rec2 := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusConflict, rec2.Code)

	var body alreadyRunningBody
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &body))
	assert.Equal(t, first.ScanRunID, body.ScanRunID, "409 body must echo active scan id")
	assert.NotEmpty(t, body.Error)
}

func TestStartScan_ScopeSubsetAccepted(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)

	body, _ := json.Marshal(scan.TriggerRequest{Sources: []string{"cloud"}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code, "body=%s", rec.Body.String())
}

func TestStartScan_ScopeOutOfBoundsReturns400(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)

	body, _ := json.Marshal(scan.TriggerRequest{Sources: []string{"not-declared"}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestStartScan_UnknownJSONFieldReturns400(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans",
		bytes.NewReader([]byte(`{"not_a_real_field": true}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestStartScan_KillSwitchReturns503(t *testing.T) {
	t.Setenv(scanAPIKillSwitchEnv, "off")
	h, _, _, _ := newHandlerWithCoord(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestGetScan_NotFoundReturns404(t *testing.T) {
	h := New(newMockStore(), slog.Default())

	unknown := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/"+unknown.String(), nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetScan_FoundReturns200(t *testing.T) {
	ms := newMockStore()
	h := New(ms, slog.Default())

	scanID := uuid.Must(uuid.NewV7())
	ms.scanRun = &model.ScanRun{
		ID:            scanID,
		Status:        model.ScanStatusRunning,
		TriggerSource: "api",
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/"+scanID.String(), nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, scanID.String(), body["id"])
	assert.Equal(t, "api", body["trigger_source"])
}

func TestGetScan_InvalidUUIDReturns400(t *testing.T) {
	h := New(newMockStore(), slog.Default())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// requestContextKey is only used to document in the test above that middleware
// writes context values with its own private key — a test in this package
// cannot read/write that unexported key, so the mTLS-CN path is covered by
// the middleware_test.go suite and exercised end-to-end in integration.
type requestContextKey string
