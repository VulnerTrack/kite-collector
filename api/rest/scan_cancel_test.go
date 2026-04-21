package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/scan"
)

func TestCancelScan_NoCoordinatorReturns503(t *testing.T) {
	h := New(newMockStore(), slog.Default())
	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCancelScan_KillSwitchReturns503(t *testing.T) {
	t.Setenv(scanAPIKillSwitchEnv, "off")
	h, _, _, _ := newHandlerWithCoord(t)
	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCancelScan_InvalidUUIDReturns400(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/not-a-uuid/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCancelScan_UnknownIDReturns404(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)
	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCancelScan_AlreadyTerminalReturns409(t *testing.T) {
	h, ms, _, _ := newHandlerWithCoord(t)
	id := uuid.Must(uuid.NewV7())

	ms.mu.Lock()
	ms.scanRun = &model.ScanRun{ID: id, Status: model.ScanStatusCompleted}
	ms.mu.Unlock()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestCancelScan_RunningScanReturns202AndStamps(t *testing.T) {
	h, ms, _, runner := newHandlerWithCoord(t)

	// Launch a real scan through the coordinator so Cancel has an active
	// run to target. The fake runner blocks until released.
	id, err := h.coordinator.Start(context.Background(), scan.StartRequest{
		Config: &config.Config{
			Discovery: config.DiscoveryConfig{
				Sources: map[string]config.SourceConfig{"network": {Enabled: true}},
			},
		},
	})
	require.NoError(t, err)

	// Seed the mock store to Running status — the coordinator's
	// CreateScanRun populated the row, but the mock only stores the last
	// seen scanRun; make sure Status reflects Running here.
	ms.mu.Lock()
	if ms.scanRun == nil || ms.scanRun.ID != id {
		ms.scanRun = &model.ScanRun{ID: id, Status: model.ScanStatusRunning}
	} else {
		ms.scanRun.Status = model.ScanStatusRunning
	}
	ms.mu.Unlock()

	before := time.Now().UTC()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/scans/"+id.String()+"/cancel", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, "body=%s", rec.Body.String())

	var body cancelResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, id.String(), body.ScanRunID)
	assert.False(t, body.CancelRequestedAt.Before(before),
		"cancel_requested_at must be now-ish: got=%s before=%s", body.CancelRequestedAt, before)

	ms.mu.Lock()
	stamp := ms.scanRun.CancelRequestedAt
	ms.mu.Unlock()
	require.NotNil(t, stamp, "cancel_requested_at must be set on the mock store row")
	assert.False(t, stamp.Before(before))

	// Release the runner so the goroutine can finish; t.Cleanup in
	// newHandlerWithCoord also releases defensively.
	runner.release()
}
