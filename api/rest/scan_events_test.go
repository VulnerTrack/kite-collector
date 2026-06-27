package rest

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/scan"
)

// readNSSEFrames reads up to n SSE frames from rd. Each frame is the
// concatenation of `event: ...` and `data: ...` lines separated by the
// trailing blank-line terminator. Returns fewer than n frames if the
// connection closes or the timeout elapses.
func readNSSEFrames(t *testing.T, rd *bufio.Reader, n int, timeout time.Duration) []string {
	t.Helper()
	frames := make([]string, 0, n)
	deadline := time.Now().Add(timeout)
	var buf strings.Builder
	for len(frames) < n {
		if time.Now().After(deadline) {
			break
		}
		line, err := rd.ReadString('\n')
		if err != nil {
			if buf.Len() > 0 {
				frames = append(frames, strings.TrimRight(buf.String(), "\n"))
			}
			break
		}
		if line == "\n" {
			if buf.Len() > 0 {
				frames = append(frames, strings.TrimRight(buf.String(), "\n"))
				buf.Reset()
			}
			continue
		}
		buf.WriteString(line)
	}
	return frames
}

func TestScanEvents_EmitsSnapshotThenDoneForTerminalRun(t *testing.T) {
	h, ms, _, _ := newHandlerWithCoord(t)
	scanID := uuid.Must(uuid.NewV7())

	ms.mu.Lock()
	ms.scanRun = &model.ScanRun{
		ID:            scanID,
		Status:        model.ScanStatusCompleted,
		TriggerSource: "api",
	}
	ms.mu.Unlock()

	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/api/v1/scans/"+scanID.String()+"/events", nil)
	require.NoError(t, err)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	frames := readNSSEFrames(t, bufio.NewReader(resp.Body), 2, 2*time.Second)

	require.GreaterOrEqual(t, len(frames), 2,
		"expected snapshot + done frames, got %d: %v", len(frames), frames)
	assert.Contains(t, frames[0], "event: snapshot")
	assert.Contains(t, frames[0], scanID.String())
	assert.Contains(t, frames[1], "event: done")
}

func TestScanEvents_StreamsLiveEventsUntilDone(t *testing.T) {
	h, ms, _, runner := newHandlerWithCoord(t)

	// Kick off a real scan via the coordinator so the ring buffer gets a
	// running-status event the SSE subscriber will pick up.
	scanID, err := h.coordinator.Start(context.Background(), scan.StartRequest{
		Config: &config.Config{
			Discovery: config.DiscoveryConfig{
				Sources: map[string]config.SourceConfig{"network": {Enabled: true}},
			},
		},
	})
	require.NoError(t, err)

	// Seed the mock store so the handler's GetScanRun lookup succeeds.
	ms.mu.Lock()
	ms.scanRun = &model.ScanRun{ID: scanID, Status: model.ScanStatusRunning}
	ms.mu.Unlock()

	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/api/v1/scans/"+scanID.String()+"/events", nil)
	require.NoError(t, err)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rd := bufio.NewReader(resp.Body)

	// Release the fake runner so the coordinator publishes EventDone.
	go func() {
		time.Sleep(50 * time.Millisecond)
		runner.release()
	}()

	frames := readNSSEFrames(t, rd, 4, 3*time.Second)
	require.NotEmpty(t, frames)

	var sawSnapshot, sawDone bool
	for _, f := range frames {
		if strings.Contains(f, "event: snapshot") {
			sawSnapshot = true
		}
		if strings.Contains(f, "event: done") {
			sawDone = true
		}
	}
	assert.True(t, sawSnapshot, "expected an initial snapshot frame: %v", frames)
	assert.True(t, sawDone, "expected a terminal done frame: %v", frames)
}

func TestScanEvents_NotFoundReturns404(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)
	unknown := uuid.Must(uuid.NewV7())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/scans/"+unknown.String()+"/events", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestScanEvents_InvalidUUIDReturns400(t *testing.T) {
	h, _, _, _ := newHandlerWithCoord(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/scans/not-a-uuid/events", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestScanEvents_NoCoordinatorReturns503(t *testing.T) {
	h := New(newMockStore(), nil)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/scans/"+id.String()+"/events", nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
