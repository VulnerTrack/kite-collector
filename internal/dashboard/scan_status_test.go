package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/scan"
)

// fakeRunner is a minimal scan.Runner used by the dashboard tests. It
// blocks indefinitely on a channel until released so the coordinator
// reports an active scan for Active() assertions.
type fakeRunner struct {
	block chan struct{}
}

func newFakeRunner() *fakeRunner { return &fakeRunner{block: make(chan struct{})} }

func (f *fakeRunner) RunWithOptions(ctx context.Context, _ *config.Config, _ engine.RunOptions) (*model.ScanResult, error) {
	select {
	case <-f.block:
		return &model.ScanResult{Status: string(model.ScanStatusCompleted)}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("fake runner context cancelled: %w", ctx.Err())
	}
}

func (f *fakeRunner) release() {
	if f.block != nil {
		close(f.block)
		f.block = nil
	}
}

func TestRenderScanStatus_NoCoordinator(t *testing.T) {
	st := testStore(t)
	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, nil))

	out := buf.String()
	assert.Contains(t, out, "badge-gray")
	assert.Contains(t, out, "read-only")
}

func TestRenderScanStatus_NoScansYet(t *testing.T) {
	st := testStore(t)
	coord := scan.New(newFakeRunner(), st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = coord.Shutdown(context.Background()) })

	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord))

	assert.Contains(t, buf.String(), "No scans yet")
}

func TestRenderScanStatus_LatestTerminal(t *testing.T) {
	st := testStore(t)
	coord := scan.New(newFakeRunner(), st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = coord.Shutdown(context.Background()) })

	// Seed a completed scan so the template renders the terminal badge.
	require.NoError(t, st.CreateScanRun(context.Background(), model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Add(-10 * time.Minute),
		Status:    model.ScanStatusCompleted,
	}))

	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord))

	out := buf.String()
	assert.Contains(t, out, "badge-green", "completed scans must render green: %s", out)
	assert.Contains(t, out, "completed")
}

func TestRenderScanStatus_ActiveScan(t *testing.T) {
	st := testStore(t)
	runner := newFakeRunner()
	coord := scan.New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() {
		runner.release()
		_ = coord.Shutdown(context.Background())
	})

	scanID, err := coord.Start(context.Background(), scan.StartRequest{
		Config: &config.Config{
			Discovery: config.DiscoveryConfig{
				Sources: map[string]config.SourceConfig{"network": {Enabled: true}},
			},
		},
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord))

	out := buf.String()
	assert.Contains(t, out, "Scan running")
	assert.Contains(t, out, scanID.String(), "active fragment must echo scan id so F12 debugging works: %s", out)
}

func TestPostScanTrigger_NoCoordinatorReturnsReadOnlyBadge(t *testing.T) {
	st := testStore(t)
	srv := Serve(":0", st, testContext(), nil, Options{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scan", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "read-only")
}

func TestPostScanTrigger_WithCoordinatorStartsAndRendersActive(t *testing.T) {
	st := testStore(t)
	runner := newFakeRunner()
	coord := scan.New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() {
		runner.release()
		_ = coord.Shutdown(context.Background())
	})

	cfg := &config.Config{
		Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{"network": {Enabled: true}},
		},
	}
	srv := Serve(":0", st, testContext(), nil, Options{Coordinator: coord, BaseConfig: cfg})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scan", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Scan running", "post-trigger fragment must show active scan: %s", body)

	// A second click while the fake runner is still blocked is a no-op
	// (AlreadyRunningError) — the fragment still renders Scan running and
	// does not 500.
	rec2 := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec2, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scan", nil))
	require.Equal(t, http.StatusOK, rec2.Code, "second click must not 500: body=%s", rec2.Body.String())
	assert.True(t, strings.Contains(rec2.Body.String(), "Scan running"))
}
