package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
//
// released is guarded by sync.Once so release() is idempotent AND does not
// race with RunWithOptions reading block: we only close the channel once
// and never mutate block itself after construction.
type fakeRunner struct {
	block    chan struct{}
	released sync.Once
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
	f.released.Do(func() { close(f.block) })
}

func TestRenderScanStatus_NoCoordinator(t *testing.T) {
	st := testStore(t)
	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, nil, false))

	out := buf.String()
	assert.Contains(t, out, "Inspector mode", "status line must name the mode")
	assert.Contains(t, out, "read-only", "status detail must say why scans are off")
	assert.Contains(t, out, "disabled", "read-only variant must render the disabled button")
	assert.Contains(t, out, `aria-disabled="true"`, "read-only variant must mark itself disabled for assistive tech")
	assert.Contains(t, out, "title=", "read-only variant must carry a tooltip")
	assert.Contains(t, out, "read-only inspector mode", "tooltip must explain why the button is disabled")
	assert.NotContains(t, out, "hx-post", "read-only variant must not POST to the scan endpoint")
	// The wrapping <span title=...> is required because disabled buttons
	// don't fire mouseover events in some browsers, breaking native title tooltips.
	assert.True(t, strings.HasPrefix(strings.TrimSpace(out), "<span "), "tooltip must wrap the disabled button")
}

func TestRenderScanStatus_NoScansYet(t *testing.T) {
	st := testStore(t)
	coord := scan.New(newFakeRunner(), st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = coord.Shutdown(context.Background()) })

	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord, true))

	out := buf.String()
	assert.Contains(t, out, ">Idle<", "no runs yet reads as Idle")
	assert.Contains(t, out, "no scans yet")
	assert.Contains(t, out, `hx-post="/api/v1/scan"`, "enabled button must keep the HTMX trigger")
	assert.NotContains(t, out, "disabled", "enabled variant must not render the disabled attribute")
	assert.NotContains(t, out, "title=\"Scan trigger", "enabled variant must not render the read-only tooltip")
}

func TestRenderScanStatus_CoordinatorWithoutConfigIsDisabled(t *testing.T) {
	// A coordinator without a base config cannot start anything: the POST
	// handler would fall back to the read-only fragment, so the button must
	// not offer the click.
	st := testStore(t)
	coord := scan.New(newFakeRunner(), st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = coord.Shutdown(context.Background()) })

	var buf bytes.Buffer
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord, false))
	assert.Contains(t, buf.String(), "disabled")
	assert.NotContains(t, buf.String(), "hx-post")
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
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord, true))

	out := buf.String()
	assert.Contains(t, out, ">Idle<", "an older completed run reads as Idle: %s", out)
	assert.Contains(t, out, "last run 10m ago", "the detail line carries the relative time of the last run")
	assert.NotContains(t, out, "scan-meta-error", "a completed run is not an error tone")
}

func TestScanStatusLines_RecentCompletionThenIdle(t *testing.T) {
	now := time.Now()
	done := now.Add(-30 * time.Second)
	v := scanStatusView{CanScan: true, Latest: &model.ScanRun{
		StartedAt: now.Add(-90 * time.Second), CompletedAt: &done,
		Status: model.ScanStatusCompleted, TotalMachines: 38,
	}}
	v.fillLines(now)
	assert.Equal(t, "Completed", v.Line1)
	assert.Equal(t, "just now · 38 machines", v.Line2)

	// Past the window the same run settles into Idle · last run.
	later := now.Add(recentCompletionWindow + time.Minute)
	v = scanStatusView{CanScan: true, Latest: v.Latest}
	v.fillLines(later)
	assert.Equal(t, "Idle", v.Line1)
	assert.Contains(t, v.Line2, "last run")
}

func TestScanStatusLines_FailedRunIsErrorTone(t *testing.T) {
	now := time.Now()
	v := scanStatusView{CanScan: true, Latest: &model.ScanRun{
		StartedAt: now.Add(-3 * time.Hour), Status: model.ScanStatusFailed,
	}}
	v.fillLines(now)
	assert.Equal(t, "Last run failed", v.Line1)
	assert.Equal(t, "3h ago", v.Line2)
	assert.Equal(t, "scan-meta-error", v.ToneClass)
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
	require.NoError(t, renderScanStatusFragment(&buf, context.Background(), st, coord, true))

	out := buf.String()
	assert.Contains(t, out, ">Scanning<", "the status line must say a scan is in flight")
	assert.Contains(t, out, "Scanning&hellip;", "the button reads Scanning while disabled")
	assert.Contains(t, out, "disabled", "the button must not offer a second click mid-run")
	assert.Contains(t, out, `class="scan-btn-icon spin"`, "the button carries the spinner")
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
	assert.Contains(t, body, ">Scanning<", "post-trigger fragment must show active scan: %s", body)

	// A second click while the fake runner is still blocked is a no-op
	// (AlreadyRunningError) — the fragment still renders Scan running and
	// does not 500.
	rec2 := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec2, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scan", nil))
	require.Equal(t, http.StatusOK, rec2.Code, "second click must not 500: body=%s", rec2.Body.String())
	assert.True(t, strings.Contains(rec2.Body.String(), ">Scanning<"))
}
