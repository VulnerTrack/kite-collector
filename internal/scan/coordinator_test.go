package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// fakeRunner is a test double for *engine.Engine. When block is non-nil the
// RunWithOptions call blocks until block is closed or ctx is cancelled.
type fakeRunner struct {
	block  chan struct{}
	result *model.ScanResult
	err    error
	calls  []engine.RunOptions
	mu     sync.Mutex
}

func (r *fakeRunner) RunWithOptions(ctx context.Context, _ *config.Config, opts engine.RunOptions) (*model.ScanResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, opts)
	block := r.block
	r.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, fmt.Errorf("fake runner ctx canceled: %w", ctx.Err())
		}
	}
	return r.result, r.err
}

func (r *fakeRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *fakeRunner) setBlock(ch chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.block = ch
}

var _ Runner = (*fakeRunner)(nil)

// fakeStore satisfies store.Store with minimal behaviour: it records
// CreateScanRun and CompleteScanRun calls so assertions can verify the
// coordinator actually persisted rows before launching the goroutine.
type fakeStore struct {
	created   map[uuid.UUID]model.ScanRun
	completed map[uuid.UUID]model.ScanResult
	mu        sync.Mutex
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		created:   make(map[uuid.UUID]model.ScanRun),
		completed: make(map[uuid.UUID]model.ScanResult),
	}
}

func (s *fakeStore) CreateScanRun(_ context.Context, run model.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created[run.ID] = run
	return nil
}

func (s *fakeStore) CompleteScanRun(_ context.Context, id uuid.UUID, result model.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completed[id] = result
	return nil
}

func (s *fakeStore) createdCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.created)
}

// --- unused methods return zero values ---

func (s *fakeStore) UpsertAsset(_ context.Context, _ model.Asset) error {
	return nil
}

func (s *fakeStore) UpsertAssets(_ context.Context, _ []model.Asset) (int, int, error) {
	return 0, 0, nil
}

func (s *fakeStore) GetAssetByID(_ context.Context, _ uuid.UUID) (*model.Asset, error) {
	return nil, store.ErrNotFound
}

func (s *fakeStore) GetAssetByNaturalKey(_ context.Context, _ string) (*model.Asset, error) {
	return nil, nil
}

func (s *fakeStore) GetAssetsByNaturalKeys(_ context.Context, _ []string) (map[string]model.Asset, error) {
	return nil, nil
}

func (s *fakeStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	return nil, nil
}

func (s *fakeStore) GetStaleAssets(_ context.Context, _ time.Duration) ([]model.Asset, error) {
	return nil, nil
}

func (s *fakeStore) InsertEvent(_ context.Context, _ model.AssetEvent) error {
	return nil
}

func (s *fakeStore) InsertEvents(_ context.Context, _ []model.AssetEvent) error {
	return nil
}

func (s *fakeStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	return nil, nil
}

func (s *fakeStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) {
	return nil, nil
}

func (s *fakeStore) ListScanRuns(_ context.Context, _ int) ([]model.ScanRun, error) {
	return []model.ScanRun{}, nil
}

func (s *fakeStore) GetScanRun(_ context.Context, id uuid.UUID) (*model.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run, ok := s.created[id]; ok {
		cp := run
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (s *fakeStore) MarkScanCancelRequested(_ context.Context, id uuid.UUID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.created[id]
	if !ok {
		return store.ErrNotFound
	}
	t := at
	run.CancelRequestedAt = &t
	s.created[id] = run
	return nil
}

func (s *fakeStore) UpsertSoftware(_ context.Context, _ uuid.UUID, _ []model.InstalledSoftware) error {
	return nil
}

func (s *fakeStore) ListSoftware(_ context.Context, _ uuid.UUID) ([]model.InstalledSoftware, error) {
	return nil, nil
}

func (s *fakeStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error {
	return nil
}

func (s *fakeStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (s *fakeStore) InsertPostureAssessments(_ context.Context, _ []model.PostureAssessment) error {
	return nil
}

func (s *fakeStore) ListPostureAssessments(_ context.Context, _ store.PostureFilter) ([]model.PostureAssessment, error) {
	return nil, nil
}

func (s *fakeStore) InsertRuntimeIncident(_ context.Context, _ model.RuntimeIncident) error {
	return nil
}

func (s *fakeStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	return nil, nil
}

func (s *fakeStore) Migrate(_ context.Context) error {
	return nil
}

func (s *fakeStore) Close() error {
	return nil
}

func (s *fakeStore) ListContentTables(_ context.Context) ([]store.TableSchema, error) {
	return nil, nil
}

func (s *fakeStore) DescribeTable(_ context.Context, _ string) (*store.TableSchema, error) {
	return nil, store.ErrUnknownTable
}

func (s *fakeStore) ListRows(_ context.Context, _ store.RowsFilter) ([]store.Row, int64, error) {
	return nil, 0, store.ErrUnknownTable
}

func (s *fakeStore) GetRowReport(_ context.Context, _ string, _ map[string]string) (*store.RowReport, error) {
	return nil, store.ErrUnknownTable
}

var _ store.Store = (*fakeStore)(nil)

func minimalConfig() *config.Config {
	return &config.Config{
		Safety: config.SafetyConfig{ScanDeadline: "30s"},
		Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{
				"test": {Enabled: true},
			},
		},
	}
}

// TestCoordinator_StartTwiceReturnsAlreadyRunning verifies the single-scan
// invariant: a second Start while the first scan is in flight must fail with
// *AlreadyRunningError carrying the first scan's ID.
func TestCoordinator_StartTwiceReturnsAlreadyRunning(t *testing.T) {
	block := make(chan struct{})
	runner := &fakeRunner{}
	runner.setBlock(block)

	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())

	firstID, err := c.Start(context.Background(), StartRequest{Config: minimalConfig()})
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, firstID)

	// ScanRun row must be persisted before Start returns.
	assert.Equal(t, 1, st.createdCount(), "ScanRun row must be created synchronously")

	// Second call must fail with AlreadyRunningError and echo firstID.
	_, err = c.Start(context.Background(), StartRequest{Config: minimalConfig()})
	require.Error(t, err)

	var arErr *AlreadyRunningError
	require.ErrorAs(t, err, &arErr)
	assert.Equal(t, firstID, arErr.ActiveID, "AlreadyRunningError must carry in-flight ID")
	assert.True(t, errors.Is(err, ErrAlreadyRunning), "errors.Is(err, ErrAlreadyRunning) must succeed")

	// Active() reports the in-flight run.
	active, ok := c.Active()
	require.True(t, ok)
	assert.Equal(t, firstID, active.ID)

	// Release the first scan and shut down cleanly.
	close(block)
	require.NoError(t, c.Shutdown(context.Background()))

	// Exactly one engine invocation, with the pre-allocated ScanID.
	assert.Equal(t, 1, runner.callCount(), "engine should have been invoked exactly once")
	runner.mu.Lock()
	assert.Equal(t, firstID, runner.calls[0].ScanID, "engine must receive pre-allocated ScanID")
	runner.mu.Unlock()
}

// TestCoordinator_ShutdownCancelsInFlight verifies that Shutdown cancels the
// in-flight scan context and waits for the goroutine to finalise. The scan
// must end with ScanStatusTimedOut on the published EventDone.
func TestCoordinator_ShutdownCancelsInFlight(t *testing.T) {
	runner := &fakeRunner{}
	runner.setBlock(make(chan struct{})) // never released; only ctx cancellation exits

	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())

	scanID, err := c.Start(context.Background(), StartRequest{Config: minimalConfig()})
	require.NoError(t, err)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, c.Shutdown(shutdownCtx))

	// After Shutdown returns, no scan is active.
	_, ok := c.Active()
	assert.False(t, ok, "no active run after Shutdown")

	// EventDone must have been published with ScanStatusTimedOut.
	events := c.RecentEvents()
	var doneEvent *Event
	for i := range events {
		if events[i].Type == EventDone && events[i].ScanRunID == scanID {
			doneEvent = &events[i]
			break
		}
	}
	require.NotNil(t, doneEvent, "EventDone must be published")
	assert.Equal(t, model.ScanStatusTimedOut, doneEvent.Status,
		"cancelled scan should terminate as TimedOut")
}

// TestCoordinator_CancelAllowsRestart verifies that after Cancel clears the
// active slot, a subsequent Start returns a fresh scan ID rather than
// AlreadyRunningError.
func TestCoordinator_CancelAllowsRestart(t *testing.T) {
	runner := &fakeRunner{}
	runner.setBlock(make(chan struct{}))

	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })

	firstID, err := c.Start(context.Background(), StartRequest{Config: minimalConfig()})
	require.NoError(t, err)

	// Cancel by ID.
	require.NoError(t, c.Cancel(firstID))

	// Wrong ID → ErrUnknownRun.
	assert.ErrorIs(t, c.Cancel(uuid.Must(uuid.NewV7())), ErrUnknownRun)

	// Wait for the goroutine to clear the active slot.
	require.Eventually(t, func() bool {
		_, ok := c.Active()
		return !ok
	}, 2*time.Second, 10*time.Millisecond, "active slot must clear after cancellation")

	// Cancel(firstID) after completion returns ErrUnknownRun.
	assert.ErrorIs(t, c.Cancel(firstID), ErrUnknownRun)

	// A subsequent Start must succeed with a different ID.
	runner.setBlock(make(chan struct{}))
	secondID, err := c.Start(context.Background(), StartRequest{Config: minimalConfig()})
	require.NoError(t, err)
	assert.NotEqual(t, firstID, secondID)
}

// TestCoordinator_SlowSubscriberDoesNotBlockPublisher verifies ring-buffer
// semantics: a subscriber that stops reading must not stall publish().
func TestCoordinator_SlowSubscriberDoesNotBlockPublisher(t *testing.T) {
	runner := &fakeRunner{}
	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })

	_, unsubscribe := c.Subscribe()
	defer unsubscribe()

	// Flood events far in excess of subscriberChanSize so the subscriber
	// channel fills up. The publisher must not block on the stuck reader.
	const flood = subscriberChanSize * 4
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < flood; i++ {
			c.publish(Event{
				ScanRunID: uuid.Must(uuid.NewV7()),
				Type:      EventProgress,
				At:        time.Now(),
			})
		}
	}()

	select {
	case <-done:
		// Publisher completed without blocking on slow subscriber.
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on slow subscriber — ring-buffer invariant violated")
	}

	// Ring buffer must be bounded at ringCap.
	assert.LessOrEqual(t, len(c.RecentEvents()), defaultRingBufferSize)
}

// TestCoordinator_SubscribeReplaysRingBuffer verifies that late subscribers
// receive recently-published events on Subscribe.
func TestCoordinator_SubscribeReplaysRingBuffer(t *testing.T) {
	runner := &fakeRunner{}
	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })

	scanID := uuid.Must(uuid.NewV7())
	c.publish(Event{ScanRunID: scanID, Type: EventStatus, Status: model.ScanStatusRunning, At: time.Now()})
	c.publish(Event{ScanRunID: scanID, Type: EventDone, Status: model.ScanStatusCompleted, At: time.Now()})

	ch, unsub := c.Subscribe()
	defer unsub()

	received := make([]Event, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			received = append(received, ev)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("expected replay event %d", i)
		}
	}
	assert.Equal(t, EventStatus, received[0].Type)
	assert.Equal(t, EventDone, received[1].Type)
}

// TestCoordinator_RunnerReceivesOptions verifies that Start passes the
// trigger_source and triggered_by fields through to the engine RunOptions.
func TestCoordinator_RunnerReceivesOptions(t *testing.T) {
	runner := &fakeRunner{result: &model.ScanResult{Status: string(model.ScanStatusCompleted)}}
	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })

	_, err := c.Start(context.Background(), StartRequest{
		Config:        minimalConfig(),
		TriggerSource: "api",
		TriggeredBy:   "tenant-abc",
	})
	require.NoError(t, err)

	// Wait for the goroutine to finish.
	require.Eventually(t, func() bool {
		_, ok := c.Active()
		return !ok
	}, 2*time.Second, 10*time.Millisecond)

	runner.mu.Lock()
	defer runner.mu.Unlock()
	require.Len(t, runner.calls, 1)
	assert.Equal(t, "api", runner.calls[0].TriggerSource)
	assert.Equal(t, "tenant-abc", runner.calls[0].TriggeredBy)
}

// TestCoordinator_StartWithNilConfigRejected verifies defensive validation.
func TestCoordinator_StartWithNilConfigRejected(t *testing.T) {
	runner := &fakeRunner{}
	st := newFakeStore()
	c := New(runner, st, context.Background(), slog.Default())
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })

	_, err := c.Start(context.Background(), StartRequest{Config: nil})
	require.Error(t, err)
	assert.Equal(t, 0, runner.callCount())
	assert.Equal(t, 0, st.createdCount())
}
