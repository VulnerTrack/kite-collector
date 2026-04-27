// Package scan contains the scan coordinator that owns engine invocations.
//
// The coordinator enforces the single-scan-at-a-time invariant required by
// RFC-0104: the engine's dedup index, source-health state, and circuit
// breakers are not safe for parallel Run() calls, so a second trigger while
// a scan is in flight must return ErrAlreadyRunning rather than racing.
//
// It also brokers scan lifecycle events to subscribers (the SSE stream
// handler and the dashboard status fragment) without ever blocking the
// engine goroutine — slow subscribers drop events, not the engine.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// Runner is the subset of *engine.Engine the coordinator depends on.
// It exists to make unit tests fast (no discovery registry, no dedup,
// no classifier) and to keep the coordinator decoupled from the concrete
// engine plumbing in main.go.
type Runner interface {
	RunWithOptions(ctx context.Context, cfg *config.Config, opts engine.RunOptions) (*model.ScanResult, error)
}

// EventType enumerates the kinds of events the coordinator publishes.
type EventType string

const (
	// EventStatus is emitted when a scan transitions between states
	// (queued → running → terminal).
	EventStatus EventType = "status"

	// EventProgress is reserved for per-source progress updates. No
	// producer emits these yet; the type is defined so consumers can
	// switch on it today and receive real values after RFC-0104 phase 4
	// wires engine hooks.
	EventProgress EventType = "progress"

	// EventDone marks the final event for a scan. After it is published
	// the coordinator will no longer emit events for this scan ID.
	EventDone EventType = "done"
)

// Event is a single lifecycle notification for a scan run.
type Event struct {
	At        time.Time        `json:"at"`
	Payload   map[string]any   `json:"payload,omitempty"`
	Type      EventType        `json:"type"`
	Status    model.ScanStatus `json:"status,omitempty"`
	Error     string           `json:"error,omitempty"`
	ScanRunID uuid.UUID        `json:"scan_run_id"`
}

// ActiveRun describes a scan that is currently in flight.
type ActiveRun struct {
	StartedAt time.Time `json:"started_at"`
	ID        uuid.UUID `json:"id"`
}

// StartRequest bundles the inputs to Coordinator.Start.
type StartRequest struct {
	Config        *config.Config
	TriggerSource string
	TriggeredBy   string
}

// AlreadyRunningError carries the ID of the in-flight scan so the handler
// can echo it back to the caller. A sentinel Is() target (ErrAlreadyRunning)
// lets callers use errors.Is for a coarser check when the ID is not needed.
type AlreadyRunningError struct {
	ActiveID uuid.UUID
}

func (e *AlreadyRunningError) Error() string {
	return fmt.Sprintf("a scan is already running (id: %s)", e.ActiveID)
}

// Is reports whether target is the ErrAlreadyRunning sentinel.
func (e *AlreadyRunningError) Is(target error) bool {
	return target == ErrAlreadyRunning
}

// ErrAlreadyRunning is the sentinel value for AlreadyRunningError.Is checks.
var ErrAlreadyRunning = errors.New("scan already running")

// ErrUnknownRun is returned when a caller references an ID that is not the
// current active run (wrong ID supplied, or the scan has already finished).
var ErrUnknownRun = errors.New("unknown or inactive scan run")

// defaultRingBufferSize bounds how many recent events a new subscriber
// replays on Subscribe. The figure is a rough balance between "a client
// reconnecting mid-scan can catch up" and "never hold unbounded memory".
const defaultRingBufferSize = 256

// subscriberChanSize bounds the per-subscriber buffered channel. Slow
// subscribers drop the oldest event rather than stalling the publisher.
const subscriberChanSize = 64

// Coordinator serialises engine invocations and brokers their events.
type Coordinator struct {
	// baseCtx ties the lifetime of all in-flight scans to the owning
	// process. Shutdown cancels it; active goroutines observe ctx.Err()
	// and wind down.
	baseCtx     context.Context
	runner      Runner
	store       store.Store
	logger      *slog.Logger
	baseCancel  context.CancelFunc
	cancelFunc  context.CancelFunc
	activeDone  chan struct{}
	subs        map[int]chan Event
	activeStart time.Time
	ring        []Event
	activeRunID uuid.UUID
	ringCap     int
	subID       int
	mu          sync.Mutex
	ringMu      sync.Mutex
}

// New constructs a Coordinator. baseCtx is inherited by every scan the
// coordinator launches, so cancelling it (via Shutdown) stops in-flight
// work. logger is optional — nil falls back to slog.Default().
func New(runner Runner, st store.Store, baseCtx context.Context, logger *slog.Logger) *Coordinator {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(baseCtx)
	return &Coordinator{
		runner:     runner,
		store:      st,
		logger:     logger,
		baseCtx:    ctx,
		baseCancel: cancel,
		ringCap:    defaultRingBufferSize,
		subs:       make(map[int]chan Event),
	}
}

// Active returns (activeID, activeStart, true) when a scan is in flight
// and (uuid.Nil, zero, false) otherwise.
func (c *Coordinator) Active() (ActiveRun, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeRunID == uuid.Nil {
		return ActiveRun{}, false
	}
	return ActiveRun{ID: c.activeRunID, StartedAt: c.activeStart}, true
}

// Start launches a scan in a detached goroutine and returns the newly
// allocated run ID as soon as the ScanRun row has been persisted. A
// second concurrent call returns *AlreadyRunningError carrying the
// in-flight ID.
func (c *Coordinator) Start(ctx context.Context, req StartRequest) (uuid.UUID, error) {
	if req.Config == nil {
		return uuid.Nil, errors.New("scan: Start requires a non-nil config")
	}

	c.mu.Lock()
	if c.activeRunID != uuid.Nil {
		id := c.activeRunID
		c.mu.Unlock()
		return uuid.Nil, &AlreadyRunningError{ActiveID: id}
	}

	scanID := uuid.Must(uuid.NewV7())
	startedAt := time.Now().UTC()

	// Create the ScanRun row synchronously so GET /api/v1/scans/{id} does
	// not 404 in the window between the 202 response and the goroutine
	// entering engine.Run.
	scopeJSON, _ := json.Marshal(req.Config.Discovery.Sources)
	sourceNames := make([]string, 0, len(req.Config.Discovery.Sources))
	for name := range req.Config.Discovery.Sources {
		sourceNames = append(sourceNames, name)
	}
	sourcesJSON, _ := json.Marshal(sourceNames)

	triggerSource := req.TriggerSource
	if triggerSource == "" {
		triggerSource = "api"
	}

	run := model.ScanRun{
		ID:               scanID,
		StartedAt:        startedAt,
		Status:           model.ScanStatusRunning,
		ScopeConfig:      string(scopeJSON),
		DiscoverySources: string(sourcesJSON),
		TriggerSource:    triggerSource,
		TriggeredBy:      req.TriggeredBy,
	}
	if err := c.store.CreateScanRun(ctx, run); err != nil {
		c.mu.Unlock()
		return uuid.Nil, fmt.Errorf("create scan run: %w", err)
	}

	scanCtx, cancel := context.WithCancel(c.baseCtx)
	done := make(chan struct{})

	c.activeRunID = scanID
	c.activeStart = startedAt
	c.cancelFunc = cancel
	c.activeDone = done
	c.mu.Unlock()

	c.publish(Event{
		ScanRunID: scanID,
		Type:      EventStatus,
		Status:    model.ScanStatusRunning,
		At:        startedAt,
	})

	go c.runScan(scanCtx, cancel, done, scanID, req)

	return scanID, nil
}

// runScan is the goroutine body. It owns the engine invocation, maps the
// outcome to a terminal status, publishes the final event, and clears the
// active-run bookkeeping. The cancel closure is invoked on exit so
// context resources are released even when the engine returned normally.
func (c *Coordinator) runScan(scanCtx context.Context, cancel context.CancelFunc, done chan struct{}, scanID uuid.UUID, req StartRequest) {
	defer close(done)
	defer cancel()
	defer c.clear(scanID)

	opts := engine.RunOptions{
		ScanID:        scanID,
		TriggerSource: req.TriggerSource,
		TriggeredBy:   req.TriggeredBy,
	}

	result, err := c.runner.RunWithOptions(scanCtx, req.Config, opts)

	status := model.ScanStatusCompleted
	switch {
	case err != nil && errors.Is(scanCtx.Err(), context.Canceled):
		// Operator-requested cancellation (either via Cancel or Shutdown).
		status = model.ScanStatusTimedOut
	case err != nil:
		status = model.ScanStatusFailed
	case result != nil && result.Status != "":
		status = model.ScanStatus(result.Status)
	}

	ev := Event{
		ScanRunID: scanID,
		Type:      EventDone,
		Status:    status,
		At:        time.Now().UTC(),
	}
	if err != nil {
		ev.Error = err.Error()
		if errors.Is(err, sqlite.ErrTransientStorageExhausted) {
			c.logger.Warn("scan: engine returned error",
				"scan_id", scanID, "error", err, "status", status,
				"hint", "ensure the DB directory is not on a cloud-sync folder "+
					"(Dropbox/OneDrive/iCloud), is not being scanned by antivirus, "+
					"and is not on a network mount. The kite-collector DB needs "+
					"exclusive local FS access.")
		} else {
			c.logger.Warn("scan: engine returned error",
				"scan_id", scanID, "error", err, "status", status)
		}
	}
	c.publish(ev)
}

// Cancel requests graceful cancellation of the scan identified by id. It
// returns ErrUnknownRun if id does not match the active scan (including
// the empty/no-active case).
func (c *Coordinator) Cancel(id uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeRunID == uuid.Nil || c.activeRunID != id {
		return ErrUnknownRun
	}
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	return nil
}

// Shutdown cancels any in-flight scan and waits up to ctx's deadline for
// the goroutine to finalise. It returns ctx.Err() when the deadline
// elapses before the goroutine exits; callers can still observe the
// final ScanRun row via the store because the goroutine's own persistence
// call uses the engine's original (un-cancelled) context.
func (c *Coordinator) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	cancel := c.cancelFunc
	done := c.activeDone
	c.mu.Unlock()

	// Cancel the base context so any future Start call observes a dead
	// context and the current goroutine's scanCtx is also cancelled.
	c.baseCancel()
	if cancel != nil {
		cancel()
	}

	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("scan: shutdown context elapsed: %w", ctx.Err())
	}
}

// clear releases the active-run fields once the goroutine has finished.
// Runs only for the scan ID that owns the slot — a late clear from a
// previous run is a no-op.
func (c *Coordinator) clear(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeRunID != id {
		return
	}
	c.activeRunID = uuid.Nil
	c.activeStart = time.Time{}
	c.cancelFunc = nil
	c.activeDone = nil
}

// Subscribe registers a subscriber. The returned channel receives events
// starting with any replay from the ring buffer and continuing until
// unsubscribe() is called. Slow readers lose events rather than blocking
// the publisher.
func (c *Coordinator) Subscribe() (<-chan Event, func()) {
	c.ringMu.Lock()
	defer c.ringMu.Unlock()

	id := c.subID
	c.subID++
	ch := make(chan Event, subscriberChanSize)

	// Replay the ring buffer so late subscribers see recent events
	// (the snapshot frame the SSE handler emits).
	for _, ev := range c.ring {
		select {
		case ch <- ev:
		default:
			// Ring too long for this subscriber's buffer; drop rather
			// than block. The live stream will still be delivered.
		}
	}

	c.subs[id] = ch
	unsubscribe := func() {
		c.ringMu.Lock()
		defer c.ringMu.Unlock()
		if existing, ok := c.subs[id]; ok {
			delete(c.subs, id)
			close(existing)
		}
	}
	return ch, unsubscribe
}

// RecentEvents returns a snapshot of the ring buffer. Handlers use this
// instead of Subscribe when they just want to render the current state
// without opening a long-lived stream.
func (c *Coordinator) RecentEvents() []Event {
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	out := make([]Event, len(c.ring))
	copy(out, c.ring)
	return out
}

// publish appends an event to the ring buffer and fans it out to every
// subscriber. Subscribers whose channel buffers are full drop the event
// — never block — so a stuck client cannot wedge the engine goroutine.
func (c *Coordinator) publish(ev Event) {
	c.ringMu.Lock()
	defer c.ringMu.Unlock()

	c.ring = append(c.ring, ev)
	if len(c.ring) > c.ringCap {
		// Keep the tail. Shifting a bounded-size slice is O(n) but n is
		// fixed at ringCap (256) — negligible compared to actual scan
		// work, and we avoid allocating a new backing array.
		copy(c.ring, c.ring[len(c.ring)-c.ringCap:])
		c.ring = c.ring[:c.ringCap]
	}

	for id, ch := range c.subs {
		select {
		case ch <- ev:
		default:
			c.logger.Debug("scan: subscriber dropped event",
				"subscriber", id, "scan_id", ev.ScanRunID, "type", ev.Type)
		}
	}
}
