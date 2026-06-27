// Package streamctrl implements the dashboard-facing StreamController
// contract. It wraps an emitter.Emitter and gates Emit/EmitBatch on an
// atomic flag so operators can pause OTLP streaming from the RFC-0112
// onboarding UI without restarting the binary.
//
// The controller is deliberately minimal: Start/Stop flips a flag,
// Status returns a snapshot of counters the Emit calls update. Scanning
// itself is orthogonal — only the external emission is gated.
package streamctrl

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// State values surfaced by Status(). These match the dashboard renderer
// expectations so the badge colour stays stable.
const (
	StateIdle     = "idle"
	StateRunning  = "running"
	StateStopped  = "stopped"
	StateDegraded = "degraded"
)

// Controller is the concrete StreamController implementation.
//
// It embeds an emitter.Emitter and forwards Emit/EmitBatch only while
// running. Start/Stop are idempotent and safe for concurrent use.
type Controller struct {
	inner         emitter.Emitter
	lastEventAt   time.Time
	state         string
	lastErr       string
	backlogDepth  int64
	totalSent     atomic.Int64
	runningActive atomic.Bool
	mu            sync.Mutex
}

// New wraps inner with a start/stop-able gate. The initial state is
// "idle"; call Start to begin forwarding events.
func New(inner emitter.Emitter) *Controller {
	if inner == nil {
		inner = emitter.NewNoop()
	}
	return &Controller{inner: inner, state: StateIdle}
}

// Start transitions to running. It is idempotent and never returns an
// error for this minimal adapter.
func (c *Controller) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateRunning
	c.lastErr = ""
	c.runningActive.Store(true)
	return nil
}

// Stop transitions to stopped. Pending events already passed to Emit
// before Stop return normally; new Emit calls become no-ops.
func (c *Controller) Stop(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateStopped
	c.runningActive.Store(false)
	return nil
}

// Emit forwards event only while running. When stopped it drops the
// event silently so the caller's scan logic is not penalised.
func (c *Controller) Emit(ctx context.Context, event model.AssetEvent) error {
	if !c.runningActive.Load() {
		return nil
	}
	err := c.inner.Emit(ctx, event)
	c.recordEmit(1, err)
	if err != nil {
		return fmt.Errorf("streamctrl emit: %w", err)
	}
	return nil
}

// EmitBatch forwards the batch only while running.
func (c *Controller) EmitBatch(ctx context.Context, events []model.AssetEvent) error {
	if !c.runningActive.Load() {
		return nil
	}
	err := c.inner.EmitBatch(ctx, events)
	c.recordEmit(int64(len(events)), err)
	if err != nil {
		return fmt.Errorf("streamctrl emit batch: %w", err)
	}
	return nil
}

// Shutdown forwards to the inner emitter. It does NOT flip state —
// the process is exiting anyway.
func (c *Controller) Shutdown(ctx context.Context) error {
	if err := c.inner.Shutdown(ctx); err != nil {
		return fmt.Errorf("streamctrl shutdown: %w", err)
	}
	return nil
}

func (c *Controller) recordEmit(n int64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.state = StateDegraded
		c.lastErr = err.Error()
		return
	}
	c.totalSent.Add(n)
	c.lastEventAt = time.Now().UTC()
	if c.state == StateDegraded {
		c.state = StateRunning
		c.lastErr = ""
	}
}

// Status returns a snapshot for the dashboard renderer. The returned
// struct matches dashboard.StreamStatus exactly.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{
		State:         c.state,
		LastEventAt:   c.lastEventAt,
		LastErrorText: c.lastErr,
		BacklogDepth:  int(c.backlogDepth),
		TotalSent:     c.totalSent.Load(),
	}
}

// Status mirrors dashboard.StreamStatus. Kept in this package so the
// emitter layer does not import dashboard.
type Status struct {
	LastEventAt   time.Time
	State         string
	LastErrorText string
	BacklogDepth  int
	TotalSent     int64
}
