package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// DurableEmitter decorates an emitter.Emitter with an on-disk overflow buffer,
// turning the previously fire-and-forget OTLP path into at-least-once delivery.
//
// When the wrapped emitter fails to deliver (endpoint down, retries exhausted),
// the events are serialized and spooled to a durable SQLite Queue instead of
// being dropped, and EmitBatch returns nil — the data is safely persisted and
// will be delivered later. A background drain goroutine replays spooled
// payloads through the inner emitter whenever it is reachable, removing each on
// success.
//
// Durability bounds (both configurable):
//   - maxAttempts: a payload the server keeps rejecting (poison / contract
//     violation) is dropped after this many failed drains, so one bad payload
//     cannot block the queue head forever.
//   - the Queue's WithMaxRows cap evicts the oldest rows during a long outage,
//     bounding disk growth (data loss is logged).
//
// At-least-once, not exactly-once: a crash between a successful inner send and
// the queue Remove replays that payload, so the collector may see duplicates.
// The OTLP records carry stable event ids, so downstream dedup is possible.
type DurableEmitter struct {
	inner  emitter.Emitter
	queue  *Queue
	logger *slog.Logger

	route         string
	maxAttempts   int
	drainInterval time.Duration
	drainBatch    int

	mu     sync.Mutex
	cancel context.CancelFunc
	doneCh chan struct{}
	closed bool
}

const (
	durableRoute            = "events"
	defaultDurableMaxRows   = 100_000
	defaultDurableMaxTries  = 50
	defaultDrainInterval    = 15 * time.Second
	defaultDrainBatch       = 256
	durableEmitTimeoutError = "durable emitter is shut down"
)

// DurableOption configures a DurableEmitter.
type DurableOption func(*DurableEmitter)

// WithDrainInterval sets how often the background drain attempts to flush the
// spool to the endpoint.
func WithDrainInterval(d time.Duration) DurableOption {
	return func(e *DurableEmitter) { e.drainInterval = d }
}

// WithMaxAttempts sets how many failed drains a single payload tolerates
// before it is dropped as poison.
func WithMaxAttempts(n int) DurableOption {
	return func(e *DurableEmitter) { e.maxAttempts = n }
}

// NewDurableEmitter wraps inner with a disk-backed overflow buffer stored under
// dataDir (queue.db). Call Start to begin the background drain.
func NewDurableEmitter(ctx context.Context, inner emitter.Emitter, dataDir string, logger *slog.Logger, opts ...DurableOption) (*DurableEmitter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	q, err := NewQueue(ctx, dataDir, logger, WithMaxRows(defaultDurableMaxRows))
	if err != nil {
		return nil, fmt.Errorf("durable emitter: open queue: %w", err)
	}
	e := &DurableEmitter{
		inner:         inner,
		queue:         q,
		logger:        logger,
		route:         durableRoute,
		maxAttempts:   defaultDurableMaxTries,
		drainInterval: defaultDrainInterval,
		drainBatch:    defaultDrainBatch,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Emit sends a single event, spooling on failure. See EmitBatch.
func (e *DurableEmitter) Emit(ctx context.Context, event model.MachineEvent) error {
	return e.EmitBatch(ctx, []model.MachineEvent{event})
}

// EmitBatch tries the inner emitter first. On failure it spools the events to
// the durable queue and returns nil (accepted for later delivery). It returns
// an error only when the data can neither be delivered NOR persisted — the one
// case that is a genuine drop.
func (e *DurableEmitter) EmitBatch(ctx context.Context, events []model.MachineEvent) error {
	if len(events) == 0 {
		return nil
	}

	sendErr := e.inner.EmitBatch(ctx, events)
	if sendErr == nil {
		return nil
	}

	body, marshalErr := json.Marshal(events)
	if marshalErr != nil {
		// Cannot serialize to spool — this is a real drop; surface both causes.
		return fmt.Errorf("durable emitter: send failed (%w) and events could not be spooled: %w", sendErr, marshalErr)
	}
	if enqErr := e.queue.Enqueue(ctx, e.route, body); enqErr != nil {
		e.logger.Error("endpoint unreachable and spool write failed; events dropped",
			"code", string(LogCodeDurableSpoolFailed),
			"count", len(events),
			"send_error", sendErr.Error(),
			"spool_error", enqErr.Error())
		return fmt.Errorf("durable emitter: delivery failed and spool write failed: %w", sendErr)
	}

	e.logger.Warn("endpoint unreachable; events spooled to disk for later delivery",
		"code", string(LogCodeDurableSpooled),
		"count", len(events),
		"send_error", sendErr.Error())
	return nil
}

// Start launches the background drain goroutine. It is not tied to the caller's
// context lifetime beyond cancellation via Shutdown; pass a context whose
// cancellation should also stop the drain (e.g. the agent's root context).
func (e *DurableEmitter) Start(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.cancel != nil {
		return // already started or shut down
	}
	loopCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.doneCh = make(chan struct{})
	go e.drainLoop(loopCtx)
}

func (e *DurableEmitter) drainLoop(ctx context.Context) {
	defer close(e.doneCh)
	// Attempt an immediate drain on start so payloads left over from a previous
	// run are delivered promptly rather than after a full interval.
	e.drainOnce(ctx)

	ticker := time.NewTicker(e.drainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.drainOnce(ctx)
		}
	}
}

// drainOnce flushes as much of the spool as the endpoint will accept in one
// pass: it keeps pulling FIFO batches until the queue is empty or a delivery
// fails (endpoint down), backing off to the next tick on failure. A payload
// that has failed maxAttempts times, or is corrupt, is dropped so it cannot
// block the queue head.
func (e *DurableEmitter) drainOnce(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		items, err := e.queue.Peek(ctx, e.route, e.drainBatch)
		if err != nil {
			e.logger.Warn("durable drain: peek failed",
				"code", string(LogCodeDurableDrainFailed), "error", err)
			return
		}
		if len(items) == 0 {
			return
		}
		progressed := false
		for i := range items {
			if ctx.Err() != nil {
				return
			}
			it := items[i]

			var events []model.MachineEvent
			if err := json.Unmarshal(it.Payload, &events); err != nil {
				// Un-deliverable forever — drop it and move on.
				_ = e.queue.Remove(ctx, it.ID)
				progressed = true
				e.logger.Warn("durable drain: dropped corrupt spooled payload",
					"code", string(LogCodeDurableDroppedCorrupt), "id", it.ID, "error", err)
				continue
			}

			if err := e.inner.EmitBatch(ctx, events); err == nil {
				_ = e.queue.Remove(ctx, it.ID)
				progressed = true
				e.logger.Debug("durable drain: payload delivered",
					"code", string(LogCodeDurableDrained), "id", it.ID, "count", len(events))
				continue
			}

			// Delivery failed. Count the attempt; drop as poison past the bound.
			_ = e.queue.IncrementAttempts(ctx, it.ID)
			if it.Attempts+1 >= e.maxAttempts {
				_ = e.queue.Remove(ctx, it.ID)
				progressed = true
				e.logger.Warn("durable drain: dropped payload after max delivery attempts",
					"code", string(LogCodeDurableDroppedPoison),
					"id", it.ID, "attempts", it.Attempts+1, "count", len(events))
				continue
			}
			// Not yet poison: endpoint is likely still down. Stop this pass and
			// retry the whole backlog on the next tick.
			return
		}
		if !progressed {
			return // safety: never spin without making progress
		}
	}
}

// Depth returns the number of spooled payloads awaiting delivery.
func (e *DurableEmitter) Depth(ctx context.Context) (int, error) {
	return e.queue.Depth(ctx)
}

// Shutdown stops the drain, attempts one final best-effort flush, then shuts
// down the inner emitter and closes the queue. Anything still spooled survives
// to the next process start (the queue is durable).
func (e *DurableEmitter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	cancel := e.cancel
	done := e.doneCh
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	}

	// One last flush attempt so a clean shutdown delivers what it can.
	e.drainOnce(ctx)

	var errs []error
	if err := e.inner.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("inner shutdown: %w", err))
	}
	if err := e.queue.Close(); err != nil {
		errs = append(errs, fmt.Errorf("queue close: %w", err))
	}
	return errors.Join(errs...)
}

// Compile-time check that DurableEmitter satisfies the Emitter contract.
var _ emitter.Emitter = (*DurableEmitter)(nil)
