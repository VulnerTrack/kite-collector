package dashboard

import (
	"context"
	"time"
)

// StreamController is the minimal contract the dashboard uses to toggle the
// OTLP streaming goroutine at runtime. The concrete implementation lives
// outside this package (an adapter around internal/stream / internal/emitter)
// and is wired into Options.StreamController by cmd/kite-collector.
//
// All methods MUST be safe for concurrent use.
type StreamController interface {
	// Start transitions the controller to the "running" state. It is
	// idempotent: calling Start while already running returns nil.
	// It returns a non-nil error only when streaming cannot start (no
	// enrolled identity, transport misconfigured, etc.).
	Start(ctx context.Context) error

	// Stop transitions the controller to "stopped". It is idempotent.
	Stop(ctx context.Context) error

	// Status returns a snapshot of the controller's current state. The
	// zero value of StreamStatus (State == "") MUST be interpreted as
	// "idle" by renderers.
	Status() StreamStatus
}

// StreamStatus is the payload rendered into /fragments/stream-status.
// State takes one of four values — "idle", "running", "degraded",
// "stopped" — mirroring the state machine in RFC-0112 §4.4.
type StreamStatus struct {
	LastEventAt   time.Time
	State         string
	LastErrorText string
	BacklogDepth  int
	TotalSent     int64
}

// NormalizeState defaults an empty State to "idle" so templates can render
// the zero value without a nil check.
func (s StreamStatus) NormalizeState() string {
	if s.State == "" {
		return "idle"
	}
	return s.State
}
