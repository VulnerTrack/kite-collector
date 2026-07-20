package emitter

import (
	"context"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Emitter sends machine lifecycle events to an external sink.
type Emitter interface {
	// Emit sends a single event.
	Emit(ctx context.Context, event model.MachineEvent) error
	// EmitBatch sends multiple events in one call.
	EmitBatch(ctx context.Context, events []model.MachineEvent) error
	// Shutdown flushes pending events and releases resources.
	Shutdown(ctx context.Context) error
}
