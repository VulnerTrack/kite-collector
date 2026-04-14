package emitter

import (
	"context"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Compile-time interface check.
var _ Emitter = (*NoopEmitter)(nil)

// NoopEmitter silently discards every event. It is used in one-shot mode
// where no downstream consumer is configured.
type NoopEmitter struct{}

// NewNoop returns a ready-to-use NoopEmitter.
func NewNoop() *NoopEmitter { return &NoopEmitter{} }

// Emit is a no-op; it always returns nil.
func (n *NoopEmitter) Emit(_ context.Context, _ model.AssetEvent) error { return nil }

// EmitBatch is a no-op; it always returns nil.
func (n *NoopEmitter) EmitBatch(_ context.Context, _ []model.AssetEvent) error { return nil }

// Shutdown is a no-op; it always returns nil.
func (n *NoopEmitter) Shutdown(_ context.Context) error { return nil }
