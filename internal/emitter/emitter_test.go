package emitter

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestNoopEmitter_Emit_ReturnsNil(t *testing.T) {
	n := NewNoop()
	err := n.Emit(context.Background(), model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
	})
	assert.NoError(t, err)
}

func TestNoopEmitter_EmitBatch_ReturnsNil(t *testing.T) {
	n := NewNoop()
	events := []model.MachineEvent{
		{ID: uuid.Must(uuid.NewV7()), EventType: model.EventMachineDiscovered},
		{ID: uuid.Must(uuid.NewV7()), EventType: model.EventMachineUpdated},
	}
	err := n.EmitBatch(context.Background(), events)
	assert.NoError(t, err)
}

func TestNoopEmitter_Shutdown_ReturnsNil(t *testing.T) {
	n := NewNoop()
	err := n.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestNoopEmitter_ImplementsInterface(t *testing.T) {
	var _ Emitter = (*NoopEmitter)(nil)
}
