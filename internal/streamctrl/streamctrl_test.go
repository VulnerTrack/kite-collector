package streamctrl

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// recordingEmitter counts calls so we can verify gating.
type recordingEmitter struct {
	err    error
	single int
	batch  int
}

func (r *recordingEmitter) Emit(_ context.Context, _ model.AssetEvent) error {
	r.single++
	return r.err
}

func (r *recordingEmitter) EmitBatch(_ context.Context, events []model.AssetEvent) error {
	r.batch += len(events)
	return r.err
}

func (r *recordingEmitter) Shutdown(_ context.Context) error { return nil }

func TestController_DefaultIdle_DropsEmits(t *testing.T) {
	rec := &recordingEmitter{}
	c := New(rec)
	require.Equal(t, StateIdle, c.Status().State)

	require.NoError(t, c.Emit(context.Background(), model.AssetEvent{}))
	require.NoError(t, c.EmitBatch(context.Background(), []model.AssetEvent{{}, {}}))
	assert.Equal(t, 0, rec.single, "idle: single emit must not forward")
	assert.Equal(t, 0, rec.batch, "idle: batch emit must not forward")
	assert.Equal(t, int64(0), c.Status().TotalSent)
}

func TestController_StartForwardsThenStopDrops(t *testing.T) {
	rec := &recordingEmitter{}
	c := New(rec)
	require.NoError(t, c.Start(context.Background()))

	require.NoError(t, c.Emit(context.Background(), model.AssetEvent{}))
	require.NoError(t, c.EmitBatch(context.Background(), []model.AssetEvent{{}, {}, {}}))
	assert.Equal(t, 1, rec.single)
	assert.Equal(t, 3, rec.batch)
	status := c.Status()
	assert.Equal(t, StateRunning, status.State)
	assert.Equal(t, int64(4), status.TotalSent, "total sent counts 1 single + 3 batch")
	assert.False(t, status.LastEventAt.IsZero())

	require.NoError(t, c.Stop(context.Background()))
	require.NoError(t, c.Emit(context.Background(), model.AssetEvent{}))
	assert.Equal(t, 1, rec.single, "stopped: new emit must not forward")
	assert.Equal(t, StateStopped, c.Status().State)
}

func TestController_EmitErrorMarksDegraded(t *testing.T) {
	rec := &recordingEmitter{err: errors.New("boom")}
	c := New(rec)
	require.NoError(t, c.Start(context.Background()))
	_ = c.Emit(context.Background(), model.AssetEvent{})
	status := c.Status()
	assert.Equal(t, StateDegraded, status.State)
	assert.Equal(t, "boom", status.LastErrorText)
}

func TestController_NilInner_NoopFallback(t *testing.T) {
	c := New(nil)
	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Emit(context.Background(), model.AssetEvent{}))
	assert.Equal(t, int64(1), c.Status().TotalSent)
}

func TestController_NoopEmitter_Shutdown(t *testing.T) {
	c := New(emitter.NewNoop())
	require.NoError(t, c.Shutdown(context.Background()))
}
