package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// stubEmitter is a minimal inner emitter with a scriptable Shutdown error.
type stubEmitter struct {
	shutdownErr error
}

func (s *stubEmitter) Emit(context.Context, model.MachineEvent) error        { return nil }
func (s *stubEmitter) EmitBatch(context.Context, []model.MachineEvent) error { return nil }
func (s *stubEmitter) Shutdown(context.Context) error                        { return s.shutdownErr }

func TestDurable_EmitSingleEventPassesThrough(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	require.NoError(t, de.Emit(ctx, newEvent()))
	assert.Equal(t, 1, fake.acceptedCount())
	assert.Equal(t, 0, mustDepth(t, de))
}

func TestDurable_EmitBatchEmptyIsNoOp(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{down: true} // would spool if the inner were consulted
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	require.NoError(t, de.EmitBatch(ctx, nil))
	require.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{}))
	assert.Equal(t, 0, mustDepth(t, de), "empty batches must not touch the spool")
	assert.Equal(t, 0, fake.acceptedCount())
}

func TestDurable_SpoolWriteFailureSurfacesError(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{down: true}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger())
	require.NoError(t, err)

	// Sabotage the spool: with the endpoint down AND the queue broken, the
	// data genuinely cannot be preserved — the one case that must error.
	require.NoError(t, de.queue.Close())

	err = de.EmitBatch(ctx, []model.MachineEvent{newEvent()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delivery failed and spool write failed")
}

func TestDurable_DrainDropsCorruptPayload(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	require.NoError(t, de.queue.Enqueue(ctx, durableRoute, []byte("{corrupt json")))
	require.Equal(t, 1, mustDepth(t, de))

	de.drainOnce(ctx)

	assert.Equal(t, 0, mustDepth(t, de), "a corrupt payload must be dropped, not retried forever")
	assert.Equal(t, 0, fake.acceptedCount(), "corrupt payloads must never reach the inner emitter")
}

func TestDurable_DrainOncePeekFailureReturns(t *testing.T) {
	ctx := context.Background()
	de, err := NewDurableEmitter(ctx, &fakeEmitter{}, t.TempDir(), testLogger())
	require.NoError(t, err)
	require.NoError(t, de.queue.Close())

	assert.NotPanics(t, func() { de.drainOnce(ctx) },
		"a broken spool must degrade to a logged warning")
}

func TestDurable_DrainOnceHonorsCanceledContext(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	require.NoError(t, de.queue.Enqueue(ctx, durableRoute, []byte("[]")))

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	de.drainOnce(canceled)

	assert.Equal(t, 1, mustDepth(t, de), "a canceled drain must leave the spool untouched")
	assert.Equal(t, 0, fake.acceptedCount())
}

func TestDurable_StartIsIdempotent(t *testing.T) {
	ctx := context.Background()
	de, err := NewDurableEmitter(ctx, &fakeEmitter{}, t.TempDir(), testLogger(),
		WithDrainInterval(time.Hour))
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	de.Start(ctx)
	de.mu.Lock()
	firstDone := de.doneCh
	de.mu.Unlock()
	require.NotNil(t, firstDone)

	de.Start(ctx) // second start must be a no-op
	de.mu.Lock()
	secondDone := de.doneCh
	de.mu.Unlock()
	assert.Equal(t, firstDone, secondDone, "a second Start must not spawn another drain loop")
}

func TestDurable_StartAfterShutdownIsNoOp(t *testing.T) {
	ctx := context.Background()
	de, err := NewDurableEmitter(ctx, &fakeEmitter{}, t.TempDir(), testLogger())
	require.NoError(t, err)

	require.NoError(t, de.Shutdown(ctx)) // never started: cancel and doneCh are nil
	de.Start(ctx)

	de.mu.Lock()
	defer de.mu.Unlock()
	assert.Nil(t, de.cancel, "Start after Shutdown must not launch a drain loop")
	assert.Nil(t, de.doneCh)
}

func TestDurable_ShutdownTwiceIsSafe(t *testing.T) {
	ctx := context.Background()
	de, err := NewDurableEmitter(ctx, &fakeEmitter{}, t.TempDir(), testLogger(),
		WithDrainInterval(time.Hour))
	require.NoError(t, err)
	de.Start(ctx)

	require.NoError(t, de.Shutdown(ctx))
	require.NoError(t, de.Shutdown(ctx), "a second Shutdown must be a silent no-op")
}

func TestDurable_ShutdownPropagatesInnerError(t *testing.T) {
	ctx := context.Background()
	inner := &stubEmitter{shutdownErr: errors.New("otlp flush failed")}
	de, err := NewDurableEmitter(ctx, inner, t.TempDir(), testLogger())
	require.NoError(t, err)

	err = de.Shutdown(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inner shutdown: ")
	assert.Contains(t, err.Error(), "otlp flush failed")
}

// TestDurable_ConcurrentEmitWhileDown stresses the claimed concurrency
// safety: many goroutines spool at once while the endpoint is down, every
// event must be preserved exactly once, then the drain must deliver all of
// them. Run with -race.
func TestDurable_ConcurrentEmitWhileDown(t *testing.T) {
	const goroutines = 16
	const perGoroutine = 8

	ctx := context.Background()
	fake := &fakeEmitter{down: true}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), testLogger(),
		WithDrainInterval(25*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				assert.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{newEvent()}))
			}
		}()
	}
	wg.Wait()

	require.Equal(t, goroutines*perGoroutine, mustDepth(t, de),
		"every concurrent emit must be spooled exactly once")

	fake.setDown(false)
	de.Start(ctx)
	require.Eventually(t, func() bool { return mustDepth(t, de) == 0 },
		5*time.Second, 25*time.Millisecond, "the drain must flush the whole backlog")
	assert.Equal(t, goroutines*perGoroutine, fake.acceptedCount())
}
