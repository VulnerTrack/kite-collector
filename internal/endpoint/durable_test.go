package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// fakeEmitter is a controllable inner emitter: it fails while `down` is true
// and records everything it accepts.
type fakeEmitter struct {
	mu       sync.Mutex
	down     bool
	rejectID uuid.UUID // if set, always reject batches containing this event id (poison)
	accepted [][]model.MachineEvent
	shutdown bool
}

func (f *fakeEmitter) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeEmitter) EmitBatch(_ context.Context, events []model.MachineEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("fake: endpoint down")
	}
	if f.rejectID != uuid.Nil {
		for _, e := range events {
			if e.ID == f.rejectID {
				return errors.New("fake: poison payload rejected")
			}
		}
	}
	f.accepted = append(f.accepted, events)
	return nil
}

func (f *fakeEmitter) Emit(ctx context.Context, event model.MachineEvent) error {
	return f.EmitBatch(ctx, []model.MachineEvent{event})
}

func (f *fakeEmitter) Shutdown(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdown = true
	return nil
}

func (f *fakeEmitter) acceptedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.accepted {
		n += len(b)
	}
	return n
}

func newEvent() model.MachineEvent {
	return model.MachineEvent{ID: uuid.Must(uuid.NewV7()), MachineID: uuid.Must(uuid.NewV7())}
}

// TestDurable_SpoolsWhenDownDeliversWhenUp is the core at-least-once guarantee:
// events emitted while the endpoint is down are persisted (EmitBatch returns
// nil, not an error), then delivered by the drain once the endpoint recovers.
func TestDurable_SpoolsWhenDownDeliversWhenUp(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{down: true}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), nil,
		WithDrainInterval(50*time.Millisecond))
	require.NoError(t, err)
	de.Start(ctx)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	// Endpoint down: three emits must be accepted (nil) and spooled.
	for i := 0; i < 3; i++ {
		require.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{newEvent()}),
			"emit while down must succeed by spooling, not error")
	}
	depth, err := de.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, depth, "all three payloads must be spooled while down")
	assert.Equal(t, 0, fake.acceptedCount(), "nothing delivered while down")

	// Endpoint recovers: the drain must flush the spool.
	fake.setDown(false)
	require.Eventually(t, func() bool {
		d, _ := de.Depth(ctx)
		return d == 0
	}, 3*time.Second, 25*time.Millisecond, "spool must drain after recovery")
	assert.Equal(t, 3, fake.acceptedCount(), "all spooled payloads must be delivered")
}

// TestDurable_PassThroughWhenHealthy: when the endpoint is up, EmitBatch goes
// straight through and nothing is spooled.
func TestDurable_PassThroughWhenHealthy(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEmitter{}
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	require.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{newEvent(), newEvent()}))
	depth, err := de.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, depth, "healthy emit must not spool")
	assert.Equal(t, 2, fake.acceptedCount())
}

// TestDurable_DropsPoisonAfterMaxAttempts: a payload the endpoint keeps
// rejecting (while OTHER traffic would succeed) is dropped after maxAttempts so
// it cannot block the queue head forever.
func TestDurable_DropsPoisonAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()
	poison := newEvent()
	fake := &fakeEmitter{rejectID: poison.ID} // up, but rejects this one event
	de, err := NewDurableEmitter(ctx, fake, t.TempDir(), nil,
		WithDrainInterval(20*time.Millisecond),
		WithMaxAttempts(3))
	require.NoError(t, err)
	de.Start(ctx)
	t.Cleanup(func() { _ = de.Shutdown(context.Background()) })

	// The inner rejects it immediately, so EmitBatch spools it.
	require.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{poison}))
	require.Equal(t, 1, mustDepth(t, de))

	// After maxAttempts failed drains it must be dropped, unblocking the queue.
	require.Eventually(t, func() bool {
		return mustDepth(t, de) == 0
	}, 3*time.Second, 20*time.Millisecond, "poison payload must be dropped after max attempts")
}

// TestDurable_ShutdownFlushesThenPersists: on shutdown a final drain runs; what
// still cannot be delivered survives in the durable queue for the next start.
func TestDurable_ShutdownPersistsUndelivered(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	fake := &fakeEmitter{down: true}
	de, err := NewDurableEmitter(ctx, fake, dir, nil, WithDrainInterval(time.Hour))
	require.NoError(t, err)
	de.Start(ctx)
	require.NoError(t, de.EmitBatch(ctx, []model.MachineEvent{newEvent(), newEvent()}))
	require.NoError(t, de.Shutdown(ctx)) // endpoint still down: nothing delivered

	// Reopen the same dir: the spooled payloads must still be there and now
	// deliverable to a healthy endpoint.
	fake2 := &fakeEmitter{}
	de2, err := NewDurableEmitter(ctx, fake2, dir, nil, WithDrainInterval(30*time.Millisecond))
	require.NoError(t, err)
	de2.Start(ctx)
	t.Cleanup(func() { _ = de2.Shutdown(context.Background()) })

	require.Eventually(t, func() bool {
		return mustDepth(t, de2) == 0
	}, 3*time.Second, 25*time.Millisecond, "undelivered spool must survive restart and drain")
	assert.Equal(t, 2, fake2.acceptedCount())
}

func mustDepth(t *testing.T, de *DurableEmitter) int {
	t.Helper()
	d, err := de.Depth(context.Background())
	require.NoError(t, err)
	return d
}

// --- queue enhancement unit tests ---

func TestQueue_IncrementAttempts(t *testing.T) {
	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	require.NoError(t, q.Enqueue(ctx, "events", []byte("p")))
	items, err := q.Peek(ctx, "events", 10)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, 0, items[0].Attempts)

	require.NoError(t, q.IncrementAttempts(ctx, items[0].ID))
	require.NoError(t, q.IncrementAttempts(ctx, items[0].ID))
	items, err = q.Peek(ctx, "events", 10)
	require.NoError(t, err)
	assert.Equal(t, 2, items[0].Attempts, "attempts must be tracked, not stuck at 0")
}

func TestQueue_MaxRowsEvictsOldest(t *testing.T) {
	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), nil, WithMaxRows(5))
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	for i := 0; i < 20; i++ {
		require.NoError(t, q.Enqueue(ctx, "events", []byte{byte(i)}))
	}
	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, depth, "queue must be capped at max_rows")

	// The survivors must be the NEWEST five (FIFO eviction of the oldest).
	items, err := q.Peek(ctx, "events", 10)
	require.NoError(t, err)
	require.Len(t, items, 5)
	assert.Equal(t, []byte{15}, items[0].Payload, "oldest survivor should be payload 15")
	assert.Equal(t, []byte{19}, items[4].Payload, "newest should be payload 19")
}
