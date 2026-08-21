package endpoint

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewQueue_MissingDataDirFails(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	q, err := NewQueue(context.Background(), dir, testLogger())
	require.Error(t, err)
	assert.Nil(t, q)
	assert.Contains(t, err.Error(), "queue database")
}

func TestNewQueue_NilLoggerDefaults(t *testing.T) {
	t.Parallel()

	q, err := NewQueue(context.Background(), t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	require.NoError(t, q.Enqueue(context.Background(), "events", []byte("p")))
}

func TestQueue_PeekRespectsLimitAndFIFO(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	require.NoError(t, q.Enqueue(ctx, "events", []byte("first")))
	require.NoError(t, q.Enqueue(ctx, "events", []byte("second")))
	require.NoError(t, q.Enqueue(ctx, "events", []byte("third")))

	items, err := q.Peek(ctx, "events", 1)
	require.NoError(t, err)
	require.Len(t, items, 1, "limit must bound the batch size")
	assert.Equal(t, []byte("first"), items[0].Payload, "peek must be FIFO")
	assert.Equal(t, "events", items[0].Route)
	assert.Equal(t, 0, items[0].Attempts)

	// Peeking must not consume.
	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, depth)

	// A different route sees nothing.
	other, err := q.Peek(ctx, "no-such-route", 10)
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestQueue_EnqueueUnderCapDoesNotEvict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), testLogger(), WithMaxRows(5))
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	for i := 0; i < 5; i++ {
		require.NoError(t, q.Enqueue(ctx, "events", []byte{byte(i)}))
	}
	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, depth, "reaching the cap exactly must not evict anything")

	items, err := q.Peek(ctx, "events", 10)
	require.NoError(t, err)
	require.Len(t, items, 5)
	assert.Equal(t, []byte{0}, items[0].Payload, "the oldest payload must survive at the cap")
}

func TestQueue_RemoveUnknownIDIsNoOp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	require.NoError(t, q.Enqueue(ctx, "events", []byte("keep")))
	require.NoError(t, q.Remove(ctx, "no-such-id"))

	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, depth, "removing an unknown id must not touch other rows")
}

func TestQueue_OperationsAfterCloseFail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q, err := NewQueue(ctx, t.TempDir(), testLogger(), WithMaxRows(1))
	require.NoError(t, err)
	require.NoError(t, q.Enqueue(ctx, "events", []byte("p")))
	require.NoError(t, q.Close())

	err = q.Enqueue(ctx, "events", []byte("late"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enqueue: ")

	_, err = q.Peek(ctx, "events", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "peek queue: ")

	_, err = q.Depth(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query queue depth: ")

	err = q.Remove(ctx, "some-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove queue item some-id: ")

	err = q.IncrementAttempts(ctx, "some-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "increment attempts some-id: ")

	// The capacity check must degrade to a logged warning, never a panic.
	assert.NotPanics(t, func() { q.enforceCapacity(ctx) })
}
