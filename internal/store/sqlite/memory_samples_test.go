package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

func newMemoryTestStore(t *testing.T) (*SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := New(t.TempDir() + "/mem.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "mem-host", MachineType: model.MachineTypeServer,
		OSFamily: "linux", DiscoverySource: "agent",
		IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

func TestMemorySamples_RoundTripAndOrder(t *testing.T) {
	st, machineID := newMemoryTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	// Insert out of order to prove ListMemorySamples returns oldest-first.
	for _, off := range []int{2, 0, 1} {
		require.NoError(t, st.InsertMemorySample(ctx, model.MemorySample{
			MachineID:   machineID,
			SampledAt:   base.Add(time.Duration(off) * time.Minute),
			TotalBytes:  128 * 1024 * 1024 * 1024,
			UsedBytes:   uint64(off+1) * 1024 * 1024 * 1024,
			UsedPercent: float64(off + 1),
		}))
	}

	got, err := st.ListMemorySamples(ctx, machineID, base.Add(-time.Hour), 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.True(t, got[0].SampledAt.Before(got[1].SampledAt) && got[1].SampledAt.Before(got[2].SampledAt),
		"samples come back oldest-first")
	assert.EqualValues(t, 128*1024*1024*1024, got[0].TotalBytes)
	assert.NotEqual(t, uuid.Nil, got[0].ID, "a zero ID is filled with a UUIDv7 on insert")

	// `since` filters.
	fromMinuteTwo, err := st.ListMemorySamples(ctx, machineID, base.Add(2*time.Minute), 0)
	require.NoError(t, err)
	assert.Len(t, fromMinuteTwo, 1)

	// limit caps.
	limited, err := st.ListMemorySamples(ctx, machineID, base.Add(-time.Hour), 2)
	require.NoError(t, err)
	assert.Len(t, limited, 2)
}

func TestMemorySamples_PruneRetention(t *testing.T) {
	st, machineID := newMemoryTestStore(t)
	ctx := context.Background()

	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	// One sample per day going back 100 days.
	for d := 0; d < 100; d++ {
		require.NoError(t, st.InsertMemorySample(ctx, model.MemorySample{
			MachineID: machineID, SampledAt: now.AddDate(0, 0, -d),
			TotalBytes: 1, UsedBytes: 1, UsedPercent: 1,
		}))
	}

	// 90-day retention: drop everything older than now-90d.
	cutoff := now.AddDate(0, 0, -90)
	deleted, err := st.PruneMemorySamplesBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.EqualValues(t, 9, deleted, "days 91..99 (9 samples) are older than the 90-day window")

	remaining, err := st.ListMemorySamples(ctx, machineID, time.Time{}, 0)
	require.NoError(t, err)
	assert.Len(t, remaining, 91, "days 0..90 inclusive survive")
	for _, s := range remaining {
		assert.False(t, s.SampledAt.Before(cutoff), "no sample older than the cutoff remains")
	}
}

// Compile-time confirmation the SQLite store satisfies the optional interface.
var _ store.MemorySampleStore = (*SQLiteStore)(nil)
