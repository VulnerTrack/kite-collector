package memoryseries

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
	"github.com/vulnertrack/kite-collector/internal/telemetry/hostmetrics"
)

func newStoreWithLocalMachine(t *testing.T) (*sqlite.SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/mem.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	// discovery_source "agent" makes resolveLocalMachineID pick this row via
	// its fallback, regardless of the test host's real hostname.
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "seeded-not-this-host", MachineType: model.MachineTypeServer,
		OSFamily: "linux", DiscoverySource: "agent",
		IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

func fakeMem(total, used uint64, pct float64) MemReader {
	return func(context.Context) (hostmetrics.MemStat, error) {
		return hostmetrics.MemStat{Total: total, Used: used, UsedPercent: pct}, nil
	}
}

func TestSampler_SampleOnce_Inserts(t *testing.T) {
	st, id := newStoreWithLocalMachine(t)
	s, ok := New(st, fakeMem(128<<30, 64<<30, 50), 90*24*time.Hour, nil)
	require.True(t, ok, "sqlite store must satisfy MemorySampleStore")

	require.NoError(t, s.SampleOnce(context.Background()))

	got, err := st.ListMemorySamples(context.Background(), id, time.Time{}, 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.EqualValues(t, 128<<30, got[0].TotalBytes)
	assert.EqualValues(t, 64<<30, got[0].UsedBytes)
	assert.EqualValues(t, 50, got[0].UsedPercent)
}

func TestSampler_NoLocalMachine_IsQuietNoOp(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/empty.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	s, ok := New(st, fakeMem(1, 1, 1), 90*24*time.Hour, nil)
	require.True(t, ok)
	// No machines in the store yet (pre-first-scan): a no-op, not an error.
	require.NoError(t, s.SampleOnce(context.Background()))
}

func TestSampler_SampleOnce_PrunesRetentionWindow(t *testing.T) {
	st, id := newStoreWithLocalMachine(t)
	s, ok := New(st, fakeMem(1, 1, 1), 90*24*time.Hour, nil)
	require.True(t, ok)

	fixedNow := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixedNow }

	ctx := context.Background()
	// An old sample (100 days ago) must be pruned; a recent one (10 days ago)
	// must survive alongside the freshly-sampled point.
	require.NoError(t, st.InsertMemorySample(ctx, model.MemorySample{
		MachineID: id, SampledAt: fixedNow.AddDate(0, 0, -100), TotalBytes: 1, UsedBytes: 1, UsedPercent: 1,
	}))
	require.NoError(t, st.InsertMemorySample(ctx, model.MemorySample{
		MachineID: id, SampledAt: fixedNow.AddDate(0, 0, -10), TotalBytes: 1, UsedBytes: 1, UsedPercent: 1,
	}))

	require.NoError(t, s.SampleOnce(ctx))

	got, err := st.ListMemorySamples(ctx, id, time.Time{}, 0)
	require.NoError(t, err)
	assert.Len(t, got, 2, "the 100-day-old sample is pruned; the 10-day-old and the new one remain")
	cutoff := fixedNow.Add(-90 * 24 * time.Hour)
	for _, sample := range got {
		assert.False(t, sample.SampledAt.Before(cutoff))
	}
}
