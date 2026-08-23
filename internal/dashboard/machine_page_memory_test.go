package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

func TestMachinePage_ShowsHumanReadableMemoryWithSparkline(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	id := uuid.Must(uuid.NewV7())
	tags, _ := json.Marshal(map[string]any{"physical_memory_bytes": float64(128 * 1024 * 1024 * 1024)})
	require.NoError(t, st.UpsertMachine(ctx, model.Machine{
		ID: id, Hostname: "boxy", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: "agent", IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		Tags: string(tags), FirstSeenAt: now, LastSeenAt: now,
	}))

	ms, ok := st.(store.MemorySampleStore)
	require.True(t, ok)
	for i := 0; i < 5; i++ {
		require.NoError(t, ms.InsertMemorySample(ctx, model.MemorySample{
			MachineID:   id,
			SampledAt:   now.Add(-time.Duration(5-i) * time.Minute),
			TotalBytes:  128 * 1024 * 1024 * 1024,
			UsedBytes:   uint64(60+i) * 1024 * 1024 * 1024,
			UsedPercent: float64(47 + i),
		}))
	}

	var buf strings.Builder
	require.NoError(t, renderMachinePageFragment(&buf, ctx, st, id, "overview"))
	body := buf.String()

	assert.Contains(t, body, "<h3>Memory</h3>", "the memory card renders")
	assert.Contains(t, body, "128.00 GB", "total RAM is human-readable")
	assert.Contains(t, body, "64.00 GB", "current used is human-readable")
	assert.Contains(t, body, "% used", "the usage percent line renders")
	assert.Contains(t, body, "metric-spark", "the usage sparkline SVG renders")
	assert.Contains(t, body, "<polyline", "the sparkline has a plotted line")
}

func TestMachinePage_MemoryFallsBackToTotalTagWithoutSamples(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	id := uuid.Must(uuid.NewV7())
	tags, _ := json.Marshal(map[string]any{"physical_memory_bytes": "68719476736"}) // 64 GiB as string
	require.NoError(t, st.UpsertMachine(ctx, model.Machine{
		ID: id, Hostname: "no-samples", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: "agent", IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		Tags: string(tags), FirstSeenAt: now, LastSeenAt: now,
	}))

	var buf strings.Builder
	require.NoError(t, renderMachinePageFragment(&buf, ctx, st, id, "overview"))
	body := buf.String()

	assert.Contains(t, body, "<h3>Memory</h3>")
	assert.Contains(t, body, "64.00 GB", "total RAM shown from the tag even with no time series")
	assert.Contains(t, body, "collecting usage", "usage line indicates samples are pending")
	assert.NotContains(t, body, "<polyline", "no sparkline without samples")
}
