//go:build e2e

package e2e

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

// TestPostgresStoreLifecycle exercises the full PostgreSQL store lifecycle:
// upsert assets -> upsert software -> insert events -> create/complete scan
// run -> list/filter assets -> get stale assets.
func TestPostgresStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	now := time.Now().UTC().Truncate(time.Millisecond)

	// ---- Upsert assets ----
	assets := []model.Asset{
		makeAsset("e2e-srv-01", model.AssetTypeServer, now),
		makeAsset("e2e-ws-01", model.AssetTypeWorkstation, now),
		makeAsset("e2e-cloud-01", model.AssetTypeCloudInstance, now),
	}

	inserted, updated, err := st.UpsertAssets(ctx, assets)
	require.NoError(t, err)
	assert.Equal(t, 3, inserted)
	assert.Equal(t, 0, updated)

	// Re-upsert with updated fields — should count as updates.
	assets[0].OSVersion = "6.2"
	assets[0].LastSeenAt = now.Add(time.Minute)
	inserted, updated, err = st.UpsertAssets(ctx, assets)
	require.NoError(t, err)
	assert.Equal(t, 0, inserted)
	assert.Equal(t, 3, updated)

	// ---- Upsert software ----
	software := []model.InstalledSoftware{
		{
			ID:             uuid.Must(uuid.NewV7()),
			AssetID:        assets[0].ID,
			SoftwareName:   "falcon-sensor",
			Vendor:         "CrowdStrike",
			Version:        "7.0.0",
			CPE23:          "cpe:2.3:a:crowdstrike:falcon:7.0.0:*:*:*:*:*:*:*",
			PackageManager: "deb",
		},
		{
			ID:             uuid.Must(uuid.NewV7()),
			AssetID:        assets[0].ID,
			SoftwareName:   "osquery",
			Vendor:         "Meta",
			Version:        "5.11.0",
			PackageManager: "deb",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, assets[0].ID, software))

	listedSW, err := st.ListSoftware(ctx, assets[0].ID)
	require.NoError(t, err)
	assert.Len(t, listedSW, 2)

	// ---- Create scan run ----
	scanRunID := uuid.Must(uuid.NewV7())
	scanRun := model.ScanRun{
		ID:               scanRunID,
		StartedAt:        now,
		Status:           model.ScanStatusRunning,
		ScopeConfig:      `{"subnets":["10.0.0.0/24"]}`,
		DiscoverySources: `["e2e"]`,
	}
	require.NoError(t, st.CreateScanRun(ctx, scanRun))

	// ---- Insert events ----
	events := []model.AssetEvent{
		makeEvent(assets[0].ID, scanRunID, model.EventAssetDiscovered, now),
		makeEvent(assets[1].ID, scanRunID, model.EventAssetDiscovered, now),
		makeEvent(assets[2].ID, scanRunID, model.EventAssetDiscovered, now),
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	// ---- Complete scan run ----
	result := model.ScanResult{
		TotalAssets:     3,
		NewAssets:       3,
		UpdatedAssets:   0,
		StaleAssets:     0,
		EventsEmitted:   3,
		CoveragePercent: 100.0,
	}
	require.NoError(t, st.CompleteScanRun(ctx, scanRunID, result))

	latest, err := st.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.Equal(t, 3, latest.TotalAssets)
	assert.NotNil(t, latest.CompletedAt)

	// ---- List/filter assets ----
	all, err := st.ListAssets(ctx, store.AssetFilter{Limit: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3)

	cloudOnly, err := st.ListAssets(ctx, store.AssetFilter{
		AssetType: string(model.AssetTypeCloudInstance),
		Limit:     100,
	})
	require.NoError(t, err)
	for _, a := range cloudOnly {
		assert.Equal(t, model.AssetTypeCloudInstance, a.AssetType)
	}

	// ---- List events with filter ----
	evByAsset, err := st.ListEvents(ctx, store.EventFilter{
		AssetID: &assets[0].ID,
		Limit:   100,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, evByAsset)
	for _, e := range evByAsset {
		assert.Equal(t, assets[0].ID, e.AssetID)
	}

	// ---- Stale assets ----
	staleAsset := makeAsset("e2e-stale-host", model.AssetTypeServer, now.Add(-72*time.Hour))
	_, _, err = st.UpsertAssets(ctx, []model.Asset{staleAsset})
	require.NoError(t, err)

	stale, err := st.GetStaleAssets(ctx, 24*time.Hour)
	require.NoError(t, err)
	staleNames := make(map[string]bool)
	for _, a := range stale {
		staleNames[a.Hostname] = true
	}
	assert.True(t, staleNames["e2e-stale-host"], "stale asset should appear")
}

// TestPostgresUpsertIdempotent verifies that upserting the same asset twice
// does not duplicate it.
func TestPostgresUpsertIdempotent(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	now := time.Now().UTC().Truncate(time.Millisecond)
	asset := makeAsset("e2e-idempotent", model.AssetTypeServer, now)

	require.NoError(t, st.UpsertAsset(ctx, asset))
	require.NoError(t, st.UpsertAsset(ctx, asset))

	listed, err := st.ListAssets(ctx, store.AssetFilter{
		Hostname: "e2e-idempotent",
		Limit:    10,
	})
	require.NoError(t, err)
	assert.Len(t, listed, 1, "duplicate upsert should not create a second row")
}

// TestPostgresSoftwareReplacement verifies that UpsertSoftware fully replaces
// the previous software set.
func TestPostgresSoftwareReplacement(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	now := time.Now().UTC().Truncate(time.Millisecond)
	asset := makeAsset("e2e-sw-replace", model.AssetTypeServer, now)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	// Initial set.
	initial := []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), AssetID: asset.ID, SoftwareName: "old-agent", Vendor: "Old", Version: "1.0"},
	}
	require.NoError(t, st.UpsertSoftware(ctx, asset.ID, initial))

	listed, err := st.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 1)

	// Replace entirely.
	replacement := []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), AssetID: asset.ID, SoftwareName: "new-edr", Vendor: "New", Version: "2.0"},
		{ID: uuid.Must(uuid.NewV7()), AssetID: asset.ID, SoftwareName: "config-mgmt", Vendor: "New", Version: "3.0"},
	}
	require.NoError(t, st.UpsertSoftware(ctx, asset.ID, replacement))

	listed, err = st.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	names := map[string]bool{}
	for _, sw := range listed {
		names[sw.SoftwareName] = true
	}
	assert.False(t, names["old-agent"], "old software should be gone")
	assert.True(t, names["new-edr"])
	assert.True(t, names["config-mgmt"])
}
