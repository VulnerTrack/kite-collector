package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// helper opens a new SQLite store in a temp dir and runs Migrate.
func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "kite_test.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, s.Migrate(context.Background()))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeAsset(hostname string, assetType model.AssetType) model.Asset {
	now := time.Now().UTC().Truncate(time.Second)
	a := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       assetType,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		DiscoverySource: "test",
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
	a.ComputeNaturalKey()
	return a
}

// ---------------------------------------------------------------------------
// Migrate
// ---------------------------------------------------------------------------

func TestMigrate_CreatesTablesSuccessfully(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate_test.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	err = s.Migrate(context.Background())
	require.NoError(t, err, "first migration must succeed")

	// Running Migrate again is idempotent (CREATE IF NOT EXISTS)
	err = s.Migrate(context.Background())
	require.NoError(t, err, "second migration must also succeed")
}

// ---------------------------------------------------------------------------
// UpsertAsset + GetAssetByNaturalKey round-trip
// ---------------------------------------------------------------------------

func TestUpsertAsset_AndGetByNaturalKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("web-01", model.AssetTypeServer)
	asset.OSFamily = "linux"
	asset.Environment = "production"

	require.NoError(t, s.UpsertAsset(ctx, asset))

	// Re-compute the key to look it up the same way the store does.
	asset.ComputeNaturalKey()
	got, err := s.GetAssetByNaturalKey(ctx, asset.NaturalKey)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, asset.ID, got.ID)
	assert.Equal(t, asset.Hostname, got.Hostname)
	assert.Equal(t, asset.AssetType, got.AssetType)
	assert.Equal(t, "linux", got.OSFamily)
	assert.Equal(t, "production", got.Environment)
}

func TestGetAssetByNaturalKey_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.GetAssetByNaturalKey(ctx, "nonexistent-key")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// UpsertAssets (batch)
// ---------------------------------------------------------------------------

func TestUpsertAssets_MultipleBatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	assets := []model.Asset{
		makeAsset("batch-01", model.AssetTypeServer),
		makeAsset("batch-02", model.AssetTypeWorkstation),
		makeAsset("batch-03", model.AssetTypeContainer),
	}

	inserted, updated, err := s.UpsertAssets(ctx, assets)
	require.NoError(t, err)
	assert.Equal(t, 3, inserted)
	assert.Equal(t, 0, updated)

	// Upserting the same batch again should count as updates.
	inserted2, updated2, err := s.UpsertAssets(ctx, assets)
	require.NoError(t, err)
	assert.Equal(t, 0, inserted2)
	assert.Equal(t, 3, updated2)
}

// ---------------------------------------------------------------------------
// ListAssets
// ---------------------------------------------------------------------------

func TestListAssets_NoFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertAsset(ctx, makeAsset("a", model.AssetTypeServer)))
	require.NoError(t, s.UpsertAsset(ctx, makeAsset("b", model.AssetTypeWorkstation)))

	all, err := s.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestListAssets_FilterByAssetType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertAsset(ctx, makeAsset("s1", model.AssetTypeServer)))
	require.NoError(t, s.UpsertAsset(ctx, makeAsset("w1", model.AssetTypeWorkstation)))

	servers, err := s.ListAssets(ctx, store.AssetFilter{AssetType: string(model.AssetTypeServer)})
	require.NoError(t, err)
	assert.Len(t, servers, 1)
	assert.Equal(t, "s1", servers[0].Hostname)
}

func TestListAssets_FilterByHostname(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertAsset(ctx, makeAsset("specific-host", model.AssetTypeServer)))
	require.NoError(t, s.UpsertAsset(ctx, makeAsset("other-host", model.AssetTypeServer)))

	results, err := s.ListAssets(ctx, store.AssetFilter{Hostname: "specific-host"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "specific-host", results[0].Hostname)
}

func TestListAssets_LimitAndOffset(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a := makeAsset("host-"+string(rune('a'+i)), model.AssetTypeServer)
		// Stagger last_seen_at so ORDER BY is predictable
		a.LastSeenAt = a.LastSeenAt.Add(time.Duration(i) * time.Minute)
		require.NoError(t, s.UpsertAsset(ctx, a))
	}

	page, err := s.ListAssets(ctx, store.AssetFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page, 2)
}

// ---------------------------------------------------------------------------
// GetStaleAssets
// ---------------------------------------------------------------------------

func TestGetStaleAssets(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	fresh := makeAsset("fresh", model.AssetTypeServer)
	fresh.LastSeenAt = time.Now().UTC().Truncate(time.Second)

	stale := makeAsset("stale", model.AssetTypeServer)
	stale.LastSeenAt = time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	require.NoError(t, s.UpsertAsset(ctx, fresh))
	require.NoError(t, s.UpsertAsset(ctx, stale))

	got, err := s.GetStaleAssets(ctx, 24*time.Hour)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "stale", got[0].Hostname)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

func makeScanRun(t *testing.T, s *SQLiteStore) model.ScanRun {
	t.Helper()
	run := model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Truncate(time.Second),
		Status:    model.ScanStatusRunning,
	}
	require.NoError(t, s.CreateScanRun(context.Background(), run))
	return run
}

func TestInsertEvent_AndListEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("ev-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))
	run := makeScanRun(t, s)

	evt := model.AssetEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventAssetDiscovered,
		AssetID:   asset.ID,
		ScanRunID: run.ID,
		Severity:  model.SeverityLow,
		Details:   `{"info":"test"}`,
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, s.InsertEvent(ctx, evt))

	events, err := s.ListEvents(ctx, store.EventFilter{})
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.Equal(t, evt.ID, events[0].ID)
	assert.Equal(t, model.EventAssetDiscovered, events[0].EventType)
	assert.Equal(t, asset.ID, events[0].AssetID)
}

func TestListEvents_FilterByEventType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("ev-filter-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))
	run := makeScanRun(t, s)

	for _, et := range []model.EventType{model.EventAssetDiscovered, model.EventAssetUpdated} {
		evt := model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: et,
			AssetID:   asset.ID,
			ScanRunID: run.ID,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Second),
		}
		require.NoError(t, s.InsertEvent(ctx, evt))
	}

	discovered, err := s.ListEvents(ctx, store.EventFilter{EventType: string(model.EventAssetDiscovered)})
	require.NoError(t, err)
	assert.Len(t, discovered, 1)
}

func TestListEvents_FilterByAssetID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a1 := makeAsset("ev-a1", model.AssetTypeServer)
	a2 := makeAsset("ev-a2", model.AssetTypeWorkstation)
	require.NoError(t, s.UpsertAsset(ctx, a1))
	require.NoError(t, s.UpsertAsset(ctx, a2))
	run := makeScanRun(t, s)

	for _, a := range []model.Asset{a1, a2} {
		evt := model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: model.EventAssetDiscovered,
			AssetID:   a.ID,
			ScanRunID: run.ID,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Second),
		}
		require.NoError(t, s.InsertEvent(ctx, evt))
	}

	events, err := s.ListEvents(ctx, store.EventFilter{AssetID: &a1.ID})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, a1.ID, events[0].AssetID)
}

// ---------------------------------------------------------------------------
// ScanRun lifecycle
// ---------------------------------------------------------------------------

func TestCreateScanRun_AndGetLatest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	run := model.ScanRun{
		ID:               uuid.Must(uuid.NewV7()),
		StartedAt:        time.Now().UTC().Truncate(time.Second),
		Status:           model.ScanStatusRunning,
		ScopeConfig:      `{"subnets":["10.0.0.0/24"]}`,
		DiscoverySources: `["network"]`,
	}
	require.NoError(t, s.CreateScanRun(ctx, run))

	latest, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, run.ID, latest.ID)
	assert.Equal(t, model.ScanStatusRunning, latest.Status)
}

func TestCompleteScanRun(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	run := model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Truncate(time.Second),
		Status:    model.ScanStatusRunning,
	}
	require.NoError(t, s.CreateScanRun(ctx, run))

	result := model.ScanResult{
		TotalAssets:     10,
		NewAssets:       3,
		UpdatedAssets:   7,
		StaleAssets:     1,
		CoveragePercent: 95.5,
	}
	require.NoError(t, s.CompleteScanRun(ctx, run.ID, result))

	latest, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.NotNil(t, latest.CompletedAt)
	assert.Equal(t, 10, latest.TotalAssets)
	assert.Equal(t, 3, latest.NewAssets)
	assert.Equal(t, 7, latest.UpdatedAssets)
	assert.Equal(t, 1, latest.StaleAssets)
	assert.InDelta(t, 95.5, latest.CoveragePercent, 0.01)
}

func TestCompleteScanRun_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.CompleteScanRun(ctx, uuid.Must(uuid.NewV7()), model.ScanResult{})
	assert.Error(t, err)
}

func TestGetLatestScanRun_Empty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	latest, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	assert.Nil(t, latest, "no scan runs should return nil")
}

// TestSQLiteStore_ListScanRuns_OrderAndLimit covers the contract:
//   - rows are returned newest-first by started_at,
//   - an explicit limit caps the result set,
//   - limit <= 0 falls back to the default (50), so 5 rows fit and all return,
//   - an empty store returns a non-nil empty slice (not nil).
func TestSQLiteStore_ListScanRuns_OrderAndLimit(t *testing.T) {
	ctx := context.Background()

	t.Run("empty store returns empty slice (not nil)", func(t *testing.T) {
		s := newTestStore(t)
		runs, err := s.ListScanRuns(ctx, 100)
		require.NoError(t, err)
		require.NotNil(t, runs, "empty result must be non-nil empty slice")
		assert.Equal(t, 0, len(runs))
	})

	t.Run("orders newest-first and respects limit", func(t *testing.T) {
		s := newTestStore(t)

		// Insert 5 runs with deliberately interleaved started_at offsets so
		// insertion order does not match temporal order.
		base := time.Now().UTC().Truncate(time.Second)
		offsets := []time.Duration{
			2 * time.Minute,
			0,
			4 * time.Minute,
			1 * time.Minute,
			3 * time.Minute,
		}
		ids := make([]uuid.UUID, len(offsets))
		for i, off := range offsets {
			ids[i] = uuid.Must(uuid.NewV7())
			require.NoError(t, s.CreateScanRun(ctx, model.ScanRun{
				ID:        ids[i],
				StartedAt: base.Add(off),
				Status:    model.ScanStatusRunning,
			}))
		}

		// Limit = 3 → newest three by started_at, descending.
		// Expected order by offset: 4m, 3m, 2m → ids[2], ids[4], ids[0].
		runs, err := s.ListScanRuns(ctx, 3)
		require.NoError(t, err)
		require.Len(t, runs, 3)
		assert.Equal(t, ids[2], runs[0].ID)
		assert.Equal(t, ids[4], runs[1].ID)
		assert.Equal(t, ids[0], runs[2].ID)
		// Strictly descending by StartedAt.
		for i := 1; i < len(runs); i++ {
			assert.False(t, runs[i].StartedAt.After(runs[i-1].StartedAt),
				"runs must be ordered DESC by started_at")
		}

		// Limit = 0 → default cap (50) ≥ 5 inserted rows, so all 5 return.
		all, err := s.ListScanRuns(ctx, 0)
		require.NoError(t, err)
		assert.Len(t, all, 5, "limit<=0 must default to 50 and return all 5 rows")
	})
}

// TestScanRun_TriggerProvenanceRoundtrip covers RFC-0104 phase 2: a
// persisted ScanRun must round-trip trigger_source, triggered_by, and the
// optional cancel_requested_at marker. It also checks the default ("cli")
// that CreateScanRun stamps when the caller leaves TriggerSource empty.
func TestScanRun_TriggerProvenanceRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	cancelAt := time.Now().UTC().Truncate(time.Second)

	run := model.ScanRun{
		ID:                uuid.Must(uuid.NewV7()),
		StartedAt:         time.Now().UTC().Truncate(time.Second),
		Status:            model.ScanStatusRunning,
		TriggerSource:     "api",
		TriggeredBy:       "tenant-abc",
		CancelRequestedAt: &cancelAt,
	}
	require.NoError(t, s.CreateScanRun(ctx, run))

	latest, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, "api", latest.TriggerSource)
	assert.Equal(t, "tenant-abc", latest.TriggeredBy)
	require.NotNil(t, latest.CancelRequestedAt)
	assert.True(t, cancelAt.Equal(*latest.CancelRequestedAt))

	// Empty TriggerSource defaults to "cli".
	run2 := model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Add(time.Second).Truncate(time.Second),
		Status:    model.ScanStatusRunning,
	}
	require.NoError(t, s.CreateScanRun(ctx, run2))

	latest2, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest2)
	assert.Equal(t, run2.ID, latest2.ID)
	assert.Equal(t, "cli", latest2.TriggerSource,
		"empty TriggerSource must default to 'cli'")
	assert.Empty(t, latest2.TriggeredBy)
	assert.Nil(t, latest2.CancelRequestedAt)
}

// TestScanRun_TriggerSourceIndex verifies the idx_scan_runs_trigger_source
// index is created and usable. We assert it exists in sqlite_master and
// that EXPLAIN QUERY PLAN picks it up for a typical dashboard query.
func TestScanRun_TriggerSourceIndex(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var name string
	err := s.RawDB().QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"idx_scan_runs_trigger_source",
	).Scan(&name)
	require.NoError(t, err, "idx_scan_runs_trigger_source must exist")
	assert.Equal(t, "idx_scan_runs_trigger_source", name)

	var plan string
	rows, err := s.RawDB().QueryContext(ctx,
		`EXPLAIN QUERY PLAN
		 SELECT id FROM scan_runs
		 WHERE trigger_source = 'api'
		 ORDER BY started_at DESC`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var a, b, c int
		var detail string
		if scanErr := rows.Scan(&a, &b, &c, &detail); scanErr != nil {
			t.Fatalf("scan EXPLAIN row: %v", scanErr)
		}
		plan += detail + "\n"
	}
	require.NoError(t, rows.Err())
	assert.Contains(t, plan, "idx_scan_runs_trigger_source",
		"planner must use the trigger_source index for filtered latest-scan lookups")
}

// ---------------------------------------------------------------------------
// Installed Software
// ---------------------------------------------------------------------------

func makeSoftware(assetID uuid.UUID, name, version, pkgMgr string) model.InstalledSoftware {
	return model.InstalledSoftware{
		ID:             uuid.Must(uuid.NewV7()),
		AssetID:        assetID,
		SoftwareName:   name,
		Version:        version,
		PackageManager: pkgMgr,
	}
}

func TestUpsertSoftware_InsertAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("sw-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	sw := []model.InstalledSoftware{
		makeSoftware(asset.ID, "curl", "7.88.1", "dpkg"),
		makeSoftware(asset.ID, "wget", "1.21.3", "dpkg"),
		makeSoftware(asset.ID, "vim", "9.0", "dpkg"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "curl", got[0].SoftwareName)
	assert.Equal(t, "7.88.1", got[0].Version)
	assert.Equal(t, "dpkg", got[0].PackageManager)
	assert.Equal(t, asset.ID, got[0].AssetID)
}

func TestUpsertSoftware_ReplacesExisting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("replace-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	// First batch
	sw1 := []model.InstalledSoftware{
		makeSoftware(asset.ID, "old-pkg1", "1.0", "pacman"),
		makeSoftware(asset.ID, "old-pkg2", "2.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw1))

	// Second batch replaces first
	sw2 := []model.InstalledSoftware{
		makeSoftware(asset.ID, "new-pkg1", "3.0", "pacman"),
		makeSoftware(asset.ID, "new-pkg2", "4.0", "pacman"),
		makeSoftware(asset.ID, "new-pkg3", "5.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw2))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "new-pkg1", got[0].SoftwareName)
}

func TestUpsertSoftware_EmptySlice_DeletesAll(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("empty-sw-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	sw := []model.InstalledSoftware{
		makeSoftware(asset.ID, "pkg", "1.0", "dpkg"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw))

	// Replace with empty
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, nil))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSoftware_NoResults(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("no-sw-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSoftware_OrderedByName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("ordered-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	sw := []model.InstalledSoftware{
		makeSoftware(asset.ID, "zlib", "1.2", "pacman"),
		makeSoftware(asset.ID, "bash", "5.2", "pacman"),
		makeSoftware(asset.ID, "curl", "8.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "bash", got[0].SoftwareName)
	assert.Equal(t, "curl", got[1].SoftwareName)
	assert.Equal(t, "zlib", got[2].SoftwareName)
}

func TestUpsertSoftware_WithCPE(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("cpe-host", model.AssetTypeServer)
	require.NoError(t, s.UpsertAsset(ctx, asset))

	sw := []model.InstalledSoftware{
		{
			ID:             uuid.Must(uuid.NewV7()),
			AssetID:        asset.ID,
			SoftwareName:   "openssl",
			Version:        "3.1.4",
			Vendor:         "OpenSSL Project",
			CPE23:          "cpe:2.3:a:openssl:openssl:3.1.4:*:*:*:*:*:*:*",
			PackageManager: "rpm",
		},
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, sw))

	got, err := s.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "openssl", got[0].SoftwareName)
	assert.Equal(t, "OpenSSL Project", got[0].Vendor)
	assert.Equal(t, "cpe:2.3:a:openssl:openssl:3.1.4:*:*:*:*:*:*:*", got[0].CPE23)
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ListAssets — additional filters
// ---------------------------------------------------------------------------

func TestListAssets_FilterByIsAuthorized(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	auth := makeAsset("auth-host", model.AssetTypeServer)
	auth.IsAuthorized = model.AuthorizationAuthorized
	require.NoError(t, s.UpsertAsset(ctx, auth))

	unauth := makeAsset("unauth-host", model.AssetTypeServer)
	unauth.IsAuthorized = model.AuthorizationUnauthorized
	require.NoError(t, s.UpsertAsset(ctx, unauth))

	results, err := s.ListAssets(ctx, store.AssetFilter{IsAuthorized: string(model.AuthorizationAuthorized)})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "auth-host", results[0].Hostname)
}

func TestListAssets_FilterByIsManaged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	managed := makeAsset("managed-host", model.AssetTypeServer)
	managed.IsManaged = model.ManagedManaged
	require.NoError(t, s.UpsertAsset(ctx, managed))

	unmanaged := makeAsset("unmanaged-host", model.AssetTypeServer)
	unmanaged.IsManaged = model.ManagedUnmanaged
	require.NoError(t, s.UpsertAsset(ctx, unmanaged))

	results, err := s.ListAssets(ctx, store.AssetFilter{IsManaged: string(model.ManagedManaged)})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "managed-host", results[0].Hostname)
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Insert assets sequentially to avoid SQLite BUSY contention.
	const numAssets = 10
	for i := 0; i < numAssets; i++ {
		hostname := fmt.Sprintf("concurrent-host-%d", i)
		asset := makeAsset(hostname, model.AssetTypeServer)
		require.NoError(t, s.UpsertAsset(ctx, asset))
	}

	// Concurrent reads should be safe (WAL mode allows this).
	const numReaders = 10
	errs := make(chan error, numReaders)

	for i := 0; i < numReaders; i++ {
		go func() {
			_, err := s.ListAssets(ctx, store.AssetFilter{})
			errs <- err
		}()
	}

	for i := 0; i < numReaders; i++ {
		err := <-errs
		assert.NoError(t, err, "concurrent ListAssets should not error")
	}

	all, err := s.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err)
	assert.Len(t, all, numAssets)
}

// TestDashboardReads_UnmigratedDB reproduces the production log spam reported
// against the dashboard:
//
//	ERROR dashboard: render scan-status error="get latest scan run: ...
//	    SQL logic error: no such table: scan_runs (1)"
//	ERROR dashboard: render assets error="list assets: ...
//	    SQL logic error: no such table: assets (1)"
//	ERROR dashboard: render findings error="list findings: ...
//	    SQL logic error: no such table: config_findings (1)"
//
// Today the dashboard opens the store and starts serving HTMX polls; if the
// underlying SQLite file was never migrated (fresh install, wrong path, or
// Migrate silently skipped) every fragment render returns HTTP 500 and a
// raw driver error is logged twice per poll.
//
// Desired contract (post-fix): each read method used by the dashboard must
// treat "no such table" the same way it already treats sql.ErrNoRows /
// empty result — a non-error empty response. GetLatestScanRun already
// returns (nil, nil) on ErrNoRows; it should do the same when the
// scan_runs table is absent. ListAssets / ListSoftware / ListFindings
// should return ([]T{}, nil) instead of bubbling the driver error. This
// matches the UX the template already handles ("No scans yet", empty grid)
// and collapses the log spam into silence on an un-migrated DB.
//
// This test pins that contract: it opens a store WITHOUT calling Migrate
// and asserts each dashboard read returns a graceful empty response. It
// will fail today against the bug; once the store is taught to translate
// "no such table" into an empty result (or wrap it as a typed
// store.ErrSchemaNotInitialized that the dashboard renders as an
// actionable hint), the assertions below pass.
func TestDashboardReads_UnmigratedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "unmigrated.db")
	s, err := New(dbPath)
	require.NoError(t, err, "New must succeed even without Migrate")
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()

	t.Run("GetLatestScanRun", func(t *testing.T) {
		latest, err := s.GetLatestScanRun(ctx)
		assert.NoError(t, err,
			"un-migrated DB must not surface a raw driver error — "+
				"GetLatestScanRun should return (nil, nil) like the empty case")
		assert.Nil(t, latest)
	})

	t.Run("ListAssets", func(t *testing.T) {
		assets, err := s.ListAssets(ctx, store.AssetFilter{})
		assert.NoError(t, err,
			"un-migrated DB must not surface a raw driver error — "+
				"ListAssets should return an empty slice")
		assert.Empty(t, assets)
	})

	t.Run("ListSoftware", func(t *testing.T) {
		sw, err := s.ListSoftware(ctx, uuid.Must(uuid.NewV7()))
		assert.NoError(t, err,
			"un-migrated DB must not surface a raw driver error — "+
				"ListSoftware should return an empty slice")
		assert.Empty(t, sw)
	})

	t.Run("ListFindings", func(t *testing.T) {
		findings, err := s.ListFindings(ctx, store.FindingFilter{})
		assert.NoError(t, err,
			"un-migrated DB must not surface a raw driver error — "+
				"ListFindings should return an empty slice")
		assert.Empty(t, findings)
	})
}

func TestClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_test.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, s.Migrate(context.Background()))

	err = s.Close()
	assert.NoError(t, err)
}
