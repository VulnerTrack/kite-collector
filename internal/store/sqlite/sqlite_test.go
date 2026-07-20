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

func makeMachine(hostname string, machineType model.MachineType) model.Machine {
	now := time.Now().UTC().Truncate(time.Second)
	a := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		MachineType:     machineType,
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
// UpsertMachine + GetMachineByNaturalKey round-trip
// ---------------------------------------------------------------------------

func TestUpsertMachine_AndGetByNaturalKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("web-01", model.MachineTypeServer)
	machine.OSFamily = "linux"
	machine.Environment = "production"

	require.NoError(t, s.UpsertMachine(ctx, machine))

	// Re-compute the key to look it up the same way the store does.
	machine.ComputeNaturalKey()
	got, err := s.GetMachineByNaturalKey(ctx, machine.NaturalKey)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, machine.ID, got.ID)
	assert.Equal(t, machine.Hostname, got.Hostname)
	assert.Equal(t, machine.MachineType, got.MachineType)
	assert.Equal(t, "linux", got.OSFamily)
	assert.Equal(t, "production", got.Environment)
}

func TestGetMachineByNaturalKey_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.GetMachineByNaturalKey(ctx, "nonexistent-key")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// UpsertMachines (batch)
// ---------------------------------------------------------------------------

func TestUpsertMachines_MultipleBatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machines := []model.Machine{
		makeMachine("batch-01", model.MachineTypeServer),
		makeMachine("batch-02", model.MachineTypeWorkstation),
		makeMachine("batch-03", model.MachineTypeContainer),
	}

	inserted, updated, err := s.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 3, inserted)
	assert.Equal(t, 0, updated)

	// Upserting the same batch again should count as updates.
	inserted2, updated2, err := s.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 0, inserted2)
	assert.Equal(t, 3, updated2)
}

// ---------------------------------------------------------------------------
// ListMachines
// ---------------------------------------------------------------------------

func TestListMachines_NoFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertMachine(ctx, makeMachine("a", model.MachineTypeServer)))
	require.NoError(t, s.UpsertMachine(ctx, makeMachine("b", model.MachineTypeWorkstation)))

	all, err := s.ListMachines(ctx, store.MachineFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestListMachines_FilterByMachineType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertMachine(ctx, makeMachine("s1", model.MachineTypeServer)))
	require.NoError(t, s.UpsertMachine(ctx, makeMachine("w1", model.MachineTypeWorkstation)))

	servers, err := s.ListMachines(ctx, store.MachineFilter{MachineType: string(model.MachineTypeServer)})
	require.NoError(t, err)
	assert.Len(t, servers, 1)
	assert.Equal(t, "s1", servers[0].Hostname)
}

func TestListMachines_FilterByHostname(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertMachine(ctx, makeMachine("specific-host", model.MachineTypeServer)))
	require.NoError(t, s.UpsertMachine(ctx, makeMachine("other-host", model.MachineTypeServer)))

	results, err := s.ListMachines(ctx, store.MachineFilter{Hostname: "specific-host"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "specific-host", results[0].Hostname)
}

func TestListMachines_LimitAndOffset(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a := makeMachine("host-"+string(rune('a'+i)), model.MachineTypeServer)
		// Stagger last_seen_at so ORDER BY is predictable
		a.LastSeenAt = a.LastSeenAt.Add(time.Duration(i) * time.Minute)
		require.NoError(t, s.UpsertMachine(ctx, a))
	}

	page, err := s.ListMachines(ctx, store.MachineFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page, 2)
}

// ---------------------------------------------------------------------------
// GetStaleMachines
// ---------------------------------------------------------------------------

func TestGetStaleMachines(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	fresh := makeMachine("fresh", model.MachineTypeServer)
	fresh.LastSeenAt = time.Now().UTC().Truncate(time.Second)

	stale := makeMachine("stale", model.MachineTypeServer)
	stale.LastSeenAt = time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	require.NoError(t, s.UpsertMachine(ctx, fresh))
	require.NoError(t, s.UpsertMachine(ctx, stale))

	got, err := s.GetStaleMachines(ctx, 24*time.Hour)
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

	machine := makeMachine("ev-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))
	run := makeScanRun(t, s)

	evt := model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
		MachineID: machine.ID,
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
	assert.Equal(t, model.EventMachineDiscovered, events[0].EventType)
	assert.Equal(t, machine.ID, events[0].MachineID)
}

func TestListEvents_FilterByEventType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("ev-filter-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))
	run := makeScanRun(t, s)

	for _, et := range []model.EventType{model.EventMachineDiscovered, model.EventMachineUpdated} {
		evt := model.MachineEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: et,
			MachineID: machine.ID,
			ScanRunID: run.ID,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Second),
		}
		require.NoError(t, s.InsertEvent(ctx, evt))
	}

	discovered, err := s.ListEvents(ctx, store.EventFilter{EventType: string(model.EventMachineDiscovered)})
	require.NoError(t, err)
	assert.Len(t, discovered, 1)
}

func TestListEvents_FilterByMachineID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a1 := makeMachine("ev-a1", model.MachineTypeServer)
	a2 := makeMachine("ev-a2", model.MachineTypeWorkstation)
	require.NoError(t, s.UpsertMachine(ctx, a1))
	require.NoError(t, s.UpsertMachine(ctx, a2))
	run := makeScanRun(t, s)

	for _, a := range []model.Machine{a1, a2} {
		evt := model.MachineEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: model.EventMachineDiscovered,
			MachineID: a.ID,
			ScanRunID: run.ID,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Second),
		}
		require.NoError(t, s.InsertEvent(ctx, evt))
	}

	events, err := s.ListEvents(ctx, store.EventFilter{MachineID: &a1.ID})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, a1.ID, events[0].MachineID)
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
		TotalMachines:   10,
		NewMachines:     3,
		UpdatedMachines: 7,
		StaleMachines:   1,
		CoveragePercent: 95.5,
	}
	require.NoError(t, s.CompleteScanRun(ctx, run.ID, result))

	latest, err := s.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)

	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.NotNil(t, latest.CompletedAt)
	assert.Equal(t, 10, latest.TotalMachines)
	assert.Equal(t, 3, latest.NewMachines)
	assert.Equal(t, 7, latest.UpdatedMachines)
	assert.Equal(t, 1, latest.StaleMachines)
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
	err := s.RawDB().QueryRowContext(
		ctx,
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

func makeSoftware(machineID uuid.UUID, name, version, pkgMgr string) model.InstalledSoftware {
	return model.InstalledSoftware{
		ID:             uuid.Must(uuid.NewV7()),
		MachineID:      machineID,
		SoftwareName:   name,
		Version:        version,
		PackageManager: pkgMgr,
	}
}

func TestUpsertSoftware_InsertAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("sw-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	sw := []model.InstalledSoftware{
		makeSoftware(machine.ID, "curl", "7.88.1", "dpkg"),
		makeSoftware(machine.ID, "wget", "1.21.3", "dpkg"),
		makeSoftware(machine.ID, "vim", "9.0", "dpkg"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw))

	got, err := s.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "curl", got[0].SoftwareName)
	assert.Equal(t, "7.88.1", got[0].Version)
	assert.Equal(t, "dpkg", got[0].PackageManager)
	assert.Equal(t, machine.ID, got[0].MachineID)
}

func TestUpsertSoftware_ReplacesExisting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("replace-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	// First batch
	sw1 := []model.InstalledSoftware{
		makeSoftware(machine.ID, "old-pkg1", "1.0", "pacman"),
		makeSoftware(machine.ID, "old-pkg2", "2.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw1))

	// Second batch replaces first
	sw2 := []model.InstalledSoftware{
		makeSoftware(machine.ID, "new-pkg1", "3.0", "pacman"),
		makeSoftware(machine.ID, "new-pkg2", "4.0", "pacman"),
		makeSoftware(machine.ID, "new-pkg3", "5.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw2))

	got, err := s.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "new-pkg1", got[0].SoftwareName)
}

func TestUpsertSoftware_EmptySlice_DeletesAll(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("empty-sw-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	sw := []model.InstalledSoftware{
		makeSoftware(machine.ID, "pkg", "1.0", "dpkg"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw))

	// Replace with empty
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, nil))

	got, err := s.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSoftware_NoResults(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("no-sw-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	got, err := s.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSoftware_OrderedByName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("ordered-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	sw := []model.InstalledSoftware{
		makeSoftware(machine.ID, "zlib", "1.2", "pacman"),
		makeSoftware(machine.ID, "bash", "5.2", "pacman"),
		makeSoftware(machine.ID, "curl", "8.0", "pacman"),
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw))

	got, err := s.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "bash", got[0].SoftwareName)
	assert.Equal(t, "curl", got[1].SoftwareName)
	assert.Equal(t, "zlib", got[2].SoftwareName)
}

func TestUpsertSoftware_WithCPE(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("cpe-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	sw := []model.InstalledSoftware{
		{
			ID:             uuid.Must(uuid.NewV7()),
			MachineID:      machine.ID,
			SoftwareName:   "openssl",
			Version:        "3.1.4",
			Vendor:         "OpenSSL Project",
			CPE23:          "cpe:2.3:a:openssl:openssl:3.1.4:*:*:*:*:*:*:*",
			PackageManager: "rpm",
		},
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, sw))

	got, err := s.ListSoftware(ctx, machine.ID)
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
// ListMachines — additional filters
// ---------------------------------------------------------------------------

func TestListMachines_FilterByIsAuthorized(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	auth := makeMachine("auth-host", model.MachineTypeServer)
	auth.IsAuthorized = model.AuthorizationAuthorized
	require.NoError(t, s.UpsertMachine(ctx, auth))

	unauth := makeMachine("unauth-host", model.MachineTypeServer)
	unauth.IsAuthorized = model.AuthorizationUnauthorized
	require.NoError(t, s.UpsertMachine(ctx, unauth))

	results, err := s.ListMachines(ctx, store.MachineFilter{IsAuthorized: string(model.AuthorizationAuthorized)})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "auth-host", results[0].Hostname)
}

func TestListMachines_FilterByIsManaged(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	managed := makeMachine("managed-host", model.MachineTypeServer)
	managed.IsManaged = model.ManagedManaged
	require.NoError(t, s.UpsertMachine(ctx, managed))

	unmanaged := makeMachine("unmanaged-host", model.MachineTypeServer)
	unmanaged.IsManaged = model.ManagedUnmanaged
	require.NoError(t, s.UpsertMachine(ctx, unmanaged))

	results, err := s.ListMachines(ctx, store.MachineFilter{IsManaged: string(model.ManagedManaged)})
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

	// Insert machines sequentially to avoid SQLite BUSY contention.
	const numMachines = 10
	for i := 0; i < numMachines; i++ {
		hostname := fmt.Sprintf("concurrent-host-%d", i)
		machine := makeMachine(hostname, model.MachineTypeServer)
		require.NoError(t, s.UpsertMachine(ctx, machine))
	}

	// Concurrent reads should be safe (WAL mode allows this).
	const numReaders = 10
	errs := make(chan error, numReaders)

	for i := 0; i < numReaders; i++ {
		go func() {
			_, err := s.ListMachines(ctx, store.MachineFilter{})
			errs <- err
		}()
	}

	for i := 0; i < numReaders; i++ {
		err := <-errs
		assert.NoError(t, err, "concurrent ListMachines should not error")
	}

	all, err := s.ListMachines(ctx, store.MachineFilter{})
	require.NoError(t, err)
	assert.Len(t, all, numMachines)
}

// TestDashboardReads_UnmigratedDB reproduces the production log spam reported
// against the dashboard:
//
//	ERROR dashboard: render scan-status error="get latest scan run: ...
//	    SQL logic error: no such table: scan_runs (1)"
//	ERROR dashboard: render machines error="list machines: ...
//	    SQL logic error: no such table: machines (1)"
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
// scan_runs table is absent. ListMachines / ListSoftware / ListFindings
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

	t.Run("ListMachines", func(t *testing.T) {
		machines, err := s.ListMachines(ctx, store.MachineFilter{})
		assert.NoError(t, err,
			"un-migrated DB must not surface a raw driver error — "+
				"ListMachines should return an empty slice")
		assert.Empty(t, machines)
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

func TestStorePathAccessor(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "path_accessor.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	assert.Equal(t, dbPath, s.Path(),
		"Path() must return the dbPath supplied to New, "+
			"so transient-error logs can include it")
}

// TestUpsertMachines_TransientRetryRoundtrip is the happy-path smoke
// test that proves the withTransientRetry wrapper does not break the
// normal UpsertMachines flow. Simulating SQLITE_IOERR_DELETE_NOENT
// against a real DB would require racing the OS, so the unit tests on
// withTransientRetry cover the retry logic itself.
func TestUpsertMachines_TransientRetryRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machines := []model.Machine{
		makeMachine("retry-01", model.MachineTypeServer),
		makeMachine("retry-02", model.MachineTypeWorkstation),
	}

	inserted, updated, err := s.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 2, inserted)
	assert.Equal(t, 0, updated)

	// Repeat to exercise the existing-key code path under the retry
	// wrapper.
	inserted2, updated2, err := s.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 0, inserted2)
	assert.Equal(t, 2, updated2)
}
