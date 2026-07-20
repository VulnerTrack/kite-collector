//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/postgres"
)

// newTestStore creates a PostgresStore from the KITE_TEST_POSTGRES_DSN env var,
// runs migrations, and registers a cleanup that closes the store.
func newTestStore(t *testing.T) *postgres.PostgresStore {
	t.Helper()

	dsn := os.Getenv("KITE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KITE_TEST_POSTGRES_DSN not set; skipping postgres integration test")
	}

	st, err := postgres.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	require.NoError(t, st.Migrate(ctx))

	return st
}

// makeMachine builds a minimal Machine with a computed natural key.
func makeMachine(hostname string, machineType model.MachineType) model.Machine {
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := model.Machine{
		ID:              uuid.New(),
		Hostname:        hostname,
		MachineType:     machineType,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		OSFamily:        "linux",
		OSVersion:       "6.1",
		Environment:     "production",
		Owner:           "secops",
		Criticality:     "high",
		DiscoverySource: "nmap",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            "[]",
	}
	a.ComputeNaturalKey()
	return a
}

// ---------------------------------------------------------------------------
// UpsertMachines / ListMachines
// ---------------------------------------------------------------------------

func TestUpsertMachines_InsertAndUpdate(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a1 := makeMachine("pg-test-host-01", model.MachineTypeServer)
	a2 := makeMachine("pg-test-host-02", model.MachineTypeWorkstation)

	inserted, updated, err := st.UpsertMachines(ctx, []model.Machine{a1, a2})
	require.NoError(t, err)
	assert.Equal(t, 2, inserted)
	assert.Equal(t, 0, updated)

	// Upsert the same machines again -- should count as updates.
	a1.OSVersion = "6.2"
	a1.LastSeenAt = time.Now().UTC().Truncate(time.Millisecond)
	inserted, updated, err = st.UpsertMachines(ctx, []model.Machine{a1, a2})
	require.NoError(t, err)
	assert.Equal(t, 0, inserted)
	assert.Equal(t, 2, updated)
}

func TestListMachines_FilterByHostname(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a := makeMachine("pg-list-filter-host", model.MachineTypeServer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{a})
	require.NoError(t, err)

	results, err := st.ListMachines(ctx, store.MachineFilter{
		Hostname: "pg-list-filter-host",
		Limit:    10,
	})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "pg-list-filter-host", results[0].Hostname)
}

func TestListMachines_FilterByMachineType(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a := makeMachine("pg-type-filter-host", model.MachineTypeContainer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{a})
	require.NoError(t, err)

	results, err := st.ListMachines(ctx, store.MachineFilter{
		MachineType: string(model.MachineTypeContainer),
		Limit:       10,
	})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Equal(t, model.MachineTypeContainer, r.MachineType)
	}
}

// ---------------------------------------------------------------------------
// GetStaleMachines
// ---------------------------------------------------------------------------

func TestGetStaleMachines(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	staleMachine := makeMachine("pg-stale-host", model.MachineTypeServer)
	staleMachine.LastSeenAt = time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)

	freshMachine := makeMachine("pg-fresh-host", model.MachineTypeServer)
	freshMachine.LastSeenAt = time.Now().UTC().Truncate(time.Millisecond)

	_, _, err := st.UpsertMachines(ctx, []model.Machine{staleMachine, freshMachine})
	require.NoError(t, err)

	stale, err := st.GetStaleMachines(ctx, 24*time.Hour)
	require.NoError(t, err)

	staleHostnames := make(map[string]bool)
	for _, a := range stale {
		staleHostnames[a.Hostname] = true
	}
	assert.True(t, staleHostnames["pg-stale-host"], "stale machine should appear in results")
	assert.False(t, staleHostnames["pg-fresh-host"], "fresh machine should not appear in stale results")
}

// ---------------------------------------------------------------------------
// InsertEvents / ListEvents
// ---------------------------------------------------------------------------

func TestInsertEvents_AndListByMachineID(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("pg-event-host", model.MachineTypeServer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{machine})
	require.NoError(t, err)

	scanRunID := uuid.New()
	events := []model.MachineEvent{
		{
			ID:        uuid.New(),
			MachineID: machine.ID,
			ScanRunID: scanRunID,
			EventType: model.EventMachineDiscovered,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   `{"source":"nmap"}`,
		},
		{
			ID:        uuid.New(),
			MachineID: machine.ID,
			ScanRunID: scanRunID,
			EventType: model.EventMachineUpdated,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   `{"field":"os_version"}`,
		},
	}

	err = st.InsertEvents(ctx, events)
	require.NoError(t, err)

	listed, err := st.ListEvents(ctx, store.EventFilter{
		MachineID: &machine.ID,
		Limit:     10,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listed), 2)
}

func TestListEvents_FilterByScanRunID(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("pg-event-scan-host", model.MachineTypeServer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{machine})
	require.NoError(t, err)

	scanRunID := uuid.New()
	otherScanRunID := uuid.New()

	events := []model.MachineEvent{
		{
			ID:        uuid.New(),
			MachineID: machine.ID,
			ScanRunID: scanRunID,
			EventType: model.EventMachineDiscovered,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   "{}",
		},
		{
			ID:        uuid.New(),
			MachineID: machine.ID,
			ScanRunID: otherScanRunID,
			EventType: model.EventMachineUpdated,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   "{}",
		},
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	listed, err := st.ListEvents(ctx, store.EventFilter{
		ScanRunID: &scanRunID,
		Limit:     10,
	})
	require.NoError(t, err)
	for _, ev := range listed {
		assert.Equal(t, scanRunID, ev.ScanRunID)
	}
}

// ---------------------------------------------------------------------------
// CreateScanRun / CompleteScanRun / GetLatestScanRun
// ---------------------------------------------------------------------------

func TestScanRun_CreateCompleteAndGetLatest(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	run := model.ScanRun{
		ID:               uuid.New(),
		StartedAt:        time.Now().UTC().Truncate(time.Millisecond),
		Status:           model.ScanStatusRunning,
		DiscoverySources: mustJSON([]string{"nmap", "cloud-api"}),
		ScopeConfig:      `{"subnets":["10.0.0.0/24"]}`,
	}
	require.NoError(t, st.CreateScanRun(ctx, run))

	// Complete the scan run.
	result := model.ScanResult{
		TotalMachines:   42,
		NewMachines:     10,
		UpdatedMachines: 30,
		StaleMachines:   2,
		EventsEmitted:   52,
		CoveragePercent: 95.5,
	}
	require.NoError(t, st.CompleteScanRun(ctx, run.ID, result))

	// Retrieve latest and verify fields.
	latest, err := st.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, run.ID, latest.ID)
	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.Equal(t, 42, latest.TotalMachines)
	assert.Equal(t, 10, latest.NewMachines)
	assert.NotNil(t, latest.CompletedAt)
}

// ---------------------------------------------------------------------------
// UpsertSoftware / ListSoftware
// ---------------------------------------------------------------------------

func TestUpsertSoftware_AndList(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("pg-software-host", model.MachineTypeServer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{machine})
	require.NoError(t, err)

	software := []model.InstalledSoftware{
		{
			ID:             uuid.New(),
			MachineID:      machine.ID,
			SoftwareName:   "CrowdStrike Falcon",
			Vendor:         "CrowdStrike",
			Version:        "7.0.1",
			CPE23:          "cpe:2.3:a:crowdstrike:falcon:7.0.1:*:*:*:*:*:*:*",
			PackageManager: "msi",
		},
		{
			ID:             uuid.New(),
			MachineID:      machine.ID,
			SoftwareName:   "osquery",
			Vendor:         "Meta",
			Version:        "5.11.0",
			CPE23:          "",
			PackageManager: "deb",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machine.ID, software))

	listed, err := st.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	names := make(map[string]bool)
	for _, sw := range listed {
		names[sw.SoftwareName] = true
	}
	assert.True(t, names["CrowdStrike Falcon"])
	assert.True(t, names["osquery"])
}

func TestUpsertSoftware_ReplacesExisting(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	machine := makeMachine("pg-software-replace-host", model.MachineTypeServer)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{machine})
	require.NoError(t, err)

	// Initial software set.
	initial := []model.InstalledSoftware{
		{
			ID:           uuid.New(),
			MachineID:    machine.ID,
			SoftwareName: "old-agent",
			Vendor:       "OldCorp",
			Version:      "1.0.0",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machine.ID, initial))

	listed, err := st.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 1)
	assert.Equal(t, "old-agent", listed[0].SoftwareName)

	// Replace with a completely new set.
	replacement := []model.InstalledSoftware{
		{
			ID:           uuid.New(),
			MachineID:    machine.ID,
			SoftwareName: "new-edr",
			Vendor:       "NewCorp",
			Version:      "2.0.0",
		},
		{
			ID:           uuid.New(),
			MachineID:    machine.ID,
			SoftwareName: "config-mgmt",
			Vendor:       "NewCorp",
			Version:      "3.0.0",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machine.ID, replacement))

	listed, err = st.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	names := make(map[string]bool)
	for _, sw := range listed {
		names[sw.SoftwareName] = true
	}
	assert.False(t, names["old-agent"], "old software should have been replaced")
	assert.True(t, names["new-edr"])
	assert.True(t, names["config-mgmt"])
}

// mustJSON marshals v to a JSON string, panicking on error.
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
