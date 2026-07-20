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
// upsert machines -> upsert software -> insert events -> create/complete scan
// run -> list/filter machines -> get stale machines.
func TestPostgresStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	now := time.Now().UTC().Truncate(time.Millisecond)

	// ---- Upsert machines ----
	machines := []model.Machine{
		makeMachine("e2e-srv-01", model.MachineTypeServer, now),
		makeMachine("e2e-ws-01", model.MachineTypeWorkstation, now),
		makeMachine("e2e-cloud-01", model.MachineTypeCloudInstance, now),
	}

	inserted, updated, err := st.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 3, inserted)
	assert.Equal(t, 0, updated)

	// Re-upsert with updated fields — should count as updates.
	machines[0].OSVersion = "6.2"
	machines[0].LastSeenAt = now.Add(time.Minute)
	inserted, updated, err = st.UpsertMachines(ctx, machines)
	require.NoError(t, err)
	assert.Equal(t, 0, inserted)
	assert.Equal(t, 3, updated)

	// ---- Upsert software ----
	software := []model.InstalledSoftware{
		{
			ID:             uuid.Must(uuid.NewV7()),
			MachineID:      machines[0].ID,
			SoftwareName:   "falcon-sensor",
			Vendor:         "CrowdStrike",
			Version:        "7.0.0",
			CPE23:          "cpe:2.3:a:crowdstrike:falcon:7.0.0:*:*:*:*:*:*:*",
			PackageManager: "deb",
		},
		{
			ID:             uuid.Must(uuid.NewV7()),
			MachineID:      machines[0].ID,
			SoftwareName:   "osquery",
			Vendor:         "Meta",
			Version:        "5.11.0",
			PackageManager: "deb",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machines[0].ID, software))

	listedSW, err := st.ListSoftware(ctx, machines[0].ID)
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
	events := []model.MachineEvent{
		makeEvent(machines[0].ID, scanRunID, model.EventMachineDiscovered, now),
		makeEvent(machines[1].ID, scanRunID, model.EventMachineDiscovered, now),
		makeEvent(machines[2].ID, scanRunID, model.EventMachineDiscovered, now),
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	// ---- Complete scan run ----
	result := model.ScanResult{
		TotalMachines:   3,
		NewMachines:     3,
		UpdatedMachines: 0,
		StaleMachines:   0,
		EventsEmitted:   3,
		CoveragePercent: 100.0,
	}
	require.NoError(t, st.CompleteScanRun(ctx, scanRunID, result))

	latest, err := st.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.Equal(t, 3, latest.TotalMachines)
	assert.NotNil(t, latest.CompletedAt)

	// ---- List/filter machines ----
	all, err := st.ListMachines(ctx, store.MachineFilter{Limit: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3)

	cloudOnly, err := st.ListMachines(ctx, store.MachineFilter{
		MachineType: string(model.MachineTypeCloudInstance),
		Limit:       100,
	})
	require.NoError(t, err)
	for _, a := range cloudOnly {
		assert.Equal(t, model.MachineTypeCloudInstance, a.MachineType)
	}

	// ---- List events with filter ----
	evByMachine, err := st.ListEvents(ctx, store.EventFilter{
		MachineID: &machines[0].ID,
		Limit:     100,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, evByMachine)
	for _, e := range evByMachine {
		assert.Equal(t, machines[0].ID, e.MachineID)
	}

	// ---- Stale machines ----
	staleMachine := makeMachine("e2e-stale-host", model.MachineTypeServer, now.Add(-72*time.Hour))
	_, _, err = st.UpsertMachines(ctx, []model.Machine{staleMachine})
	require.NoError(t, err)

	stale, err := st.GetStaleMachines(ctx, 24*time.Hour)
	require.NoError(t, err)
	staleNames := make(map[string]bool)
	for _, a := range stale {
		staleNames[a.Hostname] = true
	}
	assert.True(t, staleNames["e2e-stale-host"], "stale machine should appear")
}

// TestPostgresUpsertIdempotent verifies that upserting the same machine twice
// does not duplicate it.
func TestPostgresUpsertIdempotent(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	now := time.Now().UTC().Truncate(time.Millisecond)
	machine := makeMachine("e2e-idempotent", model.MachineTypeServer, now)

	require.NoError(t, st.UpsertMachine(ctx, machine))
	require.NoError(t, st.UpsertMachine(ctx, machine))

	listed, err := st.ListMachines(ctx, store.MachineFilter{
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
	machine := makeMachine("e2e-sw-replace", model.MachineTypeServer, now)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{machine})
	require.NoError(t, err)

	// Initial set.
	initial := []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), MachineID: machine.ID, SoftwareName: "old-agent", Vendor: "Old", Version: "1.0"},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machine.ID, initial))

	listed, err := st.ListSoftware(ctx, machine.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 1)

	// Replace entirely.
	replacement := []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), MachineID: machine.ID, SoftwareName: "new-edr", Vendor: "New", Version: "2.0"},
		{ID: uuid.Must(uuid.NewV7()), MachineID: machine.ID, SoftwareName: "config-mgmt", Vendor: "New", Version: "3.0"},
	}
	require.NoError(t, st.UpsertSoftware(ctx, machine.ID, replacement))

	listed, err = st.ListSoftware(ctx, machine.ID)
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
