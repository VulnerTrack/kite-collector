package sqlite

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// TestUpsertMachines_SoftwareCarry verifies the transient Software carry:
// UpsertMachines persists rows a discovery source attached to the machine,
// replaces them on a fresh non-empty set, and — critically for offline
// hosts — leaves the last-known inventory untouched when the machine
// carries no software this cycle (P3.7).
func TestUpsertMachines_SoftwareCarry(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	m := makeMachine("db-host", model.MachineTypeServer)
	m.Software = []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), SoftwareName: "MySQL", Vendor: "Oracle", Version: "8.4.3", PackageManager: "network_service", InstallPath: "tcp/3306"},
	}
	_, _, err := s.UpsertMachines(ctx, []model.Machine{m})
	require.NoError(t, err)

	got, err := s.ListSoftware(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, got, 1, "the carried software is persisted")
	assert.Equal(t, "MySQL", got[0].SoftwareName)
	assert.Equal(t, "8.4.3", got[0].Version)

	// Re-scan sees the host offline (no software this cycle): the prior
	// inventory MUST survive rather than being wiped.
	offline := makeMachine("db-host", model.MachineTypeServer)
	offline.Software = nil
	_, _, err = s.UpsertMachines(ctx, []model.Machine{offline})
	require.NoError(t, err)

	got, err = s.ListSoftware(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, got, 1, "empty software leaves last-known inventory untouched")
	assert.Equal(t, "8.4.3", got[0].Version)

	// A fresh non-empty set replaces the previous rows wholesale.
	upgraded := makeMachine("db-host", model.MachineTypeServer)
	upgraded.Software = []model.InstalledSoftware{
		{ID: uuid.Must(uuid.NewV7()), SoftwareName: "MySQL", Vendor: "Oracle", Version: "8.4.5", PackageManager: "network_service", InstallPath: "tcp/3306"},
		{ID: uuid.Must(uuid.NewV7()), SoftwareName: "Redis", Vendor: "Redis", Version: "7.2.4", PackageManager: "network_service", InstallPath: "tcp/6379"},
	}
	_, _, err = s.UpsertMachines(ctx, []model.Machine{upgraded})
	require.NoError(t, err)

	got, err = s.ListSoftware(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, got, 2, "a fresh set replaces the prior inventory")
	byName := map[string]string{}
	for _, sw := range got {
		byName[sw.SoftwareName] = sw.Version
	}
	assert.Equal(t, "8.4.5", byName["MySQL"], "MySQL version updated")
	assert.Equal(t, "7.2.4", byName["Redis"])
}
