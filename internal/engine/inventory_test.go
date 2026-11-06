package engine

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestInventoryEventsCarryEveryPackageOnUnchangedRescan(t *testing.T) {
	machine := model.Machine{ID: uuid.New(), Hostname: "host", Architecture: "amd64",
		Interfaces: []model.NetworkInterface{{IPAddress: "10.0.0.1"}}}
	event := model.MachineEvent{ID: uuid.New(), EventType: model.EventMachineAnalyzed,
		Details: model.BuildEventDetails(machine, model.EventMachineAnalyzed)}
	event.FromMachine(machine)
	packages := make([]model.InstalledSoftware, 914)
	for i := range packages {
		packages[i] = model.InstalledSoftware{SoftwareName: fmt.Sprintf("pkg-%d", i), Version: "1", InstallPath: "/usr/lib"}
	}
	chunks, err := inventoryEvents(machine, event, packages)
	require.NoError(t, err)
	require.Len(t, chunks, 5)
	seen := map[string]bool{}
	ids := map[uuid.UUID]bool{}
	for _, chunk := range chunks {
		require.Equal(t, model.EventMachineAnalyzed, chunk.EventType)
		require.Equal(t, machine.ID, chunk.MachineID)
		require.False(t, ids[chunk.ID])
		ids[chunk.ID] = true
		var body struct {
			Software   []model.InstalledSoftware `json:"software"`
			Interfaces []model.NetworkInterface  `json:"interfaces"`
			Inventory  model.Machine             `json:"inventory"`
		}
		require.NoError(t, json.Unmarshal([]byte(chunk.Details), &body))
		require.LessOrEqual(t, len(body.Software), inventorySoftwarePageSize)
		require.Equal(t, machine.Interfaces, body.Interfaces)
		require.Equal(t, "amd64", body.Inventory.Architecture)
		for _, pkg := range body.Software {
			require.False(t, seen[pkg.SoftwareName])
			seen[pkg.SoftwareName] = true
			require.Equal(t, "/usr/lib", pkg.InstallPath)
		}
	}
	require.Len(t, seen, len(packages))
}

func TestInventoryEventsRetainHostsWithoutPackages(t *testing.T) {
	event := model.MachineEvent{Details: `{}`}
	chunks, err := inventoryEvents(model.Machine{}, event, nil)
	require.NoError(t, err)
	require.Len(t, chunks, 1)
}

func TestInventoryContinuationDoesNotRepeatLifecycleAlert(t *testing.T) {
	machine := model.Machine{ID: uuid.New()}
	event := model.MachineEvent{ID: uuid.New(), EventType: model.EventUnauthorizedMachineDetected,
		Severity: model.SeverityHigh, Details: model.BuildEventDetails(machine, model.EventUnauthorizedMachineDetected)}
	chunks, err := inventoryEvents(machine, event, make([]model.InstalledSoftware, 201))
	require.NoError(t, err)
	require.Equal(t, event.EventType, chunks[0].EventType)
	require.Equal(t, event.Severity, chunks[0].Severity)
	require.Equal(t, model.EventMachineAnalyzed, chunks[1].EventType)
	require.Equal(t, model.SeverityLow, chunks[1].Severity)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(chunks[1].Details), &body))
	require.Equal(t, string(model.EventMachineAnalyzed), body["event_type"])
}
