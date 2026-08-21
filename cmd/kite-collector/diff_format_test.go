package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func diffFixtureMachine(host string, typ model.MachineType) model.Machine {
	return model.Machine{
		ID:              uuid.New(),
		Hostname:        host,
		MachineType:     typ,
		OSFamily:        "linux",
		OSVersion:       "ubuntu-24.04",
		IsAuthorized:    model.AuthorizationAuthorized,
		IsManaged:       model.ManagedManaged,
		Environment:     "prod",
		Owner:           "infra",
		DiscoverySource: "network",
		LastSeenAt:      time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestNaturalKey(t *testing.T) {
	a := diffFixtureMachine("web-01", model.MachineTypeServer)
	assert.Equal(t, "web-01|server", naturalKey(a))
	assert.Equal(t, "|", naturalKey(model.Machine{}))
}

func TestCompareMachines_DetectsEachField(t *testing.T) {
	base := diffFixtureMachine("h", model.MachineTypeServer)

	assert.Nil(t, compareMachines(base, base), "identical machines have no diff")

	cases := []struct {
		mutate func(*model.Machine)
		field  string
	}{
		{func(m *model.Machine) { m.LastSeenAt = m.LastSeenAt.Add(time.Hour) }, "LastSeenAt"},
		{func(m *model.Machine) { m.IsAuthorized = model.AuthorizationUnauthorized }, "IsAuthorized"},
		{func(m *model.Machine) { m.IsManaged = model.ManagedUnmanaged }, "IsManaged"},
		{func(m *model.Machine) { m.OSVersion = "ubuntu-25.04" }, "OSVersion"},
		{func(m *model.Machine) { m.OSFamily = "bsd" }, "OSFamily"},
		{func(m *model.Machine) { m.Environment = "staging" }, "Environment"},
		{func(m *model.Machine) { m.Owner = "secops" }, "Owner"},
		{func(m *model.Machine) { m.DiscoverySource = "agent" }, "DiscoverySource"},
	}
	for _, tc := range cases {
		changed := base
		tc.mutate(&changed)
		assert.Equal(t, []string{tc.field}, compareMachines(base, changed))
	}
}

func TestComputeDiff_PartitionsByNaturalKey(t *testing.T) {
	a := diffFixtureMachine("alpha", model.MachineTypeServer)
	b := diffFixtureMachine("bravo", model.MachineTypeServer)
	c := diffFixtureMachine("charlie", model.MachineTypeServer)
	aChanged := a
	aChanged.Owner = "new-team"

	res := computeDiff(
		[]model.Machine{a, b},
		[]model.Machine{aChanged, c},
	)

	require.Len(t, res.New, 1)
	assert.Equal(t, "charlie", res.New[0].Hostname)
	require.Len(t, res.Removed, 1)
	assert.Equal(t, "bravo", res.Removed[0].Hostname)
	require.Len(t, res.Changed, 1)
	assert.Equal(t, "alpha", res.Changed[0].After.Hostname)
	assert.Equal(t, []string{"Owner"}, res.Changed[0].Fields)
	assert.Equal(t, "infra", res.Changed[0].Before.Owner)
	assert.Equal(t, "new-team", res.Changed[0].After.Owner)
	assert.Empty(t, res.Unchanged)
}

func TestComputeDiff_UnchangedMachine(t *testing.T) {
	a := diffFixtureMachine("same", model.MachineTypeServer)
	res := computeDiff([]model.Machine{a}, []model.Machine{a})
	assert.Empty(t, res.New)
	assert.Empty(t, res.Removed)
	assert.Empty(t, res.Changed)
	require.Len(t, res.Unchanged, 1)
	assert.Equal(t, "same", res.Unchanged[0].Hostname)
}

func TestFormatDiffJSON_SummaryAndUnchangedToggle(t *testing.T) {
	a := diffFixtureMachine("kept", model.MachineTypeServer)
	res := DiffResult{
		New:       []model.Machine{diffFixtureMachine("n1", model.MachineTypeServer)},
		Removed:   []model.Machine{diffFixtureMachine("r1", model.MachineTypeServer)},
		Unchanged: []model.Machine{a},
	}

	out := captureStdout(t, func() {
		require.NoError(t, formatDiffJSON(res, false))
	})
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	summary := doc["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["new"])
	assert.Equal(t, float64(1), summary["removed"])
	assert.Equal(t, float64(0), summary["changed"])
	assert.Equal(t, float64(1), summary["unchanged"])
	_, hasUnchanged := doc["unchanged"]
	assert.False(t, hasUnchanged, "unchanged list hidden without --show-unchanged")

	out = captureStdout(t, func() {
		require.NoError(t, formatDiffJSON(res, true))
	})
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	_, hasUnchanged = doc["unchanged"]
	assert.True(t, hasUnchanged)
}

func TestFormatDiffTable_SectionsAndCounts(t *testing.T) {
	changed := diffFixtureMachine("ch-01", model.MachineTypeServer)
	after := changed
	after.Owner = "x"
	res := DiffResult{
		New:     []model.Machine{diffFixtureMachine("new-01", model.MachineTypeServer)},
		Changed: []ChangedMachine{{Before: changed, After: after, Fields: []string{"Owner"}}},
	}

	out := captureStdout(t, func() { formatDiffTable(res, false) })

	assert.Contains(t, out, "Diff Summary")
	assert.Contains(t, out, "New:       1")
	assert.Contains(t, out, "Removed:   0")
	assert.Contains(t, out, "Changed:   1")
	assert.Contains(t, out, "Unchanged: 0")
	assert.Contains(t, out, "--- New Machines ---")
	assert.Contains(t, out, "new-01")
	assert.NotContains(t, out, "--- Removed Machines ---")
	assert.Contains(t, out, "--- Changed Machines ---")
	assert.Contains(t, out, "ch-01")
	assert.Contains(t, out, "Owner")
	assert.NotContains(t, out, "--- Unchanged Machines ---")
}

func TestFormatDiffCSV_ExactRows(t *testing.T) {
	newM := diffFixtureMachine("csv-new", model.MachineTypeServer)
	unch := diffFixtureMachine("csv-same", model.MachineTypeServer)
	after := diffFixtureMachine("csv-chg", model.MachineTypeServer)
	res := DiffResult{
		New:       []model.Machine{newM},
		Changed:   []ChangedMachine{{After: after, Fields: []string{"Owner", "OSVersion"}}},
		Unchanged: []model.Machine{unch},
	}

	out := captureStdout(t, func() { formatDiffCSV(res, true) })

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 4)
	assert.Equal(t, []string{
		"status", "hostname", "machine_type", "is_authorized",
		"is_managed", "os_version", "changed_fields",
	}, records[0])
	assert.Equal(t, []string{
		"new", "csv-new", "server", "authorized",
		"managed", "ubuntu-24.04", "",
	}, records[1])
	assert.Equal(t, []string{
		"changed", "csv-chg", "server", "authorized",
		"managed", "ubuntu-24.04", "Owner;OSVersion",
	}, records[2])
	assert.Equal(t, []string{
		"unchanged", "csv-same", "server", "authorized",
		"managed", "ubuntu-24.04", "",
	}, records[3])
}

// seedDiffDB creates a migrated store at dir/kite.db containing machines.
func seedDiffDB(t *testing.T, dir string, machines ...model.Machine) string {
	t.Helper()
	dbPath := filepath.Join(dir, "kite.db")
	ctx := context.Background()
	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	require.NoError(t, err)
	require.NoError(t, encStore.Migrate(ctx))
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)
	for _, m := range machines {
		require.NoError(t, st.UpsertMachine(ctx, m))
	}
	require.NoError(t, encStore.Close())
	return dbPath
}

func TestRunDiff_EndToEndAcrossFormats(t *testing.T) {
	kept := diffFixtureMachine("db-kept", model.MachineTypeServer)
	gone := diffFixtureMachine("db-gone", model.MachineTypeServer)
	added := diffFixtureMachine("db-added", model.MachineTypeServer)

	db1 := seedDiffDB(t, t.TempDir(), kept, gone)
	db2 := seedDiffDB(t, t.TempDir(), kept, added)

	out := captureStdout(t, func() {
		require.NoError(t, runDiff(db1, db2, "json", false))
	})
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	summary := doc["summary"].(map[string]any)
	assert.Equal(t, float64(1), summary["new"])
	assert.Equal(t, float64(1), summary["removed"])
	assert.Equal(t, float64(0), summary["changed"])
	assert.Equal(t, float64(1), summary["unchanged"])

	out = captureStdout(t, func() {
		require.NoError(t, runDiff(db1, db2, "csv", false))
	})
	assert.Contains(t, out, "new,db-added")
	assert.Contains(t, out, "removed,db-gone")

	out = captureStdout(t, func() {
		require.NoError(t, runDiff(db1, db2, "table", true))
	})
	assert.Contains(t, out, "New:       1")
	assert.Contains(t, out, "--- Unchanged Machines ---")

	// A directory in place of the db file cannot be opened as a store.
	err := runDiff(t.TempDir(), db2, "table", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open db1")
}
