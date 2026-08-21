package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func TestRunMigrate_ApplyThenStatusThenDryRun(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kite.db")

	require.NoError(t, runMigrate(dbPath, false, "", false))
	_, err := os.Stat(dbPath)
	require.NoError(t, err, "migrate must create the database file")

	statusOut := captureStdout(t, func() {
		require.NoError(t, runMigrate(dbPath, true, "", false))
	})
	assert.Contains(t, statusOut, "Migration Status (SQLite: "+dbPath+")")
	assert.Contains(t, statusOut, "VERSION")
	assert.Contains(t, statusOut, "applied (")
	assert.Contains(t, statusOut, "| Pending: 0")
	assert.NotContains(t, statusOut, "pending       ")

	dryOut := captureStdout(t, func() {
		require.NoError(t, runMigrate(dbPath, false, "", true))
	})
	assert.Contains(t, dryOut, "all migrations already applied")
	assert.NotContains(t, dryOut, "would apply:")
}

func TestRunMigrate_RepairUnknownVersionFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kite.db")
	require.NoError(t, runMigrate(dbPath, false, "", false))

	err := runMigrate(dbPath, false, "not-a-real-version", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repair migration")
	assert.Contains(t, err.Error(), `"not-a-real-version" not found`)
}

func TestRunMigrate_UnopenableStoreFails(t *testing.T) {
	// A directory where the db file should be cannot be opened as a store.
	err := runMigrate(t.TempDir(), false, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open store")
}

// seedQueryDB creates a migrated store with one machine and one scan run.
func seedQueryDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "kite.db")
	ctx := context.Background()
	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	require.NoError(t, err)
	require.NoError(t, encStore.Migrate(ctx))
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)
	require.NoError(t, st.UpsertMachine(ctx, diffFixtureMachine("query-host", model.MachineTypeServer)))
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:            uuid.New(),
		StartedAt:     time.Now().UTC().Truncate(time.Second),
		Status:        model.ScanStatusCompleted,
		TotalMachines: 1,
	}))
	require.NoError(t, encStore.Close())
	return dbPath
}

func TestRunQuery_MachinesRendersHeaderAndRow(t *testing.T) {
	dbPath := seedQueryDB(t)

	out := captureStdout(t, func() {
		require.NoError(t, runQuery("machines", dbPath, 50, ""))
	})
	// tabwriter renders the tab-joined uppercased column list with spacing.
	assert.Contains(t, out, "HOSTNAME")
	assert.Contains(t, out, "MACHINE_TYPE")
	assert.Contains(t, out, "OS_FAMILY")
	assert.Contains(t, out, "query-host")
	assert.Contains(t, out, "server")
	assert.Contains(t, out, "2026-08-01T12:00:00Z")
}

func TestRunQuery_ScansAndUnlimited(t *testing.T) {
	dbPath := seedQueryDB(t)

	out := captureStdout(t, func() {
		// limit <= 0 exercises the no-LIMIT branch.
		require.NoError(t, runQuery("scans", dbPath, 0, ""))
	})
	assert.Contains(t, out, "STARTED_AT")
	assert.Contains(t, out, "completed")
}

func TestRunQuery_FindingsTargetIsBrokenByCWEColumnDrop(t *testing.T) {
	// Known latent bug: the static findings queries still select cwe_id,
	// which migration 20260624140000_drop_vulnerability_tables.sql removed.
	// This test pins today's behavior so a schema/query fix flips it loudly.
	dbPath := seedQueryDB(t)

	err := runQuery("findings", dbPath, 10, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such column: cwe_id")

	err = runQuery("findings", dbPath, 10, "high")
	require.Error(t, err, "the severity-filtered variant selects cwe_id too")
	assert.Contains(t, err.Error(), "no such column: cwe_id")
}

func TestRunQuery_UnknownTarget(t *testing.T) {
	err := runQuery("users", filepath.Join(t.TempDir(), "kite.db"), 10, "")
	require.Error(t, err)
	assert.Equal(t, "unknown query target: users (use: machines, software, findings, scans)",
		err.Error())
}

func TestRunReport_JSONIncludesMachinesAndLatestScan(t *testing.T) {
	dbPath := seedQueryDB(t)

	out := captureStdout(t, func() {
		require.NoError(t, runReport(dbPath, "json", ""))
	})

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Equal(t, float64(1), doc["total_machines"])
	machines := doc["machines"].([]any)
	require.Len(t, machines, 1)
	assert.Equal(t, "query-host", machines[0].(map[string]any)["hostname"])
	_, hasScan := doc["latest_scan"]
	assert.True(t, hasScan, "seeded scan run must surface as latest_scan")
	_, hasFindings := doc["findings"]
	assert.False(t, hasFindings, "no findings seeded → key omitted")
}

func TestRunReport_TableFormatShowsScanSummary(t *testing.T) {
	dbPath := seedQueryDB(t)

	out := captureStdout(t, func() {
		require.NoError(t, runReport(dbPath, "table", ""))
	})
	assert.Contains(t, out, "Latest scan: ")
	assert.Contains(t, out, "(total: 1, new: 0, stale: 0)")
	assert.Contains(t, out, "HOSTNAME")
	assert.Contains(t, out, "query-host")
}

func TestRunReport_CSVAndHTMLFormats(t *testing.T) {
	dbPath := seedQueryDB(t)

	csvOut := captureStdout(t, func() {
		require.NoError(t, runReport(dbPath, "csv", ""))
	})
	assert.Contains(t, csvOut, "id,hostname,machine_type")
	assert.Contains(t, csvOut, "query-host")

	htmlOut := captureStdout(t, func() {
		require.NoError(t, runReport(dbPath, "html", ""))
	})
	assert.Contains(t, htmlOut, "<!DOCTYPE html>")
	assert.Contains(t, htmlOut, "query-host")
}

func TestRunReport_OutputFileRedirectsStdout(t *testing.T) {
	dbPath := seedQueryDB(t)
	outPath := filepath.Join(t.TempDir(), "report.json")

	// runReport reassigns os.Stdout when --output is used and does not
	// restore it; pin and restore it here so the test process is unaffected.
	orig := os.Stdout
	defer func() { os.Stdout = orig }()

	require.NoError(t, runReport(dbPath, "json", outPath))
	os.Stdout = orig

	raw, err := os.ReadFile(outPath) //#nosec G304 -- temp path owned by the test
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, float64(1), doc["total_machines"])
}

func TestRunReport_UnopenableStoreFails(t *testing.T) {
	err := runReport(t.TempDir(), "json", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open store")
}

func TestRunDB_EncryptedDatabasePointsAtQueryCommand(t *testing.T) {
	// Any file that does not carry the SQLite magic reads as encrypted;
	// this deterministic branch never launches the sqlite3 CLI.
	dbPath := filepath.Join(t.TempDir(), "kite.db")
	require.NoError(t, os.WriteFile(dbPath, bytes.Repeat([]byte{0xAA}, 32), 0o600))

	enc, err := sqlite.IsEncrypted(dbPath)
	require.NoError(t, err)
	require.True(t, enc, "fixture must read as encrypted")

	out := captureStdout(t, func() {
		require.NoError(t, runDB(dbPath))
	})
	assert.Contains(t, out, "Database is encrypted at rest. The sqlite3 CLI cannot read it.")
	assert.Contains(t, out, "kite-collector query machines")
	assert.Contains(t, out, "kite-collector dashboard")
}
