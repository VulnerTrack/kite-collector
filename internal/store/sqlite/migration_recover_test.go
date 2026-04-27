package sqlite

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// applyMigrationFile reads and executes a single embedded migration .sql file
// against the store's database connection, bypassing the schema_migrations
// tracking table. Used to reproduce specific historical states (e.g. a DB
// that applied migrations 20260403–20260424 but skipped 20260425).
func applyMigrationFile(t *testing.T, s *SQLiteStore, name string) {
	t.Helper()
	sqlBytes, err := fs.ReadFile(migrationFS, "migrations/"+name)
	require.NoErrorf(t, err, "read embedded migration %s", name)
	_, err = s.db.ExecContext(context.Background(), string(sqlBytes))
	require.NoErrorf(t, err, "exec migration %s", name)
}

// migrationFiles returns every embedded migration filename in lexical order.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	files, err := listMigrationFiles()
	require.NoError(t, err)
	return files
}

// TestRecoverScanTriggerSource_AddsMissingColumns reproduces the live
// operator bug: a database whose schema_migrations table records
// 20260425000000_scan_trigger_source as applied but whose scan_runs table
// is missing trigger_source / triggered_by / cancel_requested_at. Applying
// the 20260427 recovery migration must add the columns back, preserve the
// existing row's data, and recreate the supporting index.
func TestRecoverScanTriggerSource_AddsMissingColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// 1. Apply every migration UP TO BUT NOT INCLUDING 20260425. This
	//    leaves scan_runs in its pre-trigger_source shape — the same shape
	//    that broken operator deploys exhibit at runtime.
	for _, file := range migrationFiles(t) {
		if file >= "20260425000000_scan_trigger_source.sql" {
			break
		}
		applyMigrationFile(t, s, file)
	}

	cols := tableColumns(t, s, "scan_runs")
	require.NotContains(t, cols, "trigger_source",
		"precondition: scan_runs must lack trigger_source before recovery")

	// 2. Insert a representative row using only pre-20260425 columns.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_runs (
			id, started_at, completed_at, status,
			total_assets, new_assets, updated_assets, stale_assets,
			coverage_percent, error_count, scope_config, discovery_sources
		) VALUES (
			'run-legacy-1', '2026-04-22T10:00:00Z', '2026-04-22T10:05:00Z',
			'completed', 42, 7, 3, 0, 95.5, 0, '{"scope":"all"}', 'nmap,ssh'
		)
	`)
	require.NoError(t, err)

	// 3. Apply ONLY the new 20260427 recovery migration.
	applyMigrationFile(t, s, "20260427000000_ensure_scan_trigger_source_columns.sql")

	// 4. The three previously-missing columns must now exist.
	cols = tableColumns(t, s, "scan_runs")
	assert.Contains(t, cols, "trigger_source")
	assert.Contains(t, cols, "triggered_by")
	assert.Contains(t, cols, "cancel_requested_at")

	// And the canonical pre-existing columns must still be there.
	for _, c := range []string{
		"id", "started_at", "completed_at", "status",
		"total_assets", "new_assets", "updated_assets", "stale_assets",
		"coverage_percent", "error_count", "scope_config", "discovery_sources",
	} {
		assert.Contains(t, cols, c, "expected pre-existing column %s to survive rebuild", c)
	}

	// 5. The existing row survived with all original column values intact,
	//    and the new columns adopted their DEFAULTs.
	var (
		gotID          string
		gotStarted     string
		gotStatus      string
		gotTotal       int64
		gotCoverage    float64
		gotScope       string
		gotSources     string
		gotTrigger     string
		gotTriggeredBy *string
		gotCancelReqAt *string
	)
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT id, started_at, status, total_assets, coverage_percent,
		       scope_config, discovery_sources, trigger_source,
		       triggered_by, cancel_requested_at
		FROM scan_runs WHERE id = 'run-legacy-1'
	`).Scan(&gotID, &gotStarted, &gotStatus, &gotTotal, &gotCoverage,
		&gotScope, &gotSources, &gotTrigger, &gotTriggeredBy, &gotCancelReqAt))

	assert.Equal(t, "run-legacy-1", gotID)
	assert.Equal(t, "2026-04-22T10:00:00Z", gotStarted)
	assert.Equal(t, "completed", gotStatus)
	assert.Equal(t, int64(42), gotTotal)
	assert.InDelta(t, 95.5, gotCoverage, 0.001)
	assert.Equal(t, `{"scope":"all"}`, gotScope)
	assert.Equal(t, "nmap,ssh", gotSources)
	assert.Equal(t, "cli", gotTrigger,
		"trigger_source should adopt its DEFAULT 'cli' on legacy rows")
	assert.Nil(t, gotTriggeredBy)
	assert.Nil(t, gotCancelReqAt)

	// 6. The supporting index must be recreated.
	var idxName string
	err = s.db.QueryRowContext(ctx, `
		SELECT name FROM sqlite_master
		WHERE type = 'index' AND name = 'idx_scan_runs_trigger_source'
	`).Scan(&idxName)
	require.NoError(t, err, "expected idx_scan_runs_trigger_source to exist after recovery")
	assert.Equal(t, "idx_scan_runs_trigger_source", idxName)
}

// TestRecoverScanTriggerSource_PreservesExistingDataOnHealthyDB simulates a
// healthy upgrade path: the full migration chain has been applied, including
// 20260425, and a row with non-default trigger_source / triggered_by /
// cancel_requested_at exists. The recovery migration must not lose any rows.
//
// NOTE on data semantics: because pure SQLite SQL cannot conditionally
// reference a column that may or may not exist, the recovery migration only
// copies the pre-20260425 column union. On a healthy DB this means the three
// new columns are reset to their DEFAULTs (trigger_source -> 'cli',
// triggered_by -> NULL, cancel_requested_at -> NULL). This trade-off is
// documented in the migration file. This test asserts the row count is
// preserved and the canonical columns are intact, while explicitly
// acknowledging the default-reset behaviour for the three new columns.
func TestRecoverScanTriggerSource_PreservesExistingDataOnHealthyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "healthy_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// 1. Apply every migration UP TO AND INCLUDING 20260426 (skip the new
	//    20260427 we are about to test). This mirrors a healthy operator
	//    deploy that ran 20260425 successfully.
	for _, file := range migrationFiles(t) {
		if file == "20260427000000_ensure_scan_trigger_source_columns.sql" {
			continue
		}
		applyMigrationFile(t, s, file)
	}

	cols := tableColumns(t, s, "scan_runs")
	require.Contains(t, cols, "trigger_source",
		"precondition: healthy DB must already have trigger_source")

	// 2. Insert a row with a non-default trigger_source and a populated
	//    triggered_by, simulating an API-initiated scan.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_runs (
			id, started_at, status, trigger_source, triggered_by
		) VALUES (
			'run-api-1', '2026-04-22T11:00:00Z', 'completed', 'api', 'svc-account-7'
		)
	`)
	require.NoError(t, err)

	var beforeCount int
	require.NoError(t, s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_runs`).Scan(&beforeCount))

	// 3. Apply the recovery migration.
	applyMigrationFile(t, s, "20260427000000_ensure_scan_trigger_source_columns.sql")

	// 4. Row count is preserved — no data loss at the row level.
	var afterCount int
	require.NoError(t, s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_runs`).Scan(&afterCount))
	assert.Equal(t, beforeCount, afterCount,
		"row count must be preserved across the rebuild")

	// 5. The row still exists with all canonical columns intact.
	var (
		gotID      string
		gotStarted string
		gotStatus  string
		gotTrigger string
	)
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT id, started_at, status, trigger_source
		FROM scan_runs WHERE id = 'run-api-1'
	`).Scan(&gotID, &gotStarted, &gotStatus, &gotTrigger))
	assert.Equal(t, "run-api-1", gotID)
	assert.Equal(t, "2026-04-22T11:00:00Z", gotStarted)
	assert.Equal(t, "completed", gotStatus)

	// 6. Documented trade-off: new-column values reset to DEFAULTs. This
	//    assertion locks the behaviour in so any future change must update
	//    the migration's header comment too.
	assert.Equal(t, "cli", gotTrigger,
		"healthy-DB rebuild resets trigger_source to its DEFAULT — see migration header")
}

// TestRecoverScanTriggerSource_FullChainApplies verifies that a fresh DB
// with the full migration chain (including the new 20260427 file) records
// every migration as applied and ends with the canonical scan_runs schema.
func TestRecoverScanTriggerSource_FullChainApplies(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))

	cols := tableColumns(t, s, "scan_runs")
	for _, c := range []string{
		"trigger_source", "triggered_by", "cancel_requested_at",
		"id", "started_at", "status", "total_assets",
	} {
		assert.Contains(t, cols, c)
	}

	// The new migration must be recorded as applied.
	infos, err := s.MigrationStatus(ctx)
	require.NoError(t, err)
	var found bool
	for _, info := range infos {
		if info.Version == "20260427000000_ensure_scan_trigger_source_columns" {
			found = true
			assert.True(t, info.Applied,
				"recovery migration should be applied on fresh DB")
		}
	}
	assert.True(t, found, "20260427000000_ensure_scan_trigger_source_columns must be embedded")
}
