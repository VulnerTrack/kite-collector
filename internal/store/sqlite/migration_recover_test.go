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

const recoveryMigration = "20260427000000_ensure_scan_trigger_source_columns.sql"

// TestRecoveryMigration_AddsMissingColumns reproduces the broken-operator
// scenario: the schema_migrations table records 20260425 as applied, but
// scan_runs is missing trigger_source / triggered_by / cancel_requested_at.
// Running 20260427 via the migration runner must add the columns back,
// preserve the existing row's data, and create the supporting index.
func TestRecoveryMigration_AddsMissingColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// 1. Apply every migration UP TO BUT NOT INCLUDING 20260425. This
	//    leaves scan_runs in its pre-trigger_source shape -- the same shape
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
	applyMigrationFile(t, s, recoveryMigration)

	// 4. The three previously-missing columns must now exist.
	cols = tableColumns(t, s, "scan_runs")
	assert.Contains(t, cols, "trigger_source")
	assert.Contains(t, cols, "triggered_by")
	assert.Contains(t, cols, "cancel_requested_at")

	// 5. The pre-existing row's canonical column values are intact, and the
	//    new columns adopt their DEFAULTs (cli / NULL / NULL) -- exactly the
	//    behaviour the original 20260425 ADD COLUMN would have produced.
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

	// 6. The supporting index must exist after recovery.
	var idxName string
	err = s.db.QueryRowContext(ctx, `
		SELECT name FROM sqlite_master
		WHERE type = 'index' AND name = 'idx_scan_runs_trigger_source'
	`).Scan(&idxName)
	require.NoError(t, err, "expected idx_scan_runs_trigger_source to exist after recovery")
	assert.Equal(t, "idx_scan_runs_trigger_source", idxName)
}

// TestRecoveryMigration_IsNoOpOnHealthyDB_PreservesValues is the regression
// test for the data-loss bug we are fixing. On a healthy DB whose 20260425
// successfully ran and where operators have populated trigger_source='api',
// triggered_by='dashboard', cancel_requested_at=<ts>, the recovery migration
// must NOT reset those values to defaults. The full runner path is exercised
// (Migrate(ctx)) so the @tolerate header is honoured.
func TestRecoveryMigration_IsNoOpOnHealthyDB_PreservesValues(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "healthy_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// 1. Apply every migration UP TO AND INCLUDING 20260426 directly (skip
	//    the new 20260427 we are about to test). This mirrors a healthy
	//    operator deploy that ran 20260425 successfully.
	for _, file := range migrationFiles(t) {
		if file == recoveryMigration {
			continue
		}
		applyMigrationFile(t, s, file)
	}

	cols := tableColumns(t, s, "scan_runs")
	require.Contains(t, cols, "trigger_source",
		"precondition: healthy DB must already have trigger_source")

	// 2. Insert a row with non-default trigger_source, triggered_by, AND
	//    cancel_requested_at, simulating an API-initiated, operator-cancelled
	//    scan -- the exact shape of value that the buggy rebuild would lose.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_runs (
			id, started_at, status,
			trigger_source, triggered_by, cancel_requested_at
		) VALUES (
			'run-api-1', '2026-04-22T11:00:00Z', 'completed',
			'api', 'dashboard', '2026-04-25T10:00:00Z'
		)
	`)
	require.NoError(t, err)

	// 3. Run the recovery migration via the FULL runner path so the
	//    @tolerate directive is exercised end-to-end. We pre-record every
	//    other migration as applied, then let Migrate() process 20260427.
	preRecordAppliedMigrationsExcept(t, ctx, s, recoveryMigration)
	require.NoError(t, s.Migrate(ctx))

	// 4. Row count is preserved.
	var afterCount int
	require.NoError(t, s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_runs`).Scan(&afterCount))
	assert.Equal(t, 1, afterCount, "row count must be preserved")

	// 5. THE REGRESSION ASSERTION: all three operator-populated values must
	//    survive. The old rebuild approach reset these to 'cli' / NULL / NULL.
	var (
		gotTrigger     string
		gotTriggeredBy *string
		gotCancelReqAt *string
	)
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT trigger_source, triggered_by, cancel_requested_at
		FROM scan_runs WHERE id = 'run-api-1'
	`).Scan(&gotTrigger, &gotTriggeredBy, &gotCancelReqAt))
	assert.Equal(t, "api", gotTrigger,
		"trigger_source must NOT be reset to 'cli' on healthy DB")
	require.NotNil(t, gotTriggeredBy, "triggered_by must NOT be reset to NULL")
	assert.Equal(t, "dashboard", *gotTriggeredBy)
	require.NotNil(t, gotCancelReqAt, "cancel_requested_at must NOT be reset to NULL")
	assert.Equal(t, "2026-04-25T10:00:00Z", *gotCancelReqAt)
}

// TestRecoveryMigration_SwallowsDuplicateColumnError verifies idempotency
// at the runner level: applying the recovery migration twice on a healthy
// DB must succeed (the second call exercises the @tolerate path explicitly).
func TestRecoveryMigration_SwallowsDuplicateColumnError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "idempotent_trigger_source.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// First Migrate() applies the full chain including 20260427.
	require.NoError(t, s.Migrate(ctx))

	// Re-running the recovery migration directly (bypassing
	// schema_migrations) must succeed thanks to @tolerate. We invoke the
	// runner path again by clearing the recorded entry and re-Migrating.
	require.NoError(t, s.RepairMigration(ctx, "20260427000000_ensure_scan_trigger_source_columns"))
	require.NoError(t, s.Migrate(ctx),
		"second application of recovery migration must succeed (duplicate column tolerated)")

	// And the columns are still present.
	cols := tableColumns(t, s, "scan_runs")
	assert.Contains(t, cols, "trigger_source")
	assert.Contains(t, cols, "triggered_by")
	assert.Contains(t, cols, "cancel_requested_at")
}

// preRecordAppliedMigrationsExcept marks every embedded migration EXCEPT
// the named one as applied in schema_migrations. Used to drive Migrate()
// to process exactly the named migration via the full runner path. The
// schema_migrations table is created on demand to mirror Migrate()'s own
// initialisation.
func preRecordAppliedMigrationsExcept(t *testing.T, ctx context.Context, s *SQLiteStore, exclude string) {
	t.Helper()
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum   TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)
	`)
	require.NoError(t, err)
	for _, file := range migrationFiles(t) {
		if file == exclude {
			continue
		}
		version := file[:len(file)-len(".sql")]
		_, err := s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO schema_migrations (version, checksum, applied_at)
			VALUES (?, '', '2026-04-22T00:00:00Z')
		`, version)
		require.NoError(t, err)
	}
}
