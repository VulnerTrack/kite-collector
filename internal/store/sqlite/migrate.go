package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
)

// migrationNameRe enforces the YYYYMMDDHHMMSS_ timestamp prefix convention.
var migrationNameRe = regexp.MustCompile(`^\d{14}_`)

// tolerateDuplicateColumnDirective opts a migration into per-statement
// "duplicate column name" error tolerance. A migration file declares it by
// including a comment line like:
//
//	-- @tolerate: duplicate column name
//
// anywhere in its body. Used by recovery migrations whose ADD COLUMN
// statements may already have been applied -- without this, re-running them
// would abort the migration on a healthy DB. The tolerance is intentionally
// scoped to the migration runner only; normal queries never receive it.
const tolerateDuplicateColumnDirective = "@tolerate: duplicate column name"

// duplicateColumnPhrase is the exact substring (case-insensitive) returned
// by modernc.org/sqlite when ALTER TABLE ADD COLUMN finds an existing
// column. Matching against the message is acceptable because the engine
// returns this phrase verbatim from the SQLite C source.
const duplicateColumnPhrase = "duplicate column name"

// appliedMigration holds the recorded state of a previously applied migration.
type appliedMigration struct {
	checksum  string
	appliedAt string
}

// MigrationInfo describes a single migration's embedded and applied state.
type MigrationInfo struct {
	Version         string
	File            string
	Checksum        string // SHA256 of the embedded SQL file
	AppliedAt       string // RFC3339 timestamp, empty if not applied
	AppliedChecksum string // checksum stored in schema_migrations
	Applied         bool
}

// EmbeddedMigrationCount returns the number of .sql files in the embedded
// migration filesystem. Safe to call without a database connection.
func EmbeddedMigrationCount() int {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			n++
		}
	}
	return n
}

// Migrate applies all pending embedded SQL migrations in filename order.
// It creates a schema_migrations tracking table, validates filenames,
// verifies checksums of previously applied migrations, and runs new ones
// inside individual transactions.
func (s *SQLiteStore) Migrate(ctx context.Context) error {
	// 1. Ensure the tracking table exists.
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum   TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// 2. List and validate embedded migration files.
	files, err := listMigrationFiles()
	if err != nil {
		return err
	}

	// 3. Read applied migrations from the tracking table.
	applied, err := s.getAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// R3: Verify checksums of already-applied migrations.
	for version, stored := range applied {
		fileName := version + ".sql"
		sqlBytes, readErr := fs.ReadFile(migrationFS, "migrations/"+fileName)
		if readErr != nil {
			continue // file removed from embed — not an error
		}
		current := sha256hex(sqlBytes)
		if stored.checksum != current {
			slog.Error("migration checksum mismatch — file was modified after being applied",
				"version", version,
				"applied_checksum", stored.checksum,
				"current_checksum", current,
			)
		}
	}

	// 4. Apply pending migrations.
	for _, file := range files {
		version := strings.TrimSuffix(file, ".sql")
		if _, ok := applied[version]; ok {
			continue
		}

		sqlBytes, readErr := fs.ReadFile(migrationFS, "migrations/"+file)
		if readErr != nil {
			return fmt.Errorf("read migration %s: %w", file, readErr)
		}

		checksum := sha256hex(sqlBytes)
		t0 := time.Now()
		slog.Info("applying migration", "version", version)

		// R5: Each migration runs in its own transaction.
		tx, txErr := s.db.BeginTx(ctx, &sql.TxOptions{})
		if txErr != nil {
			return fmt.Errorf("begin tx for %s: %w", version, txErr)
		}

		sqlText := string(sqlBytes)
		tolerate := strings.Contains(sqlText, tolerateDuplicateColumnDirective)

		// Most migrations are executed as a single ExecContext over the
		// whole file. When the file opts into duplicate-column tolerance
		// (via the @tolerate header), split on `;` and execute statements
		// individually so that a single "duplicate column" error in one
		// ALTER does not abort the remaining statements in the file.
		if tolerate {
			for i, stmt := range splitSQLStatements(sqlText) {
				if _, execErr := tx.ExecContext(ctx, stmt); execErr != nil {
					if isDuplicateColumnErr(execErr) {
						slog.Warn("migrate: column already exists; treating as recovery no-op",
							"migration", file,
							"statement_index", i,
							"error", execErr.Error(),
						)
						continue
					}
					_ = tx.Rollback()
					return fmt.Errorf("migration %s stmt %d failed: %w", version, i, execErr)
				}
			}
		} else if _, execErr := tx.ExecContext(ctx, sqlText); execErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s failed: %w", version, execErr)
		}

		if _, execErr := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?, ?, ?)`,
			version, checksum, time.Now().UTC().Format(time.RFC3339),
		); execErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, execErr)
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("commit migration %s: %w", version, commitErr)
		}

		// R12: log elapsed time per migration.
		slog.Info("migration applied",
			"version", version,
			"checksum", checksum[:12],
			"elapsed", time.Since(t0).Round(time.Millisecond),
		)
	}

	return nil
}

// MigrationStatus returns the embedded and applied state of every migration.
func (s *SQLiteStore) MigrationStatus(ctx context.Context) ([]MigrationInfo, error) {
	// Ensure tracking table exists so the query works on fresh databases.
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum   TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := s.getAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	infos := make([]MigrationInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version := strings.TrimSuffix(e.Name(), ".sql")

		sqlBytes, readErr := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		checksum := ""
		if readErr == nil {
			checksum = sha256hex(sqlBytes)
		}

		info := MigrationInfo{
			Version:  version,
			File:     e.Name(),
			Checksum: checksum,
		}
		if a, ok := applied[version]; ok {
			info.Applied = true
			info.AppliedAt = a.appliedAt
			info.AppliedChecksum = a.checksum
		}
		infos = append(infos, info)
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Version < infos[j].Version
	})
	return infos, nil
}

// RepairMigration removes the tracking entry for version so it will be
// re-applied on the next Migrate call.
func (s *SQLiteStore) RepairMigration(ctx context.Context, version string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version = ?`, version)
	if err != nil {
		return fmt.Errorf("repair %s: %w", version, err)
	}
	n, rowErr := res.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("repair rows affected: %w", rowErr)
	}
	if n == 0 {
		return fmt.Errorf("version %q not found in schema_migrations", version)
	}
	slog.Info("migration entry removed — will re-apply on next run",
		"version", version)
	return nil
}

// listMigrationFiles returns sorted .sql filenames from the embedded FS,
// validating the naming convention and the startup guard.
func listMigrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// R7: enforce NNN_ naming convention.
		if !migrationNameRe.MatchString(e.Name()) {
			return nil, fmt.Errorf("migration %q does not match required naming convention YYYYMMDDHHMMSS_name.sql", e.Name())
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)

	// R10: startup guard — binary must contain at least one migration.
	if len(files) == 0 {
		return nil, fmt.Errorf("no migrations embedded in binary — build may be broken")
	}

	return files, nil
}

// getAppliedMigrations reads all entries from the schema_migrations table.
func (s *SQLiteStore) getAppliedMigrations(ctx context.Context) (map[string]appliedMigration, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	applied := make(map[string]appliedMigration)
	for rows.Next() {
		var v, cs, at string
		if scanErr := rows.Scan(&v, &cs, &at); scanErr != nil {
			return nil, fmt.Errorf("scan schema_migrations row: %w", scanErr)
		}
		applied[v] = appliedMigration{checksum: cs, appliedAt: at}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration rows: %w", err)
	}
	return applied, nil
}

// sha256hex returns the hex-encoded SHA-256 digest of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// isDuplicateColumnErr reports whether err is a SQLite "duplicate column
// name" error returned by ALTER TABLE ADD COLUMN against an existing
// column. Matching is case-insensitive substring against the engine's
// verbatim message ("duplicate column name: <col>").
func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), duplicateColumnPhrase)
}

// splitSQLStatements splits a SQL file on top-level `;` boundaries while
// tolerating `--` line comments (the only comment style our migrations
// use). It returns trimmed, non-empty statements suitable for individual
// ExecContext calls. The splitter is intentionally minimal: it does not
// handle string literals containing `;` because no migration in this repo
// uses such literals. If that ever changes, replace with a real tokenizer.
func splitSQLStatements(sqlText string) []string {
	var (
		out []string
		cur strings.Builder
	)
	for _, line := range strings.Split(sqlText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			cur.WriteString(line)
			cur.WriteByte('\n')
			continue
		}
		// Split on every `;` in non-comment lines.
		parts := strings.Split(line, ";")
		for i, p := range parts {
			cur.WriteString(p)
			if i < len(parts)-1 {
				stmt := strings.TrimSpace(cur.String())
				if stmt != "" {
					out = append(out, stmt)
				}
				cur.Reset()
			}
		}
		cur.WriteByte('\n')
	}
	if tail := strings.TrimSpace(cur.String()); tail != "" {
		out = append(out, tail)
	}
	return out
}
