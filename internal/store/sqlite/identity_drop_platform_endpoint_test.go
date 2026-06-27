package sqlite

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDropPlatformEndpoint_UpgradePath simulates a live deploy that applied
// the pre-fede515 version of 20260423000001_identity_onboarding.sql (with
// the legacy platform_endpoint column) and then receives the new
// 20260424000000_drop_identity_platform_endpoint migration. After the new
// migration runs, the column must be gone and any existing row must survive.
func TestDropPlatformEndpoint_UpgradePath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_identity.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()

	// 1. Hand-craft the legacy schema (platform_endpoint NOT NULL) — this
	// mirrors the CREATE TABLE shipped in commit 79fc9a8 and still resident
	// in production SQLite files.
	_, err = s.db.ExecContext(ctx, `
		CREATE TABLE enrolled_identity (
			id                      INTEGER PRIMARY KEY CHECK (id = 1),
			platform_endpoint       TEXT NOT NULL,
			api_key_fingerprint     TEXT NOT NULL,
			api_key_wrapped         BLOB NOT NULL,
			first_enrolled_at       INTEGER NOT NULL,
			last_enrolled_at        INTEGER NOT NULL,
			last_check_passed_at    INTEGER,
			last_check_failed_at    INTEGER
		) STRICT;
	`)
	require.NoError(t, err)

	// 2. Insert a representative row with a non-null platform_endpoint.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO enrolled_identity (
			id, platform_endpoint, api_key_fingerprint, api_key_wrapped,
			first_enrolled_at, last_enrolled_at
		) VALUES (1, 'https://legacy.example', 'fp-legacy', X'DEAD', 111, 222)
	`)
	require.NoError(t, err)

	// 3. Apply the new migration in isolation.
	sqlBytes, err := fs.ReadFile(migrationFS,
		"migrations/20260424000000_drop_identity_platform_endpoint.sql")
	require.NoError(t, err)
	_, err = s.db.ExecContext(ctx, string(sqlBytes))
	require.NoError(t, err)

	// 4. platform_endpoint must be gone.
	cols := tableColumns(t, s, "enrolled_identity")
	assert.NotContains(t, cols, "platform_endpoint",
		"platform_endpoint should be dropped after the new migration")
	assert.Contains(t, cols, "api_key_fingerprint")
	assert.Contains(t, cols, "api_key_wrapped")
	assert.Contains(t, cols, "first_enrolled_at")
	assert.Contains(t, cols, "last_enrolled_at")
	assert.Contains(t, cols, "last_check_passed_at")
	assert.Contains(t, cols, "last_check_failed_at")

	// 5. The existing row survived, with retained columns intact.
	var (
		gotFingerprint string
		gotFirst       int64
		gotLast        int64
	)
	require.NoError(t, s.db.QueryRowContext(ctx, `
		SELECT api_key_fingerprint, first_enrolled_at, last_enrolled_at
		FROM enrolled_identity WHERE id = 1
	`).Scan(&gotFingerprint, &gotFirst, &gotLast))
	assert.Equal(t, "fp-legacy", gotFingerprint)
	assert.Equal(t, int64(111), gotFirst)
	assert.Equal(t, int64(222), gotLast)

	// 6. Upsert path from identity.go — the original prod bug — must now
	// succeed because the NOT NULL platform_endpoint constraint is gone.
	err = s.UpsertEnrolledIdentity(ctx, EnrolledIdentity{
		ApiKeyFingerprint: "fp-new",
		ApiKeyWrapped:     []byte{0x01, 0x02},
	})
	require.NoError(t, err, "upsert must succeed after platform_endpoint drop")
}

// TestDropPlatformEndpoint_FreshInstall verifies that a database migrated
// end-to-end (fresh install — edited 20260423000001 never had the column)
// applies the new migration cleanly: the INSERT...SELECT copies zero or
// more rows, the DROP+RENAME succeeds, and the final schema matches the
// upgrade path.
func TestDropPlatformEndpoint_FreshInstall(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh_identity.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))

	cols := tableColumns(t, s, "enrolled_identity")
	assert.NotContains(t, cols, "platform_endpoint")
	assert.Contains(t, cols, "api_key_fingerprint")

	// Upsert path must work on fresh installs too.
	err = s.UpsertEnrolledIdentity(ctx, EnrolledIdentity{
		ApiKeyFingerprint: "fp-fresh",
		ApiKeyWrapped:     []byte{0xAA},
	})
	require.NoError(t, err)

	// The new migration must be recorded as applied.
	infos, err := s.MigrationStatus(ctx)
	require.NoError(t, err)
	var found bool
	for _, info := range infos {
		if strings.HasPrefix(info.Version, "20260424000000_") {
			found = true
			assert.True(t, info.Applied,
				"drop-platform-endpoint migration should be applied on fresh DB")
		}
	}
	assert.True(t, found, "20260424000000_* migration should be embedded")
}

// tableColumns returns the column names of tbl using PRAGMA table_info.
func tableColumns(t *testing.T, s *SQLiteStore, tbl string) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT name FROM pragma_table_info(?)", tbl)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var cols []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		cols = append(cols, name)
	}
	require.NoError(t, rows.Err())
	return cols
}
