package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// Pure helpers: stringifyValue, valueFor
// ---------------------------------------------------------------------------

func TestStringifyValue_AllBranches(t *testing.T) {
	ts := time.Date(2026, 8, 21, 9, 30, 0, 123000000, time.UTC)

	assert.Equal(t, "", stringifyValue(nil))
	assert.Equal(t, "plain", stringifyValue("plain"))
	assert.Equal(t, "bytes", stringifyValue([]byte("bytes")))
	assert.Equal(t, "-42", stringifyValue(int64(-42)))
	assert.Equal(t, "7", stringifyValue(7))
	assert.Equal(t, "2.5", stringifyValue(2.5))
	assert.Equal(t, "true", stringifyValue(true))
	assert.Equal(t, "false", stringifyValue(false))
	assert.Equal(t, "2026-08-21T09:30:00.123Z", stringifyValue(ts))
	assert.Equal(t, "9", stringifyValue(uint16(9)), "unknown types fall back to %%v")
}

func TestValueFor(t *testing.T) {
	row := &store.Row{Columns: []store.ColumnValue{
		{Name: "a", Value: int64(1)},
		{Name: "b", Value: "two"},
	}}
	assert.Equal(t, int64(1), valueFor(row, "a"))
	assert.Equal(t, "two", valueFor(row, "b"))
	assert.Nil(t, valueFor(row, "missing"))
}

// ---------------------------------------------------------------------------
// Catalog helpers + row reports + joins on one migrated store
// ---------------------------------------------------------------------------

func TestIntrospectionCatalogAndReports(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	machine := makeMachine("intro-host", model.MachineTypeServer)
	machine.OSFamily = "linux"
	require.NoError(t, s.UpsertMachine(ctx, machine))
	run := makeScanRun(t, s)
	event := model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
		MachineID: machine.ID,
		ScanRunID: run.ID,
		Severity:  model.SeverityLow,
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, s.InsertEvent(ctx, event))

	t.Run("listViaSQLiteSchema mirrors the catalog", func(t *testing.T) {
		names, err := s.listViaSQLiteSchema(ctx)
		require.NoError(t, err)
		assert.Contains(t, names, "machines")
		assert.Contains(t, names, "events")
		assert.NotContains(t, names, "schema_migrations")
		for _, n := range names {
			assert.NotContains(t, n, "sqlite_", "system tables must be hidden")
		}
	})

	t.Run("describeIfKnown", func(t *testing.T) {
		schema, err := s.describeIfKnown(ctx, "machines")
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "machines", schema.Name)
		assert.Equal(t, []string{"id"}, schema.PrimaryKey)

		unknown, err := s.describeIfKnown(ctx, "zz_definitely_missing")
		require.NoError(t, err)
		assert.Nil(t, unknown)
	})

	t.Run("facet defaults", func(t *testing.T) {
		facets, err := s.FacetTable(ctx, "machines", 0, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, facets, "a populated machines table must yield at least one facet")
	})

	t.Run("row report outbound parents", func(t *testing.T) {
		report, err := s.GetRowReport(ctx, "events", map[string]string{"id": event.ID.String()})
		require.NoError(t, err)
		assert.Equal(t, "events", report.Table)
		assert.Equal(t, event.ID.String(), report.Row.PrimaryKey["id"])

		parents := make(map[string]string, len(report.Outbound))
		for _, out := range report.Outbound {
			parents[out.ViaColumn] = out.Table
		}
		assert.Equal(t, "machines", parents["machine_id"])
		assert.Equal(t, "scan_runs", parents["scan_run_id"])

		for _, out := range report.Outbound {
			if out.ViaColumn == "machine_id" {
				assert.Equal(t, machine.ID.String(), out.Row.PrimaryKey["id"])
			}
			if out.ViaColumn == "scan_run_id" {
				assert.Equal(t, run.ID.String(), out.Row.PrimaryKey["id"])
			}
		}
	})

	t.Run("row report pk validation", func(t *testing.T) {
		_, err := s.GetRowReport(ctx, "machines", map[string]string{"id": "x", "extra": "y"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "primary key mismatch: expected 1 columns, got 2")

		_, err = s.GetRowReport(ctx, "machines", map[string]string{"hostname": "x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `primary key missing column "id"`)

		_, err = s.GetRowReport(ctx, "machines", map[string]string{"id": uuid.Must(uuid.NewV7()).String()})
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("row report rejects table without primary key", func(t *testing.T) {
		_, err := s.RawDB().ExecContext(ctx, `CREATE TABLE zz_nopk (a TEXT, b TEXT)`)
		require.NoError(t, err)
		defer func() {
			_, dropErr := s.RawDB().ExecContext(ctx, `DROP TABLE zz_nopk`)
			require.NoError(t, dropErr)
		}()

		_, err = s.GetRowReport(ctx, "zz_nopk", map[string]string{})
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrUnknownTable)
		assert.Contains(t, err.Error(), "has no primary key")
	})

	t.Run("joined rows identifier validation", func(t *testing.T) {
		base := store.JoinFilter{
			Base: "machines", Join: "events", Type: store.JoinInner,
			OnBase: "id", OnJoin: "machine_id",
			Columns: []store.JoinColumn{
				{Table: "machines", Column: "hostname"},
				{Table: "events", Column: "event_type"},
			},
		}

		unknownBase := base
		unknownBase.Base = "zz_missing"
		_, err := s.ListJoinedRows(ctx, unknownBase)
		assert.ErrorIs(t, err, store.ErrUnknownTable)

		badType := base
		badType.Type = "cross"
		_, err = s.ListJoinedRows(ctx, badType)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported join type "cross"`)

		badOnBase := base
		badOnBase.OnBase = "zz_col"
		_, err = s.ListJoinedRows(ctx, badOnBase)
		assert.ErrorIs(t, err, store.ErrUnknownColumn)

		badOnJoin := base
		badOnJoin.OnJoin = "zz_col"
		_, err = s.ListJoinedRows(ctx, badOnJoin)
		assert.ErrorIs(t, err, store.ErrUnknownColumn)

		noColumns := base
		noColumns.Columns = nil
		_, err = s.ListJoinedRows(ctx, noColumns)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one output column")

		badBaseCol := base
		badBaseCol.Columns = []store.JoinColumn{{Table: "machines", Column: "zz_col"}}
		_, err = s.ListJoinedRows(ctx, badBaseCol)
		assert.ErrorIs(t, err, store.ErrUnknownColumn)

		badJoinCol := base
		badJoinCol.Columns = []store.JoinColumn{{Table: "events", Column: "zz_col"}}
		_, err = s.ListJoinedRows(ctx, badJoinCol)
		assert.ErrorIs(t, err, store.ErrUnknownColumn)

		foreignTable := base
		foreignTable.Columns = []store.JoinColumn{{Table: "scan_runs", Column: "id"}}
		_, err = s.ListJoinedRows(ctx, foreignTable)
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrUnknownTable)
		assert.Contains(t, err.Error(), "neither the base nor the joined table")
	})

	t.Run("joined rows clamps limit and offset", func(t *testing.T) {
		filter := store.JoinFilter{
			Base: "machines", Join: "events", Type: store.JoinInner,
			OnBase: "id", OnJoin: "machine_id",
			Columns: []store.JoinColumn{
				{Table: "machines", Column: "hostname"},
				{Table: "events", Column: "event_type"},
			},
			Limit:  store.IntrospectionRowLimit + 500,
			Offset: -3,
		}
		rows, err := s.ListJoinedRows(ctx, filter)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Len(t, rows[0].Columns, 2)
		assert.Equal(t, "machines.hostname", rows[0].Columns[0].Name)
		assert.Equal(t, "intro-host", stringifyValue(rows[0].Columns[0].Value))
		assert.Equal(t, "events.event_type", rows[0].Columns[1].Name)
		assert.Equal(t, "MachineDiscovered", stringifyValue(rows[0].Columns[1].Value))
	})

	t.Run("migration status and repair edges", func(t *testing.T) {
		infos, err := s.MigrationStatus(ctx)
		require.NoError(t, err)
		require.Len(t, infos, EmbeddedMigrationCount())
		for _, info := range infos {
			assert.True(t, info.Applied, "migration %s must be applied on a migrated store", info.Version)
			assert.Equal(t, info.Checksum, info.AppliedChecksum, "checksums must match for %s", info.Version)
		}

		err = s.RepairMigration(ctx, "00000000000000_never_existed")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in schema_migrations")
	})
}

// ---------------------------------------------------------------------------
// EncryptedStore.Snapshot
// ---------------------------------------------------------------------------

func TestEncryptedStore_Snapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	encPath := filepath.Join(dir, "snap.db.enc")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	es, err := NewEncrypted(encPath, key, "keyring", logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = es.Close() })

	inner, ok := es.Store.(*SQLiteStore)
	require.True(t, ok)
	_, err = inner.RawDB().ExecContext(ctx,
		`CREATE TABLE snap_t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = inner.RawDB().ExecContext(ctx, `INSERT INTO snap_t (id, v) VALUES (7, 'durable')`)
	require.NoError(t, err)

	snapPath := es.workPath + ".snap"

	t.Run("removes stale snapshot leftovers and writes at-rest copy", func(t *testing.T) {
		// A leftover plaintext snapshot from a crashed prior run must be
		// cleared, or VACUUM INTO would refuse to run at all.
		require.NoError(t, os.WriteFile(snapPath, []byte("stale junk"), 0o600))

		require.NoError(t, es.Snapshot(ctx))

		assert.False(t, fileExists(snapPath), "plaintext snapshot must be removed after encryption")

		encrypted, isEncErr := IsEncrypted(encPath)
		require.NoError(t, isEncErr)
		assert.True(t, encrypted, "at-rest file must not be a plaintext SQLite database")

		plainPath := filepath.Join(t.TempDir(), "restored.db")
		require.NoError(t, DecryptFile(encPath, plainPath, key))
		restored, openErr := New(plainPath)
		require.NoError(t, openErr)
		defer func() { _ = restored.Close() }()

		var v string
		require.NoError(t, restored.RawDB().QueryRowContext(ctx,
			`SELECT v FROM snap_t WHERE id = 7`).Scan(&v))
		assert.Equal(t, "durable", v)
	})

	t.Run("vacuum failure surfaces", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		err := es.Snapshot(cancelled)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot")
	})

	t.Run("requires an inner SQLiteStore", func(t *testing.T) {
		broken := &EncryptedStore{logger: logger}
		err := broken.Snapshot(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires an inner *SQLiteStore")
	})

	t.Run("un-removable sibling is logged not fatal", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "orphan.snap")
		require.NoError(t, os.WriteFile(base, []byte("junk"), 0o600))
		blockedDir := base + "-wal"
		require.NoError(t, os.MkdirAll(blockedDir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(blockedDir, "x"), []byte("y"), 0o600))

		es.removeSnapshotFiles(base)

		assert.False(t, fileExists(base), "removable files must be deleted")
		assert.True(t, fileExists(blockedDir), "non-empty directory is left in place")
	})
}

func TestCopyFile_MissingSource(t *testing.T) {
	err := copyFile(filepath.Join(t.TempDir(), "nope.db"), filepath.Join(t.TempDir(), "dst.db"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

// ---------------------------------------------------------------------------
// Encryption file primitives: error states
// ---------------------------------------------------------------------------

func TestEncryptFile_ErrorStates(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)

	t.Run("missing source", func(t *testing.T) {
		err := EncryptFile(filepath.Join(dir, "missing.db"), filepath.Join(dir, "out.enc"), key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read source")
	})

	t.Run("invalid key size", func(t *testing.T) {
		src := filepath.Join(dir, "plain.txt")
		require.NoError(t, os.WriteFile(src, []byte("data"), 0o600))
		err := EncryptFile(src, filepath.Join(dir, "out.enc"), []byte("tiny"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create cipher")
	})
}

func TestDecryptFile_ErrorStates(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}

	t.Run("missing source", func(t *testing.T) {
		err := DecryptFile(filepath.Join(dir, "missing.enc"), filepath.Join(dir, "out.db"), key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read source")
	})

	t.Run("invalid key size", func(t *testing.T) {
		src := filepath.Join(dir, "short1.enc")
		require.NoError(t, os.WriteFile(src, []byte("0123456789abcdef0123"), 0o600))
		err := DecryptFile(src, filepath.Join(dir, "out.db"), []byte("tiny"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create cipher")
	})

	t.Run("ciphertext shorter than nonce", func(t *testing.T) {
		src := filepath.Join(dir, "short2.enc")
		require.NoError(t, os.WriteFile(src, []byte{0x01, 0x02, 0x03, 0x04}, 0o600))
		err := DecryptFile(src, filepath.Join(dir, "out.db"), key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("tampered ciphertext fails authentication", func(t *testing.T) {
		src := filepath.Join(dir, "plain.bin")
		enc := filepath.Join(dir, "good.enc")
		require.NoError(t, os.WriteFile(src, []byte("attack at dawn"), 0o600))
		require.NoError(t, EncryptFile(src, enc, key))

		blob, err := os.ReadFile(enc)
		require.NoError(t, err)
		blob[len(blob)-1] ^= 0xFF
		require.NoError(t, os.WriteFile(enc, blob, 0o600)) // #nosec G703 -- enc is a test-local temp path

		err = DecryptFile(enc, filepath.Join(dir, "out.db"), key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("roundtrip preserves exact bytes", func(t *testing.T) {
		src := filepath.Join(dir, "roundtrip.bin")
		enc := filepath.Join(dir, "roundtrip.enc")
		out := filepath.Join(dir, "roundtrip.out")
		payload := []byte{0x00, 0x01, 0xFE, 0xFF, 'k', 'i', 't', 'e'}
		require.NoError(t, os.WriteFile(src, payload, 0o600))
		require.NoError(t, EncryptFile(src, enc, key))
		require.NoError(t, DecryptFile(enc, out, key))

		got, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})
}

func TestIsEncrypted_EdgeCases(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file is not encrypted", func(t *testing.T) {
		enc, err := IsEncrypted(filepath.Join(dir, "missing.db"))
		require.NoError(t, err)
		assert.False(t, enc)
	})

	t.Run("empty file is not encrypted", func(t *testing.T) {
		p := filepath.Join(dir, "empty.db")
		require.NoError(t, os.WriteFile(p, nil, 0o600))
		enc, err := IsEncrypted(p)
		require.NoError(t, err)
		assert.False(t, enc)
	})

	t.Run("short non-empty file counts as encrypted", func(t *testing.T) {
		p := filepath.Join(dir, "short.db")
		require.NoError(t, os.WriteFile(p, []byte{0xDE, 0xAD}, 0o600))
		enc, err := IsEncrypted(p)
		require.NoError(t, err)
		assert.True(t, enc)
	})

	t.Run("real sqlite file is not encrypted", func(t *testing.T) {
		p := filepath.Join(dir, "real.db")
		s, err := New(p)
		require.NoError(t, err)
		_, err = s.RawDB().ExecContext(context.Background(), `CREATE TABLE t (a INTEGER)`)
		require.NoError(t, err)
		require.NoError(t, s.Checkpoint(context.Background()))
		require.NoError(t, s.Close())

		enc, err := IsEncrypted(p)
		require.NoError(t, err)
		assert.False(t, enc)
	})

	t.Run("gcm blob counts as encrypted", func(t *testing.T) {
		p := filepath.Join(dir, "blob.enc")
		payload := make([]byte, 64)
		for i := range payload {
			payload[i] = byte(i * 3)
		}
		require.NoError(t, os.WriteFile(p, payload, 0o600))
		enc, err := IsEncrypted(p)
		require.NoError(t, err)
		assert.True(t, enc)
	})
}
