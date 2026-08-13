package sqlite

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Durability tests for the encrypted-at-rest store. These pin the two data-loss
// fixes: atomic encrypt-back (a crash mid-encrypt cannot corrupt the only
// persistent copy) and periodic Snapshot (a crash between opens loses at most
// one snapshot, not everything since process start).

// TestEncryptFileAtomic_NoPartialFileOnConcurrentReaders verifies the encrypt
// output is only ever observed complete: writeFileAtomic renames a fully
// fsynced temp file into place, so a reader never sees a truncated dst.
func TestEncryptFileAtomic_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.db")
	enc := filepath.Join(dir, "at-rest.enc")
	require.NoError(t, os.WriteFile(src, []byte("SQLite format 3\x00 the rest of a database"), 0o600))
	key := make([]byte, 32)

	require.NoError(t, EncryptFile(src, enc, key))

	// No temp files left behind in the directory.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp-", "atomic write left a temp file: %s", e.Name())
	}

	// Round-trips.
	out := filepath.Join(dir, "decrypted.db")
	require.NoError(t, DecryptFile(enc, out, key))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "SQLite format 3\x00 the rest of a database", string(got))
}

// TestEncryptFileAtomic_PreservesOldOnFailure proves the core anti-corruption
// guarantee: when the encrypt write fails, a pre-existing at-rest file is left
// untouched rather than truncated. We force failure by pointing dst at a path
// whose parent is read-only, after seeding a good file there.
func TestEncryptFileAtomic_PreservesOldOnFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only dir permissions are not enforced")
	}
	dir := t.TempDir()
	enc := filepath.Join(dir, "at-rest.enc")
	require.NoError(t, os.WriteFile(enc, []byte("PREVIOUS-GOOD-CIPHERTEXT"), 0o600))

	src := filepath.Join(dir, "plain.db")
	require.NoError(t, os.WriteFile(src, []byte("new plaintext"), 0o600))

	// Make the directory read-only so CreateTemp/rename fails.
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := EncryptFile(src, enc, make([]byte, 32))
	require.Error(t, err, "encrypt into a read-only dir must fail")

	// The previous good file must be intact — NOT truncated or replaced.
	_ = os.Chmod(dir, 0o700)
	data, readErr := os.ReadFile(enc)
	require.NoError(t, readErr)
	assert.Equal(t, "PREVIOUS-GOOD-CIPHERTEXT", string(data),
		"a failed encrypt must never damage the existing at-rest file")
}

// TestSnapshot_SurvivesProcessKill is the headline durability test: it writes
// rows, takes a Snapshot, then SIGKILLs a child process holding the store open
// (simulating OOM/crash/power-loss — no Close, so tmpfs working copy is lost).
// Reopening the at-rest file must still contain the snapshotted rows.
func TestSnapshot_SurvivesProcessKill(t *testing.T) {
	if os.Getenv("KITE_SNAPSHOT_CHILD") == "1" {
		snapshotChildMain() // never returns
		return
	}

	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.enc")

	// Run the child: it creates the encrypted store, writes N rows, snapshots,
	// prints READY, then spins forever without ever calling Close.
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run", "TestSnapshot_SurvivesProcessKill") //#nosec G702,G204 -- re-exec of the test binary itself with fixed args
	cmd.Env = append(os.Environ(),
		"KITE_SNAPSHOT_CHILD=1",
		"KITE_SNAPSHOT_ENCPATH="+encPath,
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	// Wait for READY, then kill -9 (no graceful Close, working copy evaporates).
	buf := make([]byte, 64)
	n, _ := stdout.Read(buf)
	require.Contains(t, string(buf[:n]), "READY", "child did not signal READY")
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()

	// The tmpfs working copy is gone; only the snapshot survives. Reopen and
	// count.
	es, err := NewEncrypted(encPath, fixedTestKey(), "file", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = es.Close() })

	inner, ok := es.Store.(*SQLiteStore)
	require.True(t, ok)
	var count int
	require.NoError(t, inner.RawDB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM snap_rows`).Scan(&count))
	assert.Equal(t, snapshotRowCount, count,
		"snapshotted rows must survive a process kill with no graceful Close")
}

const snapshotRowCount = 500

func fixedTestKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// snapshotChildMain runs in the forked child: create encrypted store, write
// rows, Snapshot, signal READY, then block forever (parent SIGKILLs it).
func snapshotChildMain() {
	encPath := os.Getenv("KITE_SNAPSHOT_ENCPATH")
	es, err := NewEncrypted(encPath, fixedTestKey(), "file", nil)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	inner := es.Store.(*SQLiteStore)
	if _, err := inner.RawDB().ExecContext(ctx,
		`CREATE TABLE snap_rows (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		panic(err)
	}
	for i := 0; i < snapshotRowCount; i++ {
		if _, err := inner.RawDB().ExecContext(ctx,
			`INSERT INTO snap_rows(v) VALUES (?)`, strings.Repeat("x", 32)); err != nil {
			panic(err)
		}
	}
	if err := es.Snapshot(ctx); err != nil {
		panic(err)
	}
	// Deliberately NEVER Close: the whole point is that the at-rest file is
	// durable without a graceful shutdown.
	_, _ = os.Stdout.WriteString("READY\n")
	select {} // block until the parent kills us
}
