package sqlite

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

func machineNames(t *testing.T, s store.Store) []string {
	t.Helper()
	machines, err := s.ListMachines(context.Background(), store.MachineFilter{})
	require.NoError(t, err)
	names := make([]string, 0, len(machines))
	for _, m := range machines {
		names = append(names, m.Hostname)
	}
	return names
}

func upsertHost(t *testing.T, s store.Store, hostname string) {
	t.Helper()
	_, _, err := s.UpsertMachines(context.Background(), []model.Machine{makeTestMachine(hostname, model.MachineTypeServer)})
	require.NoError(t, err)
}

// A second process opening the service's database (`status`, `doctor`,
// `dashboard`) used to decrypt the last snapshot over the service's live
// working copy, corrupting it under the open connection and discarding
// every write since that snapshot.
func TestEncryptedStore_SecondOpenerJoinsLiveWorkingCopy(t *testing.T) {
	ctx := context.Background()
	encPath := filepath.Join(t.TempDir(), "kite.db")
	key := testKey(t)

	svc, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, svc.Migrate(ctx))
	upsertHost(t, svc, "snapshotted")
	require.NoError(t, svc.Snapshot(ctx))
	upsertHost(t, svc, "live-only")

	cli, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"snapshotted", "live-only"}, machineNames(t, cli),
		"the second opener reads the live working copy, not the last snapshot")
	upsertHost(t, cli, "from-cli")
	require.NoError(t, cli.Close())
	assert.True(t, fileExists(svc.workPath), "a non-last closer must leave the shared working copy in place")

	upsertHost(t, svc, "after-cli")
	assert.ElementsMatch(t, []string{"snapshotted", "live-only", "from-cli", "after-cli"}, machineNames(t, svc))
	require.NoError(t, svc.Close())
	assert.False(t, fileExists(svc.workPath), "the last closer removes the working copy")

	again, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	assert.ElementsMatch(t, []string{"snapshotted", "live-only", "from-cli", "after-cli"}, machineNames(t, again))
}

// A non-last closer snapshots on the way out, so its writes reach the
// at-rest file even if the remaining holder dies before its own close.
func TestEncryptedStore_NonLastCloserSnapshotsItsWrites(t *testing.T) {
	ctx := context.Background()
	encPath := filepath.Join(t.TempDir(), "kite.db")
	key := testKey(t)

	svc, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })
	require.NoError(t, svc.Migrate(ctx))

	cli, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	upsertHost(t, cli, "from-cli")
	require.NoError(t, cli.Close())

	restored := filepath.Join(t.TempDir(), "restored.db")
	require.NoError(t, DecryptFile(encPath, restored, key))
	plain, err := New(restored)
	require.NoError(t, err)
	defer func() { _ = plain.Close() }()
	assert.Equal(t, []string{"from-cli"}, machineNames(t, plain))
}

func TestEncryptedStore_CloseTwiceIsANoOp(t *testing.T) {
	es, err := NewEncrypted(filepath.Join(t.TempDir(), "kite.db"), testKey(t), "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Close())
	require.NoError(t, es.Close())
}

// The service and a CLI command are separate processes; the OS locks must
// coordinate them, not just two stores inside one test binary.
func TestEncryptedStore_CrossProcessHolder(t *testing.T) {
	if os.Getenv("KITE_SHARE_HELPER") == "1" {
		runShareHelper(t)
		return
	}
	ctx := context.Background()
	encPath := filepath.Join(t.TempDir(), "kite.db")
	key := testKey(t)

	svc, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, svc.Migrate(ctx))
	upsertHost(t, svc, "service")

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEncryptedStore_CrossProcessHolder$") // #nosec G204,G702 -- re-executes this test binary
	cmd.Env = append(os.Environ(),
		"KITE_SHARE_HELPER=1", "KITE_SHARE_ENC="+encPath, "KITE_SHARE_KEY="+hex.EncodeToString(key))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	upsertHost(t, svc, "service-after")
	assert.ElementsMatch(t, []string{"service", "helper", "service-after"}, machineNames(t, svc))
	require.NoError(t, svc.Close())

	again, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	assert.ElementsMatch(t, []string{"service", "helper", "service-after"}, machineNames(t, again))
}

// runShareHelper is the second process: it must see the service's live
// write, add its own, and close without disturbing the service.
func runShareHelper(t *testing.T) {
	key, err := hex.DecodeString(os.Getenv("KITE_SHARE_KEY"))
	require.NoError(t, err)
	es, err := NewEncrypted(os.Getenv("KITE_SHARE_ENC"), key, "tpm", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Equal(t, []string{"service"}, machineNames(t, es))
	upsertHost(t, es, "helper")
	require.NoError(t, es.Close())
}
