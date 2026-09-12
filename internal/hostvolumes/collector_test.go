package hostvolumes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/volumes"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

type fakeCollector struct {
	list []volumes.Volume
	err  error
}

func (f fakeCollector) Name() string { return "fake" }
func (f fakeCollector) Collect(context.Context) ([]volumes.Volume, error) {
	return f.list, f.err
}

func seededStore(t *testing.T, discoverySource string) (*sqlite.SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/hv.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "seeded", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: discoverySource,
		IsAuthorized:    model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

func emptyStore(t *testing.T) *sqlite.SQLiteStore {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/hv.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// Happy path: capacity metrics and encryption posture reach host_volumes.
func TestCollectAndStore_PersistsCapacityMetrics(t *testing.T) {
	st, id := seededStore(t, "agent")
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	vc := fakeCollector{list: []volumes.Volume{
		{
			MountPoint: "/", Device: "/dev/nvme0n1p2", Filesystem: "ext4", MountOpts: "rw,relatime",
			Encryption: volumes.EncLUKS2, EncryptionState: volumes.EncStateUnlocked,
			SizeBytes: 500 << 30, UsedBytes: 460 << 30, InodesTotal: 30_000_000, InodesUsed: 900_000,
			Bootable: true, LastSeenAt: now, CollectedAt: now,
		},
		{
			MountPoint: "/media/usb", Device: "/dev/sdb1", Filesystem: "vfat",
			Encryption: volumes.EncNone, EncryptionState: volumes.EncStateUnknown,
			SizeBytes: 64 << 30, UsedBytes: 1 << 30, Removable: true, ReadOnly: true,
			LastSeenAt: now, CollectedAt: now,
		},
	}}

	c, ok := New(st, vc, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))

	got, err := st.ListHostVolumes(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 2)

	byMount := map[string]model.HostVolume{got[0].MountPoint: got[0], got[1].MountPoint: got[1]}
	root := byMount["/"]
	assert.EqualValues(t, 500<<30, root.SizeBytes)
	assert.EqualValues(t, 460<<30, root.UsedBytes)
	assert.InDelta(t, 92.0, root.UsedPercent(), 0.1, "a nearly-full root is reported as such")
	assert.EqualValues(t, 40<<30, root.FreeBytes())
	assert.Equal(t, "luks2", root.Encryption)
	assert.True(t, root.Bootable)

	usb := byMount["/media/usb"]
	assert.True(t, usb.Removable)
	assert.True(t, usb.ReadOnly)
	assert.Equal(t, "none", usb.Encryption, "an unencrypted removable volume is the CWE-311 signal")
}

// A per-mount probe failure still yields a partial inventory: some capacity
// beats none, and the alternative is a dashboard that empties out whenever one
// mount misbehaves.
func TestCollectAndStore_PartialInventoryIsStored(t *testing.T) {
	st, id := seededStore(t, "agent")
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	vc := fakeCollector{
		list: []volumes.Volume{{MountPoint: "/", SizeBytes: 100, UsedBytes: 50, LastSeenAt: now, CollectedAt: now}},
		err:  errors.New("statfs /private/var: permission denied"),
	}

	c, ok := New(st, vc, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()), "a partial collect is not an error")

	got, err := st.ListHostVolumes(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "unknown", got[0].Encryption, "an unprobed volume degrades to unknown, not none")
}

// A collect that produced nothing must not reach the store — pruning on a
// transient failure would wipe the machine's whole volume set.
func TestCollectAndStore_TotalFailureDoesNotPrune(t *testing.T) {
	st, id := seededStore(t, "agent")
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	good, ok := New(st, fakeCollector{list: []volumes.Volume{
		{MountPoint: "/", SizeBytes: 100, UsedBytes: 50, LastSeenAt: now, CollectedAt: now},
	}}, nil)
	require.True(t, ok)
	require.NoError(t, good.CollectAndStore(ctx))

	broken, ok := New(st, fakeCollector{err: errors.New("mount table unreadable")}, nil)
	require.True(t, ok)
	require.Error(t, broken.CollectAndStore(ctx))

	got, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 1, "the previous inventory survives a failed collect")
}

// Before the first scan writes the local machine there is nothing to attach
// volumes to; that is a quiet no-op, not an error the agent logs every cycle.
func TestCollectAndStore_NoLocalMachineIsQuietNoOp(t *testing.T) {
	st := emptyStore(t)
	c, ok := New(st, fakeCollector{list: []volumes.Volume{{MountPoint: "/"}}}, nil)
	require.True(t, ok)
	assert.NoError(t, c.CollectAndStore(context.Background()))
}

// A collector that leaves timestamps unset still produces storable rows.
func TestCollectAndStore_FillsMissingTimestamps(t *testing.T) {
	st, id := seededStore(t, "local_controller")
	c, ok := New(st, fakeCollector{list: []volumes.Volume{{MountPoint: "/", SizeBytes: 10, UsedBytes: 1}}}, nil)
	require.True(t, ok)
	require.NoError(t, c.CollectAndStore(context.Background()))

	got, err := st.ListHostVolumes(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.False(t, got[0].CollectedAt.IsZero(), "a missing collected_at is filled at store time")
	assert.False(t, got[0].LastSeenAt.IsZero())
}
