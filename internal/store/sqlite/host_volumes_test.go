package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func newVolumeStore(t *testing.T) (*SQLiteStore, uuid.UUID) {
	t.Helper()
	st, err := New(t.TempDir() + "/hv.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	id := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: id, Hostname: "hv-host", MachineType: model.MachineTypeServer, OSFamily: "linux",
		DiscoverySource: "agent", IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: now, LastSeenAt: now,
	}))
	return st, id
}

// Happy path: every field round-trips, ordered by mount point.
func TestReplaceHostVolumes_RoundTrip(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	in := []model.HostVolume{
		{
			MachineID: id, MountPoint: "/home", Device: "/dev/nvme0n1p3", Filesystem: "ext4",
			Label: "data", FSUUID: "abcd-1234", MountOpts: "rw,relatime",
			Encryption: "luks2", EncryptionState: "unlocked",
			SizeBytes: 500 * 1024 * 1024 * 1024, UsedBytes: 300 * 1024 * 1024 * 1024,
			InodesTotal: 32_768_000, InodesUsed: 1_200_000,
			LastSeenAt: now, CollectedAt: now,
		},
		{
			MachineID: id, MountPoint: "/", Device: "/dev/nvme0n1p2", Filesystem: "btrfs",
			Encryption: "none", EncryptionState: "unknown", Bootable: true, ReadOnly: false,
			SizeBytes: 100 * 1024 * 1024 * 1024, UsedBytes: 42 * 1024 * 1024 * 1024,
			LastSeenAt: now, CollectedAt: now,
		},
	}
	require.NoError(t, st.ReplaceHostVolumes(ctx, id, in))

	got, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Ordered by mount point: "/" then "/home".
	assert.Equal(t, "/", got[0].MountPoint)
	assert.True(t, got[0].Bootable)
	assert.Equal(t, "none", got[0].Encryption)
	assert.EqualValues(t, 100*1024*1024*1024, got[0].SizeBytes)
	assert.EqualValues(t, 42*1024*1024*1024, got[0].UsedBytes)

	assert.Equal(t, "/home", got[1].MountPoint)
	assert.Equal(t, "/dev/nvme0n1p3", got[1].Device)
	assert.Equal(t, "ext4", got[1].Filesystem)
	assert.Equal(t, "data", got[1].Label)
	assert.Equal(t, "abcd-1234", got[1].FSUUID)
	assert.Equal(t, "rw,relatime", got[1].MountOpts)
	assert.Equal(t, "luks2", got[1].Encryption)
	assert.Equal(t, "unlocked", got[1].EncryptionState)
	assert.EqualValues(t, 32_768_000, got[1].InodesTotal)
	assert.EqualValues(t, 1_200_000, got[1].InodesUsed)
	assert.NotEqual(t, uuid.Nil, got[1].ID, "a zero ID is filled with a UUIDv7")
	assert.Equal(t, now, got[1].CollectedAt.UTC())
}

// A rescan keeps the row identity for a mount that is still there (so the
// capacity timeline stays attached to one row) and drops one that is gone.
func TestReplaceHostVolumes_UpsertsAndPrunes(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx := context.Background()
	first := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/", SizeBytes: 100, UsedBytes: 40, Encryption: "none", EncryptionState: "unknown", CollectedAt: first, LastSeenAt: first},
		{MachineID: id, MountPoint: "/media/usb", SizeBytes: 64, UsedBytes: 8, Encryption: "none", EncryptionState: "unknown", Removable: true, CollectedAt: first, LastSeenAt: first},
	}))
	before, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, before, 2)
	rootID := before[0].ID

	// Second pass: the USB stick is unplugged, / has filled up.
	second := first.Add(5 * time.Minute)
	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/", SizeBytes: 100, UsedBytes: 91, Encryption: "none", EncryptionState: "unknown", CollectedAt: second, LastSeenAt: second},
	}))

	after, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, after, 1, "the unplugged volume is pruned, not left stale")
	assert.Equal(t, "/", after[0].MountPoint)
	assert.Equal(t, rootID, after[0].ID, "a surviving mount keeps its row identity across rescans")
	assert.EqualValues(t, 91, after[0].UsedBytes, "capacity is refreshed in place")
}

// An unstattable mount stores NULL capacity, which reads back as zero — the
// caller distinguishes it from a real zero via SizeBytes == 0.
func TestReplaceHostVolumes_UnmeasuredCapacityIsNull(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/private/var", Encryption: "apfs-encrypted", EncryptionState: "unlocked", CollectedAt: now, LastSeenAt: now},
	}))

	got, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Zero(t, got[0].SizeBytes)
	assert.Zero(t, got[0].UsedBytes)
	assert.Zero(t, got[0].UsedPercent(), "an unmeasured volume is not 'full'")

	var nullSize bool
	require.NoError(t, st.db.QueryRowContext(ctx,
		`SELECT size_bytes IS NULL FROM host_volumes WHERE machine_id = ?`, id.String()).Scan(&nullSize))
	assert.True(t, nullSize, "zero capacity is stored as NULL, not 0")
}

// Values outside the CHECK enums fall back to "unknown" instead of failing the
// whole transaction, and a row without a mount point is skipped.
func TestReplaceHostVolumes_EdgeCases(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "", SizeBytes: 1, CollectedAt: now, LastSeenAt: now},
		{MachineID: id, MountPoint: "/odd", Encryption: "veracrypt", EncryptionState: "sealed", SizeBytes: 10, UsedBytes: 5, CollectedAt: now, LastSeenAt: now},
	}))

	got, err := st.ListHostVolumes(ctx, id)
	require.NoError(t, err)
	require.Len(t, got, 1, "the row without a mount point is skipped")
	assert.Equal(t, "/odd", got[0].MountPoint)
	assert.Equal(t, "unknown", got[0].Encryption, "an out-of-enum scheme degrades to unknown")
	assert.Equal(t, "unknown", got[0].EncryptionState)
}

// synced_at is cleared on every upsert: capacity is time-varying, so a rescan
// always produces something new for the sync bridge to ship.
func TestReplaceHostVolumes_ResetsSyncedAt(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx := context.Background()
	first := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/", SizeBytes: 100, UsedBytes: 10, Encryption: "none", EncryptionState: "unknown", CollectedAt: first, LastSeenAt: first},
	}))
	_, err := st.db.ExecContext(ctx,
		`UPDATE host_volumes SET synced_at = 1 WHERE machine_id = ?`, id.String())
	require.NoError(t, err)

	require.NoError(t, st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/", SizeBytes: 100, UsedBytes: 20, Encryption: "none", EncryptionState: "unknown", CollectedAt: first.Add(time.Minute), LastSeenAt: first.Add(time.Minute)},
	}))

	var synced *int64
	require.NoError(t, st.db.QueryRowContext(ctx,
		`SELECT synced_at FROM host_volumes WHERE machine_id = ?`, id.String()).Scan(&synced))
	assert.Nil(t, synced, "a refreshed capacity row is unsynced again")
}

// Error path: a cancelled context fails the replace before any write.
func TestReplaceHostVolumes_CancelledContextErrors(t *testing.T) {
	st, id := newVolumeStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := st.ReplaceHostVolumes(ctx, id, []model.HostVolume{
		{MachineID: id, MountPoint: "/", SizeBytes: 1, Encryption: "none", EncryptionState: "unknown"},
	})
	require.Error(t, err, "a cancelled context must fail the transaction")
}
