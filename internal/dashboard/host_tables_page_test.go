package dashboard

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// TestHostScopedFragment_JoinsAssetStatus is the end-to-end check for the
// listeners/volumes tabs: a host row must render its owning asset's hostname
// and authorization status, and a facet on that status must filter in place.
func TestHostScopedFragment_JoinsAssetStatus(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/host.db"
	st, err := sqlite.New(path)
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	authorized := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: "auth-box",
		MachineType: model.MachineTypeServer, OSFamily: "linux",
		IsAuthorized: model.AuthorizationAuthorized, IsManaged: model.ManagedManaged,
		DiscoverySource: "agent", FirstSeenAt: now, LastSeenAt: now,
	}
	rogue := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: "rogue-box",
		MachineType: model.MachineTypeServer, OSFamily: "linux",
		IsAuthorized: model.AuthorizationUnauthorized, IsManaged: model.ManagedUnmanaged,
		DiscoverySource: "network", FirstSeenAt: now, LastSeenAt: now,
	}
	require.NoError(t, st.UpsertMachine(ctx, authorized))
	require.NoError(t, st.UpsertMachine(ctx, rogue))

	// Insert one listener per asset directly — the host tables are written by
	// the agent's generic host-table path, which the store doesn't expose a
	// typed method for; a raw insert on the same DB is the lightest seed.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	insert := `INSERT INTO host_listeners
		(id, machine_id, protocol, bind_address, port, exposure, process_name, username, last_seen_at, collected_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`
	ts := now.Format(time.RFC3339)
	_, err = db.ExecContext(ctx, insert, uuid.Must(uuid.NewV7()).String(), authorized.ID.String(),
		"tcp", "127.0.0.1", 22, "loopback", "sshd", "root", ts, ts)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, insert, uuid.Must(uuid.NewV7()).String(), rogue.ID.String(),
		"tcp", "0.0.0.0", 8000, "internet", "python", "app", ts, ts)
	require.NoError(t, err)

	tableSrc := store.NewCompositeTableSource(st)

	var all strings.Builder
	require.NoError(t, renderHostScopedFragment(&all, ctx, st, tableSrc, testContext(),
		listenersPageSpec, "", "", false))
	body := all.String()
	// Grid cells are matched as <td>..</td> because the same value also
	// appears in the facet rail (which is computed over ALL rows), so a bare
	// substring can't tell "in the grid" from "in the rail".
	assert.Contains(t, body, "<td>python</td>")
	assert.Contains(t, body, "<td>sshd</td>")
	assert.Contains(t, body, "auth-box", "the owning asset hostname is joined in")
	assert.Contains(t, body, "rogue-box")
	// The asset status rides each row and is offered as a facet.
	assert.Contains(t, body, "is_authorized")
	assert.Contains(t, body, "badge-red", "the unauthorized asset renders a red badge")

	// Facet on the asset status: only the rogue host's listener survives in
	// the grid (the rail still lists both buckets by design).
	var filtered strings.Builder
	require.NoError(t, renderHostScopedFragment(&filtered, ctx, st, tableSrc, testContext(),
		listenersPageSpec, "is_authorized", "unauthorized", true))
	fbody := filtered.String()
	assert.Contains(t, fbody, "<td>python</td>")
	assert.NotContains(t, fbody, "<td>sshd</td>", "the authorized host's listener is filtered out")
	assert.Contains(t, fbody, "1 of 2 rows")

	// Facet on a raw column (exposure) works the same way.
	var byExposure strings.Builder
	require.NoError(t, renderHostScopedFragment(&byExposure, ctx, st, tableSrc, testContext(),
		listenersPageSpec, "exposure", "internet", true))
	assert.Contains(t, byExposure.String(), "<td>python</td>")
	assert.NotContains(t, byExposure.String(), "<td>sshd</td>")
}

// TestVolumesFragment_RendersCapacityMetrics is the end-to-end check for the
// storage page: raw byte counters must render as human sizes plus a usage bar
// tinted by how full the volume is, and an unmeasured mount must read as
// "unknown" rather than "empty".
func TestVolumesFragment_RendersCapacityMetrics(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/vol.db"
	st, err := sqlite.New(path)
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: "disk-box",
		MachineType: model.MachineTypeServer, OSFamily: "linux",
		IsAuthorized: model.AuthorizationAuthorized, IsManaged: model.ManagedManaged,
		DiscoverySource: "agent", FirstSeenAt: now, LastSeenAt: now,
	}
	require.NoError(t, st.UpsertMachine(ctx, host))

	const gib = int64(1) << 30
	require.NoError(t, st.ReplaceHostVolumes(ctx, host.ID, []model.HostVolume{
		{ // 96% full -> crit tint
			MachineID: host.ID, MountPoint: "/", Device: "/dev/nvme0n1p2", Filesystem: "ext4",
			SizeBytes: uint64(100 * gib), UsedBytes: uint64(96 * gib),
			InodesTotal: 1_000_000, InodesUsed: 250_000,
			Encryption: "luks2", EncryptionState: "unlocked", Bootable: true,
			LastSeenAt: now, CollectedAt: now,
		},
		{ // 10% full -> ok tint
			MachineID: host.ID, MountPoint: "/data", Device: "/dev/sdb1", Filesystem: "xfs",
			SizeBytes: uint64(2000 * gib), UsedBytes: uint64(200 * gib),
			Encryption: "none", EncryptionState: "unknown",
			LastSeenAt: now, CollectedAt: now,
		},
		{ // unstattable mount -> no capacity at all
			MachineID: host.ID, MountPoint: "/private/var", Filesystem: "apfs",
			Encryption: "apfs-encrypted", EncryptionState: "unlocked",
			LastSeenAt: now, CollectedAt: now,
		},
	}))

	var out strings.Builder
	require.NoError(t, renderHostScopedFragment(&out, ctx, st, store.NewCompositeTableSource(st),
		testContext(), volumesPageSpec, "", "", false))
	body := out.String()

	assert.Contains(t, body, "disk-box", "the owning machine is joined in")
	// Sizes are humanized, never raw byte counts.
	assert.Contains(t, body, "100.00 GB", "capacity renders as a human size")
	assert.Contains(t, body, "1.95 TB", "a multi-TB volume does not render as thousands of GB")
	assert.NotContains(t, body, "107374182400", "the raw byte count never reaches the page")
	// Usage bars: the near-full root is flagged, the roomy volume is not.
	assert.Contains(t, body, `class="usage-fill usage-crit" style="width:96.0%"`)
	assert.Contains(t, body, `class="usage-fill usage-ok" style="width:10.0%"`)
	assert.Contains(t, body, `title="96.00 GB of 100.00 GB used"`, "the tooltip carries the absolute figures")
	// Inodes are a count ratio, not bytes.
	assert.Contains(t, body, "250,000 of 1,000,000 used", "inode counts are not formatted as bytes")
	// The unmeasured mount is explicitly unknown.
	assert.Contains(t, body, "&mdash;", "an unstattable mount shows as unknown, not 0 B")
	assert.NotContains(t, body, "0 B", "a missing measurement never renders as an empty disk")
}

// Unit-level guard on the cell formatter: the pieces the page test exercises
// end-to-end, plus the arithmetic edge cases a real filesystem produces.
func TestFormatHostCell_CapacityEdgeCases(t *testing.T) {
	bytesCol := hostTableColumn{Name: "size_bytes", Label: "Size", Format: cellBytes}
	ratioCol := hostTableColumn{Name: "used_bytes", Of: "size_bytes", Label: "Usage", Format: cellRatioBytes}

	assert.Equal(t, `<span class="muted">&mdash;</span>`,
		string(formatHostCell(bytesCol, map[string]string{})),
		"a NULL capacity is unknown, not zero")
	assert.Equal(t, `<span class="muted">&mdash;</span>`,
		string(formatHostCell(bytesCol, map[string]string{"size_bytes": "not-a-number"})),
		"a non-numeric capacity is unknown")
	assert.Contains(t, string(formatHostCell(bytesCol, map[string]string{"size_bytes": "1024"})), "1.0 KB")

	// A zero-sized volume can't be a ratio: dividing by it would be NaN.
	assert.Equal(t, `<span class="muted">&mdash;</span>`,
		string(formatHostCell(ratioCol, map[string]string{"used_bytes": "10", "size_bytes": "0"})),
		"a zero-size volume has no meaningful usage")

	// Root-reserved blocks let used exceed the reported total; the bar clamps
	// instead of overflowing its track.
	over := string(formatHostCell(ratioCol, map[string]string{"used_bytes": "110", "size_bytes": "100"}))
	assert.Contains(t, over, "width:100.0%", "the fill never exceeds the track")
	assert.Contains(t, over, "usage-crit")

	// Threshold boundaries: 75% warns, 90% is critical, below 75% is fine.
	assert.Contains(t, string(formatHostCell(ratioCol, map[string]string{"used_bytes": "74", "size_bytes": "100"})), "usage-ok")
	assert.Contains(t, string(formatHostCell(ratioCol, map[string]string{"used_bytes": "75", "size_bytes": "100"})), "usage-warn")
	assert.Contains(t, string(formatHostCell(ratioCol, map[string]string{"used_bytes": "90", "size_bytes": "100"})), "usage-crit")
}

// The formatter must not become an HTML injection route: a verbatim column
// carrying markup is escaped, exactly as the previous implementation did.
func TestFormatHostCell_EscapesVerbatimValues(t *testing.T) {
	col := hostTableColumn{Name: "device", Label: "Device"}
	got := string(formatHostCell(col, map[string]string{"device": `<script>alert(1)</script>`}))
	assert.NotContains(t, got, "<script>")
	assert.Contains(t, got, "&lt;script&gt;")
}
