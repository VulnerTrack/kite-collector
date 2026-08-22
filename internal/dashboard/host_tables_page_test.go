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
	_, err = db.Exec(insert, uuid.Must(uuid.NewV7()).String(), authorized.ID.String(),
		"tcp", "127.0.0.1", 22, "loopback", "sshd", "root", ts, ts)
	require.NoError(t, err)
	_, err = db.Exec(insert, uuid.Must(uuid.NewV7()).String(), rogue.ID.String(),
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
