package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// TestContainersFragment_FacetsAndInPlaceFilter drives the fixture engine
// (web+worker running under "vie", adhoc exited standalone) and checks the
// facet rail narrows the grid in place while the poll URL keeps the filter.
func TestContainersFragment_FacetsAndInPlaceFilter(t *testing.T) {
	cc := newTestContainersController(t)
	cc.markViewed(nil)
	cc.tick(context.Background())

	var all strings.Builder
	require.NoError(t, cc.renderContainersFragment(&all, context.Background(), nil, nil, false, containerFilter{}))
	unfiltered := all.String()
	assert.Contains(t, unfiltered, "facet-rail", "the facet rail renders")
	assert.Contains(t, unfiltered, "<code>state</code>", "state is offered as a facet")
	assert.Contains(t, unfiltered, "<strong>web</strong>")
	assert.Contains(t, unfiltered, "<strong>adhoc</strong>")

	var filtered strings.Builder
	require.NoError(t, cc.renderContainersFragment(&filtered, context.Background(), nil, nil, false,
		newContainerFilter("state", "exited", true)))
	body := filtered.String()
	assert.Contains(t, body, "<strong>adhoc</strong>", "the exited container stays")
	assert.NotContains(t, body, "<strong>web</strong>", "running containers are filtered out")
	assert.NotContains(t, body, "<strong>worker</strong>")
	assert.Contains(t, body, "1 of 3 rows", "the chip reports the narrowed count")
	// The filter rides the auto-refresh URL, so a poll keeps it instead of
	// snapping back to every container.
	assert.Contains(t, body, "fcol=state")
	assert.Contains(t, body, "fval=exited")
}

// TestContainersFragment_HostAssetStatusBanner checks the page shows the
// authorization/managed status of the host these containers run on.
func TestContainersFragment_HostAssetStatusBanner(t *testing.T) {
	cc := newTestContainersController(t)
	st := testStore(t)
	cc.store = st

	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	// DiscoverySource local_controller makes resolveLocalAsset pick this row
	// via its fallback, regardless of the test host's real hostname.
	require.NoError(t, st.UpsertMachine(context.Background(), model.Machine{
		ID: uuid.Must(uuid.NewV7()), Hostname: "docker-host-01",
		MachineType: model.MachineTypeServer, OSFamily: "linux",
		IsAuthorized: model.AuthorizationUnauthorized, IsManaged: model.ManagedUnmanaged,
		DiscoverySource: "local_controller", FirstSeenAt: now, LastSeenAt: now,
	}))

	cc.markViewed(nil)
	cc.tick(context.Background())
	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "docker-host-01", "the host asset banner names the host")
	assert.Contains(t, body, "unauthorized", "and shows its authorization status")
	assert.Contains(t, body, "badge-red", "an unauthorized host renders a red badge")
}
