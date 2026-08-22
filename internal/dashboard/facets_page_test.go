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
	"github.com/vulnertrack/kite-collector/internal/store"
)

// seedTwoMachines inserts one authorized and one unauthorized machine so a
// facet on is_authorized has two distinct buckets to split.
func seedTwoMachines(t *testing.T, st store.Store) context.Context {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	_, _, err := st.UpsertMachines(ctx, []model.Machine{
		{
			ID: uuid.Must(uuid.NewV7()), Hostname: "auth-host",
			MachineType: model.MachineTypeServer, OSFamily: "linux",
			IsAuthorized: model.AuthorizationAuthorized, IsManaged: model.ManagedManaged,
			DiscoverySource: "agent", FirstSeenAt: now, LastSeenAt: now,
		},
		{
			ID: uuid.Must(uuid.NewV7()), Hostname: "unauth-host",
			MachineType: model.MachineTypeWorkstation, OSFamily: "windows",
			IsAuthorized: model.AuthorizationUnauthorized, IsManaged: model.ManagedUnmanaged,
			DiscoverySource: "network", FirstSeenAt: now, LastSeenAt: now,
		},
	})
	require.NoError(t, err)
	return ctx
}

func TestBuildPageFacets(t *testing.T) {
	cols := []pageFacetColumn{
		{Name: "os_family", Values: []string{"linux", "linux", "windows", "linux"}},
		{Name: "is_authorized", Values: []string{"authorized", "unauthorized", "authorized", "unknown"}},
		// High-cardinality: distinct == row count > maxDistinct(3) → dropped.
		{Name: "hostname", Values: []string{"a", "b", "c", "d"}},
	}

	facets := buildPageFacets(cols, 3, 5, "os_family", "linux", true)

	require.Len(t, facets, 2, "the high-cardinality column must be dropped")
	// Cards are ordered by column name.
	assert.Equal(t, "is_authorized", facets[0].Column)
	assert.Equal(t, "os_family", facets[1].Column)

	os := facets[1]
	assert.Equal(t, 2, os.Distinct)
	// Values ordered by count desc: linux(3) then windows(1).
	require.Len(t, os.Values, 2)
	assert.Equal(t, "linux", os.Values[0].Value)
	assert.EqualValues(t, 3, os.Values[0].Count)
	assert.True(t, os.Values[0].Selected, "the active filter value is marked selected")
	assert.False(t, os.Values[1].Selected)
}

func TestBuildPageFacets_TopNCap(t *testing.T) {
	vals := []string{"a", "a", "b", "b", "b", "c", "d", "e"}
	facets := buildPageFacets([]pageFacetColumn{{Name: "c", Values: vals}}, 20, 2, "", "", false)
	require.Len(t, facets, 1)
	assert.Equal(t, 5, facets[0].Distinct, "distinct counts all values, not just the shown top-N")
	assert.Len(t, facets[0].Values, 2, "only the top-N values are listed")
	assert.Equal(t, "b", facets[0].Values[0].Value, "most common first")
}

func TestPageFacetKeepAndPick(t *testing.T) {
	cols := []pageFacetColumn{
		{Name: "state", Values: []string{"running", "exited", "running"}},
	}
	rows := []string{"web", "db", "cache"}

	// No filter → keep everything (nil mask).
	assert.Nil(t, pageFacetKeep(cols, "", "", false))
	assert.Equal(t, rows, pickByIndex(rows, pageFacetKeep(cols, "", "", false)))

	// Filter on a present column/value → only matching indices.
	keep := pageFacetKeep(cols, "state", "running", true)
	assert.Equal(t, []int{0, 2}, keep)
	assert.Equal(t, []string{"web", "cache"}, pickByIndex(rows, keep))

	// Filter on a column that isn't a candidate → nil (keep all), so a stale
	// or hand-typed fcol never silently blanks the grid.
	assert.Nil(t, pageFacetKeep(cols, "nonexistent", "x", true))

	// Filter on the empty bucket.
	empty := []pageFacetColumn{{Name: "health", Values: []string{"", "ok", ""}}}
	assert.Equal(t, []int{0, 2}, pageFacetKeep(empty, "health", "", true))
}

func TestRenderFacetRail(t *testing.T) {
	// Empty + unfiltered → no rail at all.
	html, err := renderFacetRail(facetRailView{BasePath: "/machines"})
	require.NoError(t, err)
	assert.Empty(t, string(html))

	facets := []pageFacet{{
		Column: "is_authorized", Distinct: 2,
		Values: []pageFacetValue{
			{Value: "authorized", Count: 3},
			{Value: "unauthorized", Count: 1, Selected: false},
		},
	}}
	html, err = renderFacetRail(facetRailView{
		BasePath: "/machines", Facets: facets, Filtered: true,
		FilterCol: "is_authorized", FilterVal: "unauthorized", Shown: 1, Total: 4,
	})
	require.NoError(t, err)
	out := string(html)
	// Links carry the base path and the escaped facet query, and stay on the
	// curated page rather than bouncing to /tables.
	assert.Contains(t, out, `hx-get="/machines?fcol=is_authorized&amp;fval=authorized"`)
	assert.NotContains(t, out, "/tables/")
	// The active-filter chip reports the narrowed count and offers a clear.
	assert.Contains(t, out, "1 of 4 rows")
	assert.Contains(t, out, `href="/machines"`)
}

// TestMachinesFragment_FiltersInPlace is the end-to-end check for the curated
// path: a facet selection narrows the grid while keeping the machines columns.
func TestMachinesFragment_FiltersInPlace(t *testing.T) {
	st := testStore(t)
	ctx := seedTwoMachines(t, st)

	var all strings.Builder
	require.NoError(t, renderMachinesFragment(&all, ctx, st, testContext(), "", "", false))
	// Anchor text is matched with delimiters because "auth-host" is a
	// substring of "unauth-host".
	assert.Contains(t, all.String(), ">auth-host</a>")
	assert.Contains(t, all.String(), ">unauth-host</a>")
	// The rail is present and offers the asset-status facet.
	assert.Contains(t, all.String(), "is_authorized")

	var filtered strings.Builder
	require.NoError(t, renderMachinesFragment(&filtered, ctx, st, testContext(),
		"is_authorized", "unauthorized", true))
	body := filtered.String()
	assert.Contains(t, body, ">unauth-host</a>", "the matching machine stays")
	assert.NotContains(t, body, ">auth-host</a>", "the non-matching machine is filtered out")
	assert.Contains(t, body, "Clear", "an active filter renders a clear affordance")
	// The rail still shows both authorization buckets (facets over all rows).
	assert.Contains(t, body, "facet-selected")
}
