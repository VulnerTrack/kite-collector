package osquery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func explorerStub() *stubQuerier {
	return &stubQuerier{
		responses: map[string][]map[string]string{
			"osquery_registry": {
				{"name": "processes"},
				{"name": "apps"},
				{"name": "osquery_info"},
			},
			`FROM "processes"`: {
				{"pid": "1", "name": "systemd", "custom_col": "x"},
				{"pid": "2", "name": "kthreadd", "custom_col": "y"},
			},
		},
		errs: map[string]error{
			`FROM "apps"`: &queryError{method: "query", code: 1, message: "Table apps was queried without a required column"},
		},
	}
}

func TestExplorer_LiveTablesSorted(t *testing.T) {
	e := newExplorerWith(explorerStub())
	names, err := e.LiveTables(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"apps", "osquery_info", "processes"}, names)
}

func TestExplorer_TableRows_ValidatesAgainstRegistry(t *testing.T) {
	e := newExplorerWith(explorerStub())

	rows, err := e.TableRows(context.Background(), "processes", 10)
	require.NoError(t, err)
	assert.Len(t, rows, 2)

	// A table the daemon does not serve is rejected before any SQL is built.
	_, err = e.TableRows(context.Background(), "not_served; DROP TABLE x", 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not served")
}

func TestExplorer_TableRows_SurfacesDaemonRejectionLoudly(t *testing.T) {
	e := newExplorerWith(explorerStub())
	_, err := e.TableRows(context.Background(), "apps", 10)
	require.Error(t, err)
	assert.True(t, IsQueryError(err), "the daemon's own rejection must stay recognizable")
	assert.Contains(t, err.Error(), "required column")
}

func TestColumnOrder_CatalogFirstThenLiveExtras(t *testing.T) {
	rows := []map[string]string{{"pid": "1", "name": "x", "zz_extra": "v"}}
	order := ColumnOrder("processes", rows)
	require.NotEmpty(t, order)
	// Catalog order: pid then name lead the processes schema.
	assert.Equal(t, "pid", order[0])
	assert.Equal(t, "name", order[1])
	// Live-only columns come last.
	assert.Equal(t, "zz_extra", order[len(order)-1])

	// Unknown tables fall back to sorted live columns.
	order = ColumnOrder("no_such_table", rows)
	assert.Equal(t, []string{"name", "pid", "zz_extra"}, order)
}
