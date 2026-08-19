package osquery

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/store"
)

func tableSourceStub() *stubQuerier {
	return &stubQuerier{
		responses: map[string][]map[string]string{
			"osquery_registry": {
				{"name": "processes"},
				{"name": "curl"},       // requires a WHERE constraint → excluded
				{"name": "custom_ext"}, // not in the catalog → still served
			},
			`SELECT * FROM "processes"`: {
				{"pid": "1", "name": "systemd", "state": "running"},
				{"pid": "2", "name": "kthreadd", "state": "sleeping"},
			},
			`COUNT(*) AS n FROM "processes"`:                        {{"n": "42"}},
			`COUNT(DISTINCT "state")`:                               {{"n": "2"}},
			`COUNT(DISTINCT`:                                        {{"n": "9999"}}, // every other column: too many
			`AS v, COUNT(*) AS n FROM "processes" GROUP BY "state"`: {{"v": "running", "n": "30"}, {"v": "sleeping", "n": "12"}},
		},
	}
}

func TestTableSource_ListContentTables_ExcludesConstraintRequired(t *testing.T) {
	ts := newTableSourceWith(tableSourceStub())
	tables, err := ts.ListContentTables(context.Background())
	require.NoError(t, err)

	names := make([]string, 0, len(tables))
	for _, tbl := range tables {
		names = append(names, tbl.Name)
	}
	assert.Equal(t, []string{"custom_ext", "processes"}, names,
		"curl requires a WHERE constraint and must be excluded")

	var procs store.TableSchema
	for _, tbl := range tables {
		if tbl.Name == "processes" {
			procs = tbl
		}
	}
	assert.Contains(t, procs.Description, "All running processes")
	assert.EqualValues(t, -1, procs.RowCount)
	require.NotEmpty(t, procs.Columns)
	assert.Equal(t, "pid", procs.Columns[0].Name)
	assert.Equal(t, "Process (or thread) ID", procs.Columns[0].Description)
	assert.Empty(t, procs.PrimaryKey, "osquery tables have no primary key")
}

func TestTableSource_DaemonDownDegradesToEmptyCatalog(t *testing.T) {
	stub := &stubQuerier{errs: map[string]error{
		"osquery_registry": errors.New("dial unix: connection refused"),
	}}
	ts := newTableSourceWith(stub)

	tables, err := ts.ListContentTables(context.Background())
	require.NoError(t, err, "a dead optional backend must not error the catalog")
	assert.Empty(t, tables)

	_, err = ts.DescribeTable(context.Background(), "processes")
	assert.ErrorIs(t, err, store.ErrUnknownTable)
}

func TestTableSource_ListRows_TotalsAndPKLessRows(t *testing.T) {
	ts := newTableSourceWith(tableSourceStub())
	rows, total, err := ts.ListRows(context.Background(), store.RowsFilter{Table: "processes", Limit: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 42, total, "totals come from COUNT(*)")
	require.Len(t, rows, 2)
	assert.Empty(t, rows[0].PrimaryKey)
	// Catalog column order leads.
	assert.Equal(t, "pid", rows[0].Columns[0].Name)
	assert.Equal(t, "name", rows[0].Columns[1].Name)

	// Unknown WHERE column is rejected before SQL is assembled.
	_, _, err = ts.ListRows(context.Background(), store.RowsFilter{
		Table: "processes", WhereColumn: "nope", WhereValue: "x",
	})
	assert.ErrorIs(t, err, store.ErrUnknownColumn)

	// Constraint-required tables are not served at all.
	_, _, err = ts.ListRows(context.Background(), store.RowsFilter{Table: "curl"})
	assert.ErrorIs(t, err, store.ErrUnknownTable)
}

func TestTableSource_FacetTable_LowCardinalityColumnsOnly(t *testing.T) {
	ts := newTableSourceWith(tableSourceStub())
	facets, err := ts.FacetTable(context.Background(), "processes", 20, 5)
	require.NoError(t, err)
	require.Len(t, facets, 1, "only state has few distinct values in the stub")
	assert.Equal(t, "state", facets[0].Column)
	assert.EqualValues(t, 2, facets[0].Distinct)
	require.Len(t, facets[0].Values, 2)
	assert.Equal(t, "running", facets[0].Values[0].Value)
	assert.EqualValues(t, 30, facets[0].Values[0].Count)
}

func TestColumnOrder_CatalogFirstThenLiveExtras(t *testing.T) {
	rows := []map[string]string{{"pid": "1", "name": "x", "zz_extra": "v"}}
	order := ColumnOrder("processes", rows)
	require.NotEmpty(t, order)
	assert.Equal(t, "pid", order[0])
	assert.Equal(t, "name", order[1])
	assert.Equal(t, "zz_extra", order[len(order)-1])

	order = ColumnOrder("no_such_table", rows)
	assert.Equal(t, []string{"name", "pid", "zz_extra"}, order)
}
