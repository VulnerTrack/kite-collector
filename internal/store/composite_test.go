package store

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSource is a minimal TableSource for composite tests.
type fakeSource struct {
	tables  []TableSchema
	listErr error
}

func (f *fakeSource) ListContentTables(context.Context) ([]TableSchema, error) {
	return f.tables, f.listErr
}

func (f *fakeSource) DescribeTable(_ context.Context, table string) (*TableSchema, error) {
	for i := range f.tables {
		if f.tables[i].Name == table {
			return &f.tables[i], nil
		}
	}
	return nil, ErrUnknownTable
}

func (f *fakeSource) ListRows(_ context.Context, filter RowsFilter) ([]Row, int64, error) {
	if _, err := f.DescribeTable(context.Background(), filter.Table); err != nil {
		return nil, 0, err
	}
	return []Row{{PrimaryKey: map[string]string{}}}, 1, nil
}

func (f *fakeSource) FacetTable(_ context.Context, table string, _, _ int) ([]ColumnFacet, error) {
	if _, err := f.DescribeTable(context.Background(), table); err != nil {
		return nil, err
	}
	return []ColumnFacet{{Column: "c"}}, nil
}

func TestCompositeTableSource_MergesWithFirstSourceWinning(t *testing.T) {
	primary := &fakeSource{tables: []TableSchema{
		{Name: "machines", Description: "durable"},
	}}
	secondary := &fakeSource{tables: []TableSchema{
		{Name: "machines", Description: "SHADOW"},
		{Name: "processes", Description: "live"},
	}}
	c := NewCompositeTableSource(primary, secondary)

	tables, err := c.ListContentTables(context.Background())
	require.NoError(t, err)
	require.Len(t, tables, 2)
	assert.Equal(t, "machines", tables[0].Name)
	assert.Equal(t, "durable", tables[0].Description, "primary wins collisions")
	assert.Equal(t, "processes", tables[1].Name)

	schema, err := c.DescribeTable(context.Background(), "machines")
	require.NoError(t, err)
	assert.Equal(t, "durable", schema.Description)

	schema, err = c.DescribeTable(context.Background(), "processes")
	require.NoError(t, err)
	assert.Equal(t, "live", schema.Description)

	_, err = c.DescribeTable(context.Background(), "nope")
	assert.ErrorIs(t, err, ErrUnknownTable)

	rows, total, err := c.ListRows(context.Background(), RowsFilter{Table: "processes"})
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.EqualValues(t, 1, total)

	facets, err := c.FacetTable(context.Background(), "processes", 20, 5)
	require.NoError(t, err)
	assert.Len(t, facets, 1)
}

func TestCompositeTableSource_FailingSecondaryDegrades_FailingPrimaryIsFatal(t *testing.T) {
	primary := &fakeSource{tables: []TableSchema{{Name: "machines"}}}
	dead := &fakeSource{listErr: errors.New("daemon down")}

	tables, err := NewCompositeTableSource(primary, dead).ListContentTables(context.Background())
	require.NoError(t, err)
	assert.Len(t, tables, 1)

	_, err = NewCompositeTableSource(dead, primary).ListContentTables(context.Background())
	assert.Error(t, err, "the primary source's failure is authoritative")
}
