package store

import (
	"context"
	"errors"
	"fmt"
)

// CompositeTableSource merges several TableSources into one catalog. The
// first source is primary (the durable store); later sources are additive
// backends. On a table-name collision the earliest source wins, so a
// secondary can never shadow a durable table. A failing secondary degrades
// to absence instead of taking the whole catalog down — transparency also
// means a dead optional backend must not break the page.
type CompositeTableSource struct {
	sources []TableSource
}

var _ TableSource = (*CompositeTableSource)(nil)

// NewCompositeTableSource composes sources in priority order. At least one
// source (the primary) is required.
func NewCompositeTableSource(sources ...TableSource) *CompositeTableSource {
	return &CompositeTableSource{sources: sources}
}

// ListContentTables returns the merged catalog: every table of every source,
// earliest source winning name collisions. An error from the primary source
// is fatal; errors from secondaries drop that source's tables for this call.
func (c *CompositeTableSource) ListContentTables(ctx context.Context) ([]TableSchema, error) {
	var merged []TableSchema
	seen := map[string]bool{}
	for i, src := range c.sources {
		tables, err := src.ListContentTables(ctx)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			continue
		}
		for _, t := range tables {
			if seen[t.Name] {
				continue
			}
			seen[t.Name] = true
			merged = append(merged, t)
		}
	}
	return merged, nil
}

// route finds the first source that knows the table and runs fn against it.
// A source signals "not mine" with ErrUnknownTable; any other error is that
// source's authoritative answer.
func (c *CompositeTableSource) route(ctx context.Context, table string, fn func(TableSource) error) error {
	for _, src := range c.sources {
		err := fn(src)
		if err == nil || !errors.Is(err, ErrUnknownTable) {
			return err
		}
	}
	return fmt.Errorf("%w: %s", ErrUnknownTable, table)
}

// DescribeTable returns the schema from the first source that knows the table.
func (c *CompositeTableSource) DescribeTable(ctx context.Context, table string) (*TableSchema, error) {
	var schema *TableSchema
	err := c.route(ctx, table, func(src TableSource) error {
		s, err := src.DescribeTable(ctx, table)
		if err == nil {
			schema = s
		}
		return err
	})
	return schema, err
}

// ListRows pages rows from the first source that knows the table.
func (c *CompositeTableSource) ListRows(ctx context.Context, filter RowsFilter) ([]Row, int64, error) {
	var (
		rows  []Row
		total int64
	)
	err := c.route(ctx, filter.Table, func(src TableSource) error {
		r, t, err := src.ListRows(ctx, filter)
		if err == nil {
			rows, total = r, t
		}
		return err
	})
	return rows, total, err
}

// FacetTable computes facets via the first source that knows the table.
func (c *CompositeTableSource) FacetTable(ctx context.Context, table string, maxDistinct, topValues int) ([]ColumnFacet, error) {
	var facets []ColumnFacet
	err := c.route(ctx, table, func(src TableSource) error {
		f, err := src.FacetTable(ctx, table, maxDistinct, topValues)
		if err == nil {
			facets = f
		}
		return err
	})
	return facets, err
}
