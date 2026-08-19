package osquery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/osquery/schema"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// TableSource adapts a live osqueryd to store.TableSource, so every table
// the daemon serves renders through the dashboard's generic catalog, grid,
// facet, and SQL-strip machinery exactly like a kite.db table — the UI never
// knows the source. The embedded schema catalog supplies descriptions and
// column documentation; the daemon supplies the data.
//
// Transparency rules:
//   - A dead or absent daemon degrades to an empty catalog, never an error:
//     an optional backend must not break the page.
//   - Tables whose virtual implementation requires a WHERE constraint
//     (curl, file, hash…) are excluded — a bare SELECT against them cannot
//     produce rows, so listing them in a generic grid would misinform.
//   - Table names are validated against the daemon's own registry before any
//     SQL is assembled; values are escaped, identifiers quoted.
type TableSource struct {
	client querier
}

var _ store.TableSource = (*TableSource)(nil)

// tableSourceProbeTimeout bounds each facet/count probe so an expensive
// virtual table cannot stall the page, mirroring the SQLite store's policy.
const tableSourceProbeTimeout = 2 * time.Second

// NewTableSource returns a TableSource over the resolved osqueryd socket
// (KITE_OSQUERY_SOCKET → platform defaults). It is safe to construct when no
// daemon exists: every catalog call degrades to empty.
func NewTableSource() *TableSource {
	return &TableSource{client: NewClient(resolveSocket(nil))}
}

// newTableSourceWith is the testing seam.
func newTableSourceWith(q querier) *TableSource {
	return &TableSource{client: q}
}

// liveTables returns the daemon's served table names, or nil when the daemon
// is unreachable.
func (t *TableSource) liveTables(ctx context.Context) map[string]bool {
	rows, err := t.client.Query(ctx,
		"SELECT name FROM osquery_registry WHERE registry = 'table' AND active = 1;")
	if err != nil {
		return nil
	}
	live := make(map[string]bool, len(rows))
	for _, row := range rows {
		if name := strings.TrimSpace(row["name"]); name != "" {
			live[name] = true
		}
	}
	return live
}

// buildSchema assembles a TableSchema for a live table from the embedded
// catalog: documented columns (visible only — SELECT * omits hidden ones),
// descriptions, and no primary key (osquery tables have none). Uncataloged
// tables (extensions, version drift) get an empty column set; the grid
// derives headers from the rows it renders.
func buildSchema(name string) store.TableSchema {
	ts := store.TableSchema{Name: name, RowCount: -1}
	cat, ok := schema.Lookup(name)
	if !ok {
		return ts
	}
	ts.Description = cat.Description
	pos := 0
	for _, col := range cat.Columns {
		if col.Hidden {
			continue
		}
		pos++
		ts.Columns = append(ts.Columns, store.ColumnSchema{
			Name:        col.Name,
			Type:        col.Type,
			Position:    pos,
			Description: col.Description,
		})
	}
	return ts
}

// requiresConstraint reports whether the cataloged table cannot answer a
// bare SELECT (it demands a WHERE on specific columns).
func requiresConstraint(name string) bool {
	cat, ok := schema.Lookup(name)
	return ok && len(cat.RequiredColumns()) > 0
}

// ListContentTables returns every table the daemon serves that a generic
// grid can meaningfully render. Row counts are -1: counting would execute
// every virtual table on each catalog load.
func (t *TableSource) ListContentTables(ctx context.Context) ([]store.TableSchema, error) {
	live := t.liveTables(ctx)
	tables := make([]store.TableSchema, 0, len(live))
	for name := range live {
		if requiresConstraint(name) {
			continue
		}
		tables = append(tables, buildSchema(name))
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return tables, nil
}

// DescribeTable returns the schema of one served table, or ErrUnknownTable —
// which is also the composite's "not mine" signal — for anything the daemon
// does not serve (including constraint-required tables and daemon-down).
func (t *TableSource) DescribeTable(ctx context.Context, table string) (*store.TableSchema, error) {
	if !t.liveTables(ctx)[table] || requiresConstraint(table) {
		return nil, store.ErrUnknownTable
	}
	ts := buildSchema(table)
	return &ts, nil
}

// columnExistsIn reports whether the cataloged (visible) schema carries the
// column. Uncataloged tables accept no column-addressed operations.
func columnExistsIn(ts *store.TableSchema, name string) bool {
	for _, c := range ts.Columns {
		if c.Name == name {
			return true
		}
	}
	return false
}

// ListRows pages rows from one served table, honoring the same RowsFilter
// contract as the SQLite store: validated WHERE equality (empty value =
// NULL-or-” bucket), clamped limit, exact filtered totals.
func (t *TableSource) ListRows(ctx context.Context, filter store.RowsFilter) ([]store.Row, int64, error) {
	ts, err := t.DescribeTable(ctx, filter.Table)
	if err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = store.IntrospectionDefaultPageSize
	}
	if limit > store.IntrospectionRowLimit {
		limit = store.IntrospectionRowLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	where := ""
	if filter.WhereColumn != "" {
		if !columnExistsIn(ts, filter.WhereColumn) {
			return nil, 0, store.ErrUnknownColumn
		}
		col := `"` + filter.WhereColumn + `"`
		if filter.WhereValue == "" {
			where = ` WHERE (` + col + ` IS NULL OR ` + col + ` = '')`
		} else {
			where = ` WHERE ` + col + ` = '` + sqlEscape(filter.WhereValue) + `'`
		}
	}
	if filter.OrderBy != "" && !columnExistsIn(ts, filter.OrderBy) {
		return nil, 0, store.ErrUnknownColumn
	}
	order := ""
	if filter.OrderBy != "" {
		order = ` ORDER BY "` + filter.OrderBy + `"`
	}

	ident := strings.ReplaceAll(filter.Table, `"`, `""`)
	q := fmt.Sprintf(`SELECT * FROM "%s"%s%s LIMIT %d OFFSET %d;`, ident, where, order, limit, offset)
	raw, err := t.client.Query(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("osquery rows %s: %w", filter.Table, err)
	}

	order2 := ColumnOrder(filter.Table, raw)
	rows := make([]store.Row, 0, len(raw))
	for _, m := range raw {
		row := store.Row{PrimaryKey: map[string]string{}}
		for _, name := range order2 {
			if v, ok := m[name]; ok {
				row.Columns = append(row.Columns, store.ColumnValue{Name: name, Value: v})
			}
		}
		rows = append(rows, row)
	}

	// Exact totals cost one COUNT(*) pass over the virtual table, bounded so
	// a pathological table degrades the pager instead of the page.
	total := int64(-1)
	countCtx, cancel := context.WithTimeout(ctx, tableSourceProbeTimeout)
	countRows, countErr := t.client.Query(countCtx, fmt.Sprintf(`SELECT COUNT(*) AS n FROM "%s"%s;`, ident, where))
	cancel()
	if countErr == nil && len(countRows) == 1 {
		if _, scanErr := fmt.Sscan(countRows[0]["n"], &total); scanErr != nil {
			total = -1
		}
	}
	if total < 0 {
		total = int64(offset + len(rows))
	}
	return rows, total, nil
}

// FacetTable computes value facets for one served table, mirroring the
// SQLite store's contract: cataloged visible columns only, probe-bounded.
func (t *TableSource) FacetTable(ctx context.Context, table string, maxDistinct, topValues int) ([]store.ColumnFacet, error) {
	ts, err := t.DescribeTable(ctx, table)
	if err != nil {
		return nil, err
	}
	if maxDistinct <= 0 {
		maxDistinct = 20
	}
	if topValues <= 0 {
		topValues = 5
	}

	const (
		maxColumns = 24
		maxFacets  = 6
	)
	ident := strings.ReplaceAll(table, `"`, `""`)
	var facets []store.ColumnFacet
	probed := 0
	for _, col := range ts.Columns {
		if len(facets) >= maxFacets || probed >= maxColumns {
			break
		}
		probed++
		colIdent := `"` + col.Name + `"`

		probeCtx, cancel := context.WithTimeout(ctx, tableSourceProbeTimeout)
		rows, err := t.client.Query(probeCtx,
			fmt.Sprintf(`SELECT COUNT(DISTINCT %s) AS n FROM "%s";`, colIdent, ident))
		cancel()
		if err != nil || len(rows) != 1 {
			continue
		}
		var distinct int64
		if _, scanErr := fmt.Sscan(rows[0]["n"], &distinct); scanErr != nil || distinct < 1 || distinct > int64(maxDistinct) {
			continue
		}

		probeCtx, cancel = context.WithTimeout(ctx, tableSourceProbeTimeout)
		rows, err = t.client.Query(probeCtx,
			fmt.Sprintf(`SELECT %s AS v, COUNT(*) AS n FROM "%s" GROUP BY %s ORDER BY COUNT(*) DESC LIMIT %d;`,
				colIdent, ident, colIdent, topValues))
		cancel()
		if err != nil {
			continue
		}
		facet := store.ColumnFacet{Column: col.Name, Distinct: distinct}
		for _, row := range rows {
			var n int64
			if _, scanErr := fmt.Sscan(row["n"], &n); scanErr != nil {
				facet.Values = nil
				break
			}
			facet.Values = append(facet.Values, store.FacetValue{Value: row["v"], Count: n})
		}
		if len(facet.Values) > 0 {
			facets = append(facets, facet)
		}
	}
	return facets, nil
}

// ColumnOrder returns the display order for a table's columns: the catalog's
// visible schema order first, then any live-only columns found in the result
// rows, sorted. osquery's Thrift API returns rows as maps, so the catalog is
// what preserves a meaningful order.
func ColumnOrder(table string, rows []map[string]string) []string {
	var order []string
	seen := map[string]bool{}
	if cat, ok := schema.Lookup(table); ok {
		for _, col := range cat.Columns {
			if col.Hidden {
				continue
			}
			order = append(order, col.Name)
			seen[col.Name] = true
		}
	}
	extra := map[string]bool{}
	for _, row := range rows {
		for name := range row {
			if !seen[name] && !extra[name] {
				extra[name] = true
			}
		}
	}
	extras := make([]string, 0, len(extra))
	for name := range extra {
		extras = append(extras, name)
	}
	sort.Strings(extras)
	return append(order, extras...)
}
