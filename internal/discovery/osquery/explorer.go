package osquery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/discovery/osquery/schema"
)

// Explorer provides generic, read-only access to every table a live osqueryd
// serves — not just the identity tables the discovery source queries. It is
// the backend of the dashboard's osquery explorer: list the daemon's tables,
// and run a bounded SELECT * against any one of them, with the table name
// validated against the daemon's own registry before any SQL is assembled.
//
// The embedded schema catalog (schema package) supplies the interpretation
// layer — descriptions, platforms, evented flags, and required-constraint
// columns — while the Explorer supplies the live data.
type Explorer struct {
	client querier
}

// NewExplorer returns an Explorer talking to the osqueryd extensions socket.
// Socket resolution follows the discovery source's precedence when socket is
// empty: KITE_OSQUERY_SOCKET → platform default paths.
func NewExplorer(socket string) *Explorer {
	if socket == "" {
		socket = resolveSocket(nil)
	}
	return &Explorer{client: NewClient(socket)}
}

// newExplorerWith is the testing seam: an Explorer over any querier.
func newExplorerWith(q querier) *Explorer {
	return &Explorer{client: q}
}

// ResolveSocketPath exposes the source's socket resolution (env → platform
// defaults) so callers like the dashboard can report which socket is in use.
// Empty means no candidate socket exists on this host.
func ResolveSocketPath() string {
	return resolveSocket(nil)
}

// Ping reports whether the daemon answers on the socket.
func (e *Explorer) Ping(ctx context.Context) error {
	return e.client.Ping(ctx)
}

// LiveTables returns the names of every table the connected daemon serves,
// sorted. This is the daemon's own registry, so it includes tables from
// extensions and excludes tables compiled out of this build.
func (e *Explorer) LiveTables(ctx context.Context) ([]string, error) {
	rows, err := e.client.Query(ctx,
		"SELECT name FROM osquery_registry WHERE registry = 'table' AND active = 1;")
	if err != nil {
		return nil, fmt.Errorf("list osquery tables: %w", err)
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		if name := strings.TrimSpace(row["name"]); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// TableRows runs a bounded SELECT * against one live table. The name is
// validated against the daemon's registry — never interpolated from user
// input directly — and limit is clamped to [1, 1000]. The daemon's own
// error for constraint-required or misbehaving virtual tables is returned
// verbatim (IsQueryError distinguishes it from transport failures).
func (e *Explorer) TableRows(ctx context.Context, table string, limit int) ([]map[string]string, error) {
	live, err := e.LiveTables(ctx)
	if err != nil {
		return nil, err
	}
	found := false
	for _, name := range live {
		if name == table {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("table %q is not served by this osqueryd", table)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	// Identifier quoted defensively even though it just matched the registry.
	q := fmt.Sprintf(`SELECT * FROM "%s" LIMIT %d;`, strings.ReplaceAll(table, `"`, `""`), limit)
	rows, err := e.client.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query osquery table %s: %w", table, err)
	}
	return rows, nil
}

// ColumnOrder returns the display order for a table's columns: the catalog's
// schema order first (visible columns), then any live-only columns found in
// the result rows, sorted. osquery's Thrift API returns rows as maps, so the
// catalog is what preserves a meaningful order.
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
