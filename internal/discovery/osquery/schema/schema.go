// Package schema embeds the published osquery table catalog — every table
// with its description, platforms, evented flag, and per-column types,
// descriptions, and required-constraint markers. It is what lets kite
// understand and interpret ALL osquery data, not just the identity tables
// the discovery source queries: the dashboard's osquery explorer annotates
// live tables with this catalog, and warns before querying tables whose
// virtual implementation requires a constraint (e.g. curl, file, hash).
//
// The data file is generated from the osquery project's published schema
// (https://osquery.io/schema/) for the version named by Version(). A live
// daemon of a different version still works: tables absent from the catalog
// render without descriptions, and catalog tables the daemon does not serve
// are marked not-loaded.
package schema

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"
)

//go:embed osquery_schema_5.23.1.json
var raw []byte

// CatalogVersion is the osquery release the embedded catalog was generated
// from.
const CatalogVersion = "5.23.1"

// Column is one column of an osquery table.
type Column struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	// Required marks a column the virtual table needs as a WHERE constraint
	// before it can produce rows at all (e.g. curl.url, file.path). A bare
	// SELECT * against such a table errors or returns nothing.
	Required bool `json:"required"`
	// Hidden columns exist but are omitted from SELECT * output.
	Hidden bool `json:"hidden"`
}

// Table is one osquery table with its documentation.
type Table struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Platforms   []string `json:"platforms"`
	// Evented tables buffer publisher events and require the matching
	// publisher (audit, EndpointSecurity, ETW…) to be active.
	Evented bool     `json:"evented"`
	Columns []Column `json:"columns"`
}

var (
	loadOnce sync.Once
	tables   []Table
	byName   map[string]*Table
)

func load() {
	loadOnce.Do(func() {
		if err := json.Unmarshal(raw, &tables); err != nil {
			// The catalog is embedded at build time; a parse failure is a
			// programmer error caught by tests. Degrade to an empty catalog
			// rather than panicking a running collector.
			tables = nil
		}
		sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
		byName = make(map[string]*Table, len(tables))
		for i := range tables {
			byName[tables[i].Name] = &tables[i]
		}
	})
}

// Tables returns every cataloged table, sorted by name. The slice is shared;
// callers must not mutate it.
func Tables() []Table {
	load()
	return tables
}

// Lookup returns the cataloged table with the given name.
func Lookup(name string) (*Table, bool) {
	load()
	t, ok := byName[name]
	return t, ok
}

// RequiredColumns lists the columns a query against this table must
// constrain for the virtual table to produce output.
func (t *Table) RequiredColumns() []string {
	var req []string
	for _, c := range t.Columns {
		if c.Required {
			req = append(req, c.Name)
		}
	}
	return req
}

// SupportsOS reports whether the table exists on the given GOOS.
func (t *Table) SupportsOS(goos string) bool {
	want := goos
	if goos == "darwin" {
		want = "darwin"
	}
	for _, p := range t.Platforms {
		if p == want {
			return true
		}
	}
	return false
}
