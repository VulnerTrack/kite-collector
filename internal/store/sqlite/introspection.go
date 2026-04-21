package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// rowCountProbeTimeout caps the fallback COUNT(*) per table on the Tables tab
// so that a pathologically large table cannot block the page load.
const rowCountProbeTimeout = 1 * time.Second

// isSystemTable reports whether name belongs to the SQLite system/migration
// surface that the introspection UI must hide.
func isSystemTable(name string) bool {
	if strings.HasPrefix(name, "sqlite_") {
		return true
	}
	if name == "schema_migrations" {
		return true
	}
	return false
}

// identQuote wraps a SQLite identifier in double quotes, escaping embedded
// quotes. The input MUST already be validated against the introspection
// catalog; this function is a defense-in-depth belt-and-braces, not a primary
// sanitizer.
func identQuote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// ListContentTables returns every non-system table in the live schema.
// SQLite ≥ 3.37 exposes PRAGMA table_list; older versions fall back to
// sqlite_schema. Row counts prefer the sqlite_stat1 estimate and fall back to
// COUNT(*) under rowCountProbeTimeout.
func (s *SQLiteStore) ListContentTables(ctx context.Context) ([]store.TableSchema, error) {
	names, err := s.listTableNames(ctx)
	if err != nil {
		return nil, err
	}

	stats, _ := s.readSQLiteStat1(ctx) // best-effort; nil map on failure

	tables := make([]store.TableSchema, 0, len(names))
	for _, name := range names {
		schema, err := s.describeTable(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("describe %s: %w", name, err)
		}
		schema.RowCount = s.rowCount(ctx, name, stats)
		tables = append(tables, *schema)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return tables, nil
}

// listTableNames returns the visible content tables. PRAGMA table_list is the
// preferred source on SQLite 3.37+; the sqlite_schema fallback covers older
// builds and errors in the pragma itself.
func (s *SQLiteStore) listTableNames(ctx context.Context) ([]string, error) {
	if names, err := s.listViaPragmaTableList(ctx); err == nil {
		return names, nil
	}
	return s.listViaSQLiteSchema(ctx)
}

func (s *SQLiteStore) listViaPragmaTableList(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_list`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// PRAGMA table_list returns: schema, name, type, ncol, wr, strict.
	// We index by column name to stay resilient to future ordering changes.
	nameIdx := -1
	typeIdx := -1
	schemaIdx := -1
	for i, c := range cols {
		switch c {
		case "name":
			nameIdx = i
		case "type":
			typeIdx = i
		case "schema":
			schemaIdx = i
		}
	}
	if nameIdx < 0 || typeIdx < 0 {
		return nil, fmt.Errorf("PRAGMA table_list missing required columns")
	}

	var names []string
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		dest := make([]any, len(cols))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		name := raw[nameIdx].String
		kind := raw[typeIdx].String
		if schemaIdx >= 0 && raw[schemaIdx].String != "main" && raw[schemaIdx].String != "" {
			continue
		}
		if name == "" || isSystemTable(name) {
			continue
		}
		if kind != "table" && kind != "view" {
			continue
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (s *SQLiteStore) listViaSQLiteSchema(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name FROM sqlite_schema
		 WHERE type IN ('table','view')
		   AND name NOT LIKE 'sqlite_%'
		   AND name <> 'schema_migrations'
		 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list sqlite_schema: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if isSystemTable(name) {
			continue
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// DescribeTable returns the full schema for a single content table, validating
// the name against the introspected catalog first.
func (s *SQLiteStore) DescribeTable(ctx context.Context, table string) (*store.TableSchema, error) {
	names, err := s.listTableNames(ctx)
	if err != nil {
		return nil, err
	}
	if !containsString(names, table) {
		return nil, store.ErrUnknownTable
	}
	schema, err := s.describeTable(ctx, table)
	if err != nil {
		return nil, err
	}
	stats, _ := s.readSQLiteStat1(ctx)
	schema.RowCount = s.rowCount(ctx, table, stats)
	return schema, nil
}

// describeTable runs PRAGMA table_info / foreign_key_list against a name that
// has already been validated.
func (s *SQLiteStore) describeTable(ctx context.Context, table string) (*store.TableSchema, error) {
	cols, pk, err := s.readColumns(ctx, table)
	if err != nil {
		return nil, err
	}
	fks, err := s.readForeignKeys(ctx, table)
	if err != nil {
		return nil, err
	}
	return &store.TableSchema{
		Name:        table,
		Columns:     cols,
		PrimaryKey:  pk,
		ForeignKeys: fks,
		RowCount:    -1,
	}, nil
}

func (s *SQLiteStore) readColumns(ctx context.Context, table string) ([]store.ColumnSchema, []string, error) {
	// PRAGMA arguments in SQLite cannot be parameter-bound; the table name has
	// already been validated by the caller against the introspected catalog.
	q := `PRAGMA table_info(` + identQuote(table) + `)` // #nosec G202 -- table validated by caller
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, nil, fmt.Errorf("table_info %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	type pkEntry struct {
		name  string
		order int
	}
	var pkEntries []pkEntry
	var cols []store.ColumnSchema

	for rows.Next() {
		var (
			cid       int
			name      string
			colType   sql.NullString
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return nil, nil, fmt.Errorf("scan table_info %s: %w", table, err)
		}
		cols = append(cols, store.ColumnSchema{
			Name:     name,
			Type:     colType.String,
			NotNull:  notNull != 0,
			Position: cid + 1,
		})
		if pk > 0 {
			pkEntries = append(pkEntries, pkEntry{name: name, order: pk})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate table_info %s: %w", table, err)
	}

	sort.Slice(pkEntries, func(i, j int) bool { return pkEntries[i].order < pkEntries[j].order })
	pk := make([]string, len(pkEntries))
	for i, e := range pkEntries {
		pk[i] = e.name
	}
	return cols, pk, nil
}

func (s *SQLiteStore) readForeignKeys(ctx context.Context, table string) ([]store.ForeignKey, error) {
	q := `PRAGMA foreign_key_list(` + identQuote(table) + `)` // #nosec G202 -- table validated
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("foreign_key_list %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	var fks []store.ForeignKey
	for rows.Next() {
		var (
			id       int
			seq      int
			refTable string
			from     string
			to       sql.NullString
			onUpdate sql.NullString
			onDelete sql.NullString
			match    sql.NullString
		)
		if err := rows.Scan(&id, &seq, &refTable, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return nil, fmt.Errorf("scan foreign_key_list %s: %w", table, err)
		}
		fks = append(fks, store.ForeignKey{
			FromColumn: from,
			ToTable:    refTable,
			ToColumn:   to.String,
		})
	}
	return fks, rows.Err()
}

// readSQLiteStat1 reads the analyzer estimate for every table, keyed by name.
// It is a best-effort probe; callers treat nil/missing entries as "unknown"
// and fall back to COUNT(*).
func (s *SQLiteStore) readSQLiteStat1(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tbl, stat FROM sqlite_stat1`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[string]int64)
	for rows.Next() {
		var tbl, stat string
		if err := rows.Scan(&tbl, &stat); err != nil {
			return stats, err
		}
		// stat is whitespace-separated; the first token is the row count.
		if _, seen := stats[tbl]; seen {
			continue
		}
		parts := strings.Fields(stat)
		if len(parts) == 0 {
			continue
		}
		n, parseErr := strconv.ParseInt(parts[0], 10, 64)
		if parseErr != nil {
			continue
		}
		stats[tbl] = n
	}
	return stats, rows.Err()
}

// rowCount returns the best available row count for table, preferring the
// sqlite_stat1 estimate and falling back to COUNT(*) under a short timeout.
// Returns -1 when neither source yields a value.
func (s *SQLiteStore) rowCount(ctx context.Context, table string, stats map[string]int64) int64 {
	if n, ok := stats[table]; ok {
		return n
	}
	probeCtx, cancel := context.WithTimeout(ctx, rowCountProbeTimeout)
	defer cancel()
	q := `SELECT COUNT(*) FROM ` + identQuote(table) // #nosec G202 -- table validated
	var n int64
	if err := s.db.QueryRowContext(probeCtx, q).Scan(&n); err != nil {
		return -1
	}
	return n
}

// ListRows returns a page of rows from the named content table after
// validating the table and OrderBy column against the introspected catalog.
func (s *SQLiteStore) ListRows(ctx context.Context, filter store.RowsFilter) ([]store.Row, int64, error) {
	schema, err := s.DescribeTable(ctx, filter.Table)
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

	orderCol := ""
	if filter.OrderBy != "" {
		if !columnExists(schema.Columns, filter.OrderBy) {
			return nil, 0, store.ErrUnknownColumn
		}
		orderCol = filter.OrderBy
	} else if len(schema.PrimaryKey) > 0 {
		orderCol = schema.PrimaryKey[0]
	} else if len(schema.Columns) > 0 {
		orderCol = schema.Columns[0].Name
	}

	colList := buildColumnList(schema.Columns)
	query := `SELECT ` + colList + ` FROM ` + identQuote(schema.Name) // #nosec G202 -- identifiers validated
	if orderCol != "" {
		query += ` ORDER BY ` + identQuote(orderCol)
	}
	query += ` LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list rows %s: %w", schema.Name, err)
	}
	defer func() { _ = rows.Close() }()

	result, err := scanGenericRows(rows, schema)
	if err != nil {
		return nil, 0, err
	}
	return result, schema.RowCount, nil
}

// GetRowReport fetches the primary row addressed by pk, then populates
// inbound (children via FK) and outbound (parents via FK) related rows.
func (s *SQLiteStore) GetRowReport(ctx context.Context, table string, pk map[string]string) (*store.RowReport, error) {
	schema, err := s.DescribeTable(ctx, table)
	if err != nil {
		return nil, err
	}
	if len(schema.PrimaryKey) == 0 {
		return nil, fmt.Errorf("%w: table %s has no primary key", store.ErrUnknownTable, table)
	}
	if len(pk) != len(schema.PrimaryKey) {
		return nil, fmt.Errorf("primary key mismatch: expected %d columns, got %d", len(schema.PrimaryKey), len(pk))
	}
	for _, col := range schema.PrimaryKey {
		if _, ok := pk[col]; !ok {
			return nil, fmt.Errorf("primary key missing column %q", col)
		}
	}

	primary, err := s.loadRowByPK(ctx, schema, pk)
	if err != nil {
		return nil, err
	}
	if primary == nil {
		return nil, store.ErrNotFound
	}

	report := &store.RowReport{
		Table: table,
		Row:   *primary,
	}

	// Outbound: parent rows this row's FKs point at.
	for _, fk := range schema.ForeignKeys {
		parentSchema, err := s.describeIfKnown(ctx, fk.ToTable)
		if err != nil {
			return nil, err
		}
		if parentSchema == nil {
			continue
		}
		val := valueFor(primary, fk.FromColumn)
		if val == nil {
			continue
		}
		parentPK := map[string]string{fk.ToColumn: stringifyValue(val)}
		parent, err := s.loadRowByPK(ctx, parentSchema, parentPK)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			continue
		}
		report.Outbound = append(report.Outbound, store.RelatedRow{
			Table:     fk.ToTable,
			ViaColumn: fk.FromColumn,
			Row:       *parent,
		})
	}

	// Inbound: scan every other content table for FKs that target this table.
	allTables, err := s.listTableNames(ctx)
	if err != nil {
		return nil, err
	}
	for _, other := range allTables {
		if other == table {
			continue
		}
		childSchema, err := s.describeTable(ctx, other)
		if err != nil {
			return nil, fmt.Errorf("describe %s: %w", other, err)
		}
		for _, fk := range childSchema.ForeignKeys {
			if fk.ToTable != table {
				continue
			}
			pkVal, ok := pk[fk.ToColumn]
			if !ok && len(schema.PrimaryKey) == 1 {
				pkVal = pk[schema.PrimaryKey[0]]
			}
			if pkVal == "" {
				continue
			}
			group, err := s.loadInboundRows(ctx, childSchema, fk.FromColumn, pkVal)
			if err != nil {
				return nil, err
			}
			if group != nil {
				report.Inbound = append(report.Inbound, *group)
			}
		}
	}
	return report, nil
}

// describeIfKnown returns a table's schema only when the table is part of the
// content catalog; returns (nil, nil) when it is system/hidden.
func (s *SQLiteStore) describeIfKnown(ctx context.Context, table string) (*store.TableSchema, error) {
	names, err := s.listTableNames(ctx)
	if err != nil {
		return nil, err
	}
	if !containsString(names, table) {
		return nil, nil
	}
	return s.describeTable(ctx, table)
}

func (s *SQLiteStore) loadRowByPK(ctx context.Context, schema *store.TableSchema, pk map[string]string) (*store.Row, error) {
	if len(pk) == 0 {
		return nil, nil
	}
	for col := range pk {
		if !columnExists(schema.Columns, col) {
			return nil, fmt.Errorf("%w: %s.%s", store.ErrUnknownColumn, schema.Name, col)
		}
	}
	cols := buildColumnList(schema.Columns)
	clauses := make([]string, 0, len(pk))
	args := make([]any, 0, len(pk))
	for col, val := range pk {
		clauses = append(clauses, identQuote(col)+" = ?")
		args = append(args, val)
	}
	// #nosec G202 -- identifiers are validated against the schema
	query := `SELECT ` + cols + ` FROM ` + identQuote(schema.Name) + ` WHERE ` + strings.Join(clauses, " AND ") + ` LIMIT 1`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load row %s: %w", schema.Name, err)
	}
	defer func() { _ = rows.Close() }()

	result, err := scanGenericRows(rows, schema)
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &result[0], nil
}

func (s *SQLiteStore) loadInboundRows(ctx context.Context, child *store.TableSchema, viaCol, pkValue string) (*store.RelatedRowGroup, error) {
	if !columnExists(child.Columns, viaCol) {
		return nil, fmt.Errorf("%w: %s.%s", store.ErrUnknownColumn, child.Name, viaCol)
	}
	cols := buildColumnList(child.Columns)
	limit := store.IntrospectionRowLimit
	// #nosec G202 -- identifiers validated against schema
	query := `SELECT ` + cols + ` FROM ` + identQuote(child.Name) +
		` WHERE ` + identQuote(viaCol) + ` = ? LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, pkValue, limit+1)
	if err != nil {
		return nil, fmt.Errorf("inbound %s.%s: %w", child.Name, viaCol, err)
	}
	defer func() { _ = rows.Close() }()

	result, err := scanGenericRows(rows, child)
	if err != nil {
		return nil, err
	}
	truncated := false
	if len(result) > limit {
		result = result[:limit]
		truncated = true
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &store.RelatedRowGroup{
		Table:     child.Name,
		ViaColumn: viaCol,
		Rows:      result,
		Truncated: truncated,
	}, nil
}

// scanGenericRows reads every row from rows into store.Row values using schema
// for column ordering and PK extraction.
func scanGenericRows(rows *sql.Rows, schema *store.TableSchema) ([]store.Row, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("columns: %w", err)
	}
	pkSet := make(map[string]struct{}, len(schema.PrimaryKey))
	for _, c := range schema.PrimaryKey {
		pkSet[c] = struct{}{}
	}

	var out []store.Row
	for rows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		row := store.Row{
			PrimaryKey: make(map[string]string, len(pkSet)),
			Columns:    make([]store.ColumnValue, len(cols)),
		}
		for i, name := range cols {
			row.Columns[i] = store.ColumnValue{Name: name, Value: raw[i]}
			if _, ok := pkSet[name]; ok {
				row.PrimaryKey[name] = stringifyValue(raw[i])
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func columnExists(cols []store.ColumnSchema, name string) bool {
	for _, c := range cols {
		if c.Name == name {
			return true
		}
	}
	return false
}

func buildColumnList(cols []store.ColumnSchema) string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = identQuote(c.Name)
	}
	return strings.Join(names, ", ")
}

// valueFor extracts a raw column value from a Row by column name.
func valueFor(r *store.Row, col string) any {
	for _, c := range r.Columns {
		if c.Name == col {
			return c.Value
		}
	}
	return nil
}

// stringifyValue produces the URL-parameter representation of a raw column
// value. Byte slices become strings, other values are formatted with %v.
func stringifyValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case time.Time:
		return x.Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", v)
	}
}

