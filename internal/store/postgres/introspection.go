package postgres

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// rowCountProbeTimeout caps the fallback COUNT(*) on any table the planner
// estimate cannot answer. Kept short so one slow table does not block the
// whole Tables tab.
const rowCountProbeTimeout = 1 * time.Second

// statementTimeoutMillis is applied via SET LOCAL statement_timeout inside
// every introspection transaction, matching RFC-0101 §4.4.
const statementTimeoutMillis = 5000

// isSystemTable reports whether a table name should be excluded regardless of
// its schema (for parity with the SQLite exclusion list).
func isSystemTable(name string) bool {
	return name == "schema_migrations"
}

// identQuote wraps a PostgreSQL identifier in double quotes, escaping any
// embedded quote. Callers must have already validated name against the live
// introspection catalog.
func identQuote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// withIntrospectionTx runs fn inside a read-only transaction that sets
// statement_timeout. Every introspection query flows through this wrapper so
// the DoS guardrail is enforced uniformly.
func (s *PostgresStore) withIntrospectionTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("begin introspection tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", statementTimeoutMillis)); err != nil {
		return fmt.Errorf("set statement_timeout: %w", err)
	}
	return fn(tx)
}

// ListContentTables returns every user-visible base table and view in the
// current schema, with row counts populated from pg_class.reltuples and
// column/PK/FK information pulled from information_schema.
func (s *PostgresStore) ListContentTables(ctx context.Context) ([]store.TableSchema, error) {
	var tables []store.TableSchema
	err := s.withIntrospectionTx(ctx, func(tx pgx.Tx) error {
		names, err := listTableNames(ctx, tx)
		if err != nil {
			return err
		}
		for _, name := range names {
			schema, err := describeTable(ctx, tx, name)
			if err != nil {
				return fmt.Errorf("describe %s: %w", name, err)
			}
			schema.RowCount = rowCount(ctx, tx, name)
			tables = append(tables, *schema)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return tables, nil
}

// listTableNames returns the content tables present in current_schema().
func listTableNames(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = current_schema()
		  AND table_type IN ('BASE TABLE','VIEW')
		ORDER BY table_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan information_schema.tables: %w", err)
		}
		if isSystemTable(name) {
			continue
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate information_schema.tables: %w", err)
	}
	return names, nil
}

// DescribeTable validates table against the introspected catalog and returns
// its full schema.
func (s *PostgresStore) DescribeTable(ctx context.Context, table string) (*store.TableSchema, error) {
	var result *store.TableSchema
	err := s.withIntrospectionTx(ctx, func(tx pgx.Tx) error {
		names, err := listTableNames(ctx, tx)
		if err != nil {
			return err
		}
		if !containsString(names, table) {
			return store.ErrUnknownTable
		}
		schema, err := describeTable(ctx, tx, table)
		if err != nil {
			return err
		}
		schema.RowCount = rowCount(ctx, tx, table)
		result = schema
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func describeTable(ctx context.Context, tx pgx.Tx, table string) (*store.TableSchema, error) {
	cols, err := readColumns(ctx, tx, table)
	if err != nil {
		return nil, err
	}
	pk, err := readPrimaryKey(ctx, tx, table)
	if err != nil {
		return nil, err
	}
	fks, err := readForeignKeys(ctx, tx, table)
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

func readColumns(ctx context.Context, tx pgx.Tx, table string) ([]store.ColumnSchema, error) {
	rows, err := tx.Query(ctx, `
		SELECT column_name, data_type, is_nullable, ordinal_position
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1
		ORDER BY ordinal_position
	`, table)
	if err != nil {
		return nil, fmt.Errorf("read columns %s: %w", table, err)
	}
	defer rows.Close()

	var cols []store.ColumnSchema
	for rows.Next() {
		var (
			name       string
			dataType   string
			isNullable string
			ordinal    int
		)
		if err := rows.Scan(&name, &dataType, &isNullable, &ordinal); err != nil {
			return nil, fmt.Errorf("scan column %s: %w", table, err)
		}
		cols = append(cols, store.ColumnSchema{
			Name:     name,
			Type:     dataType,
			NotNull:  strings.EqualFold(isNullable, "NO"),
			Position: ordinal,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate columns %s: %w", table, err)
	}
	return cols, nil
}

func readPrimaryKey(ctx context.Context, tx pgx.Tx, table string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT kcu.column_name, kcu.ordinal_position
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name
		 AND tc.table_schema   = kcu.table_schema
		WHERE tc.table_schema   = current_schema()
		  AND tc.table_name     = $1
		  AND tc.constraint_type = 'PRIMARY KEY'
		ORDER BY kcu.ordinal_position
	`, table)
	if err != nil {
		return nil, fmt.Errorf("read pk %s: %w", table, err)
	}
	defer rows.Close()

	var pk []string
	for rows.Next() {
		var col string
		var ord int
		if err := rows.Scan(&col, &ord); err != nil {
			return nil, fmt.Errorf("scan pk column %s: %w", table, err)
		}
		pk = append(pk, col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pk %s: %w", table, err)
	}
	return pk, nil
}

func readForeignKeys(ctx context.Context, tx pgx.Tx, table string) ([]store.ForeignKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT kcu.column_name, ccu.table_name, ccu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name
		 AND tc.table_schema   = kcu.table_schema
		JOIN information_schema.referential_constraints rc
		  ON tc.constraint_name = rc.constraint_name
		 AND tc.table_schema   = rc.constraint_schema
		JOIN information_schema.constraint_column_usage ccu
		  ON rc.unique_constraint_name = ccu.constraint_name
		 AND rc.unique_constraint_schema = ccu.table_schema
		WHERE tc.table_schema   = current_schema()
		  AND tc.table_name     = $1
		  AND tc.constraint_type = 'FOREIGN KEY'
		ORDER BY kcu.ordinal_position
	`, table)
	if err != nil {
		return nil, fmt.Errorf("read fks %s: %w", table, err)
	}
	defer rows.Close()

	var fks []store.ForeignKey
	for rows.Next() {
		var fromCol, toTable, toCol string
		if err := rows.Scan(&fromCol, &toTable, &toCol); err != nil {
			return nil, fmt.Errorf("scan fk %s: %w", table, err)
		}
		fks = append(fks, store.ForeignKey{
			FromColumn: fromCol,
			ToTable:    toTable,
			ToColumn:   toCol,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate fk %s: %w", table, err)
	}
	return fks, nil
}

// rowCount prefers pg_class.reltuples (planner estimate, O(1)) and falls back
// to COUNT(*) under rowCountProbeTimeout. Returns -1 when neither works.
func rowCount(ctx context.Context, tx pgx.Tx, table string) int64 {
	var n int64
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(reltuples::bigint, -1)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = $1
	`, table).Scan(&n)
	if err == nil && n >= 0 {
		return n
	}

	probeCtx, cancel := context.WithTimeout(ctx, rowCountProbeTimeout)
	defer cancel()
	q := `SELECT COUNT(*) FROM ` + identQuote(table) // #nosec G202 -- table validated
	if err := tx.QueryRow(probeCtx, q).Scan(&n); err != nil {
		return -1
	}
	return n
}

// ListRows returns a page of rows from the named table after validating the
// table and OrderBy column against the introspected catalog.
func (s *PostgresStore) ListRows(ctx context.Context, filter store.RowsFilter) ([]store.Row, int64, error) {
	var (
		result []store.Row
		total  int64
	)
	err := s.withIntrospectionTx(ctx, func(tx pgx.Tx) error {
		names, err := listTableNames(ctx, tx)
		if err != nil {
			return err
		}
		if !containsString(names, filter.Table) {
			return store.ErrUnknownTable
		}
		schema, err := describeTable(ctx, tx, filter.Table)
		if err != nil {
			return err
		}
		schema.RowCount = rowCount(ctx, tx, filter.Table)
		total = schema.RowCount

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
				return store.ErrUnknownColumn
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
		query += ` LIMIT $1 OFFSET $2`

		rows, err := tx.Query(ctx, query, limit, offset)
		if err != nil {
			return fmt.Errorf("list rows %s: %w", schema.Name, err)
		}
		defer rows.Close()

		result, err = scanGenericRows(rows, schema)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return result, total, nil
}

// GetRowReport builds the full detail report for a single row addressed by
// its primary key.
func (s *PostgresStore) GetRowReport(ctx context.Context, table string, pk map[string]string) (*store.RowReport, error) {
	var report *store.RowReport
	err := s.withIntrospectionTx(ctx, func(tx pgx.Tx) error {
		names, err := listTableNames(ctx, tx)
		if err != nil {
			return err
		}
		if !containsString(names, table) {
			return store.ErrUnknownTable
		}
		schema, err := describeTable(ctx, tx, table)
		if err != nil {
			return err
		}
		if len(schema.PrimaryKey) == 0 {
			return fmt.Errorf("%w: table %s has no primary key", store.ErrUnknownTable, table)
		}
		if len(pk) != len(schema.PrimaryKey) {
			return fmt.Errorf("primary key mismatch: expected %d columns, got %d", len(schema.PrimaryKey), len(pk))
		}
		for _, col := range schema.PrimaryKey {
			if _, ok := pk[col]; !ok {
				return fmt.Errorf("primary key missing column %q", col)
			}
		}

		primary, err := loadRowByPK(ctx, tx, schema, pk)
		if err != nil {
			return err
		}
		if primary == nil {
			return store.ErrNotFound
		}

		built := &store.RowReport{Table: table, Row: *primary}

		for _, fk := range schema.ForeignKeys {
			if !containsString(names, fk.ToTable) {
				continue
			}
			parentSchema, err := describeTable(ctx, tx, fk.ToTable)
			if err != nil {
				return fmt.Errorf("describe parent %s: %w", fk.ToTable, err)
			}
			val := valueFor(primary, fk.FromColumn)
			if val == nil {
				continue
			}
			parentPK := map[string]string{fk.ToColumn: stringifyValue(val)}
			parent, err := loadRowByPK(ctx, tx, parentSchema, parentPK)
			if err != nil {
				return err
			}
			if parent == nil {
				continue
			}
			built.Outbound = append(built.Outbound, store.RelatedRow{
				Table:     fk.ToTable,
				ViaColumn: fk.FromColumn,
				Row:       *parent,
			})
		}

		for _, other := range names {
			if other == table {
				continue
			}
			childSchema, err := describeTable(ctx, tx, other)
			if err != nil {
				return fmt.Errorf("describe %s: %w", other, err)
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
				group, err := loadInboundRows(ctx, tx, childSchema, fk.FromColumn, pkVal)
				if err != nil {
					return err
				}
				if group != nil {
					built.Inbound = append(built.Inbound, *group)
				}
			}
		}
		report = built
		return nil
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

func loadRowByPK(ctx context.Context, tx pgx.Tx, schema *store.TableSchema, pk map[string]string) (*store.Row, error) {
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
	paramN := 0
	for col, val := range pk {
		paramN++
		clauses = append(clauses, fmt.Sprintf("%s = $%d", identQuote(col), paramN))
		args = append(args, val)
	}
	// #nosec G202 -- identifiers validated against schema
	query := `SELECT ` + cols + ` FROM ` + identQuote(schema.Name) +
		` WHERE ` + strings.Join(clauses, " AND ") + ` LIMIT 1`
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load row %s: %w", schema.Name, err)
	}
	defer rows.Close()

	result, err := scanGenericRows(rows, schema)
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &result[0], nil
}

func loadInboundRows(ctx context.Context, tx pgx.Tx, child *store.TableSchema, viaCol, pkValue string) (*store.RelatedRowGroup, error) {
	if !columnExists(child.Columns, viaCol) {
		return nil, fmt.Errorf("%w: %s.%s", store.ErrUnknownColumn, child.Name, viaCol)
	}
	cols := buildColumnList(child.Columns)
	limit := store.IntrospectionRowLimit
	// #nosec G202 -- identifiers validated against schema
	query := `SELECT ` + cols + ` FROM ` + identQuote(child.Name) +
		` WHERE ` + identQuote(viaCol) + ` = $1 LIMIT $2`

	rows, err := tx.Query(ctx, query, pkValue, limit+1)
	if err != nil {
		return nil, fmt.Errorf("inbound %s.%s: %w", child.Name, viaCol, err)
	}
	defer rows.Close()

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

func scanGenericRows(rows pgx.Rows, schema *store.TableSchema) ([]store.Row, error) {
	desc := rows.FieldDescriptions()
	cols := make([]string, len(desc))
	for i, f := range desc {
		cols[i] = string(f.Name)
	}
	pkSet := make(map[string]struct{}, len(schema.PrimaryKey))
	for _, c := range schema.PrimaryKey {
		pkSet[c] = struct{}{}
	}

	var out []store.Row
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		row := store.Row{
			PrimaryKey: make(map[string]string, len(pkSet)),
			Columns:    make([]store.ColumnValue, len(cols)),
		}
		for i, name := range cols {
			row.Columns[i] = store.ColumnValue{Name: name, Value: vals[i]}
			if _, ok := pkSet[name]; ok {
				row.PrimaryKey[name] = stringifyValue(vals[i])
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
// Small helpers — duplicated from the sqlite package because each lives in
// its own Go module-internal package. Kept private.
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

func valueFor(r *store.Row, col string) any {
	for _, c := range r.Columns {
		if c.Name == col {
			return c.Value
		}
	}
	return nil
}

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
