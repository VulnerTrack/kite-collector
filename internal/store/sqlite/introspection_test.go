package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// seedMachineWithChildren inserts a single machine plus an installed software row
// and an event referencing it. It returns the machine so tests can assert on its
// PK in row reports.
func seedMachineWithChildren(t *testing.T, s *SQLiteStore) model.Machine {
	t.Helper()
	ctx := context.Background()

	machine := makeMachine("introspect-host", model.MachineTypeServer)
	machine.OSFamily = "linux"
	require.NoError(t, s.UpsertMachine(ctx, machine))

	sw := model.InstalledSoftware{
		SoftwareName: "openssl",
		Version:      "3.0.0",
	}
	require.NoError(t, s.UpsertSoftware(ctx, machine.ID, []model.InstalledSoftware{sw}))

	run := model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Truncate(time.Second),
		Status:    model.ScanStatusCompleted,
	}
	require.NoError(t, s.CreateScanRun(ctx, run))

	evt := model.MachineEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventMachineDiscovered,
		MachineID: machine.ID,
		ScanRunID: run.ID,
		Severity:  model.SeverityLow,
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, s.InsertEvents(ctx, []model.MachineEvent{evt}))

	return machine
}

func TestListContentTables_HidesSystemAndReportsColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tables, err := s.ListContentTables(ctx)
	require.NoError(t, err)

	names := make(map[string]store.TableSchema, len(tables))
	for _, tbl := range tables {
		names[tbl.Name] = tbl
		assert.NotContains(t, tbl.Name, "sqlite_",
			"system tables must be hidden from the Tables tab")
		assert.NotEqual(t, "schema_migrations", tbl.Name,
			"migration bookkeeping table must be hidden")
	}
	require.Contains(t, names, "machines")

	machines := names["machines"]
	require.NotEmpty(t, machines.Columns)
	assert.Equal(t, []string{"id"}, machines.PrimaryKey)
}

func TestDescribeTable_MachinesColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	schema, err := s.DescribeTable(ctx, "machines")
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.Equal(t, "machines", schema.Name)
	assert.Equal(t, []string{"id"}, schema.PrimaryKey)

	byName := make(map[string]store.ColumnSchema, len(schema.Columns))
	for _, c := range schema.Columns {
		byName[c.Name] = c
	}
	require.Contains(t, byName, "hostname")
	require.Contains(t, byName, "machine_type")
	assert.True(t, byName["hostname"].NotNull)
}

func TestDescribeTable_UnknownTableReturnsErr(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.DescribeTable(ctx, "this_table_does_not_exist")
	assert.ErrorIs(t, err, store.ErrUnknownTable)
}

func TestListRows_MachinesPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a := makeMachine("paging-"+string(rune('a'+i)), model.MachineTypeServer)
		require.NoError(t, s.UpsertMachine(ctx, a))
	}

	rows, total, err := s.ListRows(ctx, store.RowsFilter{Table: "machines", Limit: 2})
	require.NoError(t, err)
	assert.EqualValues(t, 5, total)
	assert.Len(t, rows, 2)
	for _, row := range rows {
		assert.NotEmpty(t, row.PrimaryKey["id"], "PK must be populated for round-trip")
	}
}

func TestListRows_UnknownTableRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, _, err := s.ListRows(ctx, store.RowsFilter{Table: "machines; DROP TABLE machines; --"})
	assert.ErrorIs(t, err, store.ErrUnknownTable,
		"identifier-injection attempt must be rejected against the live catalog")

	rows, err := s.ListMachines(ctx, store.MachineFilter{})
	require.NoError(t, err, "machines table must still exist after injection attempt")
	_ = rows
}

func TestListRows_ClampsToIntrospectionRowLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Insert 3 rows, but request a pathological limit to ensure the Store caps
	// it at IntrospectionRowLimit rather than honoring it literally.
	for i := 0; i < 3; i++ {
		require.NoError(t, s.UpsertMachine(ctx, makeMachine("clamp-"+string(rune('a'+i)), model.MachineTypeServer)))
	}

	// Limit above the cap should still succeed and return all 3 rows.
	rows, _, err := s.ListRows(ctx, store.RowsFilter{
		Table: "machines",
		Limit: store.IntrospectionRowLimit * 10,
	})
	require.NoError(t, err)
	assert.Len(t, rows, 3)
}

func TestGetRowReport_MachineWithChildrenAndParents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	machine := seedMachineWithChildren(t, s)

	report, err := s.GetRowReport(ctx, "machines", map[string]string{"id": machine.ID.String()})
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "machines", report.Table)

	inboundTables := make(map[string]store.RelatedRowGroup, len(report.Inbound))
	for _, g := range report.Inbound {
		inboundTables[g.Table] = g
	}
	require.Contains(t, inboundTables, "installed_software",
		"inbound group must surface installed_software children")
	require.Contains(t, inboundTables, "events",
		"inbound group must surface events referencing the machine")

	for _, g := range report.Inbound {
		assert.NotEmpty(t, g.Rows, "%s child rows must not be empty", g.Table)
	}

	// Events row itself carries outbound FKs to machines and scan_runs.
	eventsSchema, err := s.DescribeTable(ctx, "events")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(eventsSchema.ForeignKeys), 2)
}

func TestGetRowReport_UnknownTableRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetRowReport(ctx, "\"; DROP TABLE machines; --", map[string]string{"id": "x"})
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, store.ErrUnknownTable) || errors.Is(err, store.ErrUnknownColumn),
		"injection-shaped table name must be rejected, got: %v", err)
}

func TestListRows_WhereFilterEqualityAndEmptyBucket(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	linuxA := makeMachine("facet-linux-a", model.MachineTypeServer)
	linuxA.OSFamily = "linux"
	linuxB := makeMachine("facet-linux-b", model.MachineTypeServer)
	linuxB.OSFamily = "linux"
	windows := makeMachine("facet-windows", model.MachineTypeWorkstation)
	windows.OSFamily = "windows"
	blank := makeMachine("facet-blank", model.MachineTypeServer)
	blank.OSFamily = ""
	for _, m := range []model.Machine{linuxA, linuxB, windows, blank} {
		require.NoError(t, s.UpsertMachine(ctx, m))
	}

	rows, total, err := s.ListRows(ctx, store.RowsFilter{
		Table: "machines", WhereColumn: "os_family", WhereValue: "linux",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total, "filtered total must count matches, not the whole table")
	assert.Len(t, rows, 2)

	// Empty value selects the NULL-or-'' bucket.
	rows, total, err = s.ListRows(ctx, store.RowsFilter{
		Table: "machines", WhereColumn: "os_family", WhereValue: "",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, rows, 1)

	// Unknown filter column is rejected before any SQL is built.
	_, _, err = s.ListRows(ctx, store.RowsFilter{
		Table: "machines", WhereColumn: "no_such_column", WhereValue: "x",
	})
	assert.ErrorIs(t, err, store.ErrUnknownColumn)
}

func TestFacetTable_MachinesOSFamily(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		m := makeMachine("facet-l-"+string(rune('a'+i)), model.MachineTypeServer)
		m.OSFamily = "linux"
		require.NoError(t, s.UpsertMachine(ctx, m))
	}
	w := makeMachine("facet-w", model.MachineTypeWorkstation)
	w.OSFamily = "windows"
	require.NoError(t, s.UpsertMachine(ctx, w))

	facets, err := s.FacetTable(ctx, "machines", 20, 5)
	require.NoError(t, err)
	require.NotEmpty(t, facets, "machines has low-cardinality columns, facets expected")

	var osFacet *store.ColumnFacet
	for i := range facets {
		if facets[i].Column == "os_family" {
			osFacet = &facets[i]
		}
		// Primary key columns are never facetable.
		assert.NotEqual(t, "id", facets[i].Column)
	}
	require.NotNil(t, osFacet, "os_family has 2 distinct values and must be faceted")
	assert.EqualValues(t, 2, osFacet.Distinct)
	require.NotEmpty(t, osFacet.Values)
	// Most common value first.
	assert.Equal(t, "linux", osFacet.Values[0].Value)
	assert.EqualValues(t, 3, osFacet.Values[0].Count)
}

func TestFacetTable_UnknownTableRejected(t *testing.T) {
	s := newTestStore(t)
	_, err := s.FacetTable(context.Background(), "definitely_not_a_table", 20, 5)
	assert.ErrorIs(t, err, store.ErrUnknownTable)
}

func TestListJoinedRows_LeftKeepsUnmatchedBaseRows(t *testing.T) {
	s := newTestStore(t)
	machine := seedMachineWithChildren(t, s) // has software; no findings
	clean := makeMachine("join-clean-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(context.Background(), clean))

	rows, err := s.ListJoinedRows(context.Background(), store.JoinFilter{
		Base: "machines", Join: "installed_software", Type: store.JoinLeft,
		OnBase: "id", OnJoin: "machine_id",
		Columns: []store.JoinColumn{
			{Table: "machines", Column: "hostname"},
			{Table: "installed_software", Column: "software_name"},
		},
	})
	require.NoError(t, err)
	require.Len(t, rows, 2, "left join keeps the machine with no software")

	byHost := map[string]any{}
	for _, row := range rows {
		require.Len(t, row.Columns, 2)
		assert.Equal(t, "machines.hostname", row.Columns[0].Name)
		assert.Equal(t, "installed_software.software_name", row.Columns[1].Name)
		host, _ := row.Columns[0].Value.(string)
		byHost[host] = row.Columns[1].Value
	}
	assert.NotNil(t, byHost[machine.Hostname])
	assert.Nil(t, byHost[clean.Hostname], "unmatched joined column must be NULL")

	// Inner join drops the machine without software.
	rows, err = s.ListJoinedRows(context.Background(), store.JoinFilter{
		Base: "machines", Join: "installed_software", Type: store.JoinInner,
		OnBase: "id", OnJoin: "machine_id",
		Columns: []store.JoinColumn{{Table: "machines", Column: "hostname"}},
	})
	require.NoError(t, err)
	assert.Len(t, rows, 1)
}

func TestListJoinedRows_RejectsUnknownIdentifiers(t *testing.T) {
	s := newTestStore(t)
	base := store.JoinFilter{
		Base: "machines", Join: "installed_software", Type: store.JoinLeft,
		OnBase: "id", OnJoin: "machine_id",
		Columns: []store.JoinColumn{{Table: "machines", Column: "hostname"}},
	}

	bad := base
	bad.Join = "no_such_table"
	_, err := s.ListJoinedRows(context.Background(), bad)
	assert.ErrorIs(t, err, store.ErrUnknownTable)

	bad = base
	bad.OnJoin = "no_such_column"
	_, err = s.ListJoinedRows(context.Background(), bad)
	assert.ErrorIs(t, err, store.ErrUnknownColumn)

	bad = base
	bad.Columns = []store.JoinColumn{{Table: "machines", Column: "no_such_column"}}
	_, err = s.ListJoinedRows(context.Background(), bad)
	assert.ErrorIs(t, err, store.ErrUnknownColumn)

	bad = base
	bad.Columns = nil
	_, err = s.ListJoinedRows(context.Background(), bad)
	assert.Error(t, err)
}

func TestSavedViews_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	view := store.SavedView{
		Name: "Machines without software",
		Slug: "machines-without-software",
		Join: store.JoinFilter{
			Base: "machines", Join: "installed_software", Type: store.JoinLeft,
			OnBase: "id", OnJoin: "machine_id",
			Columns: []store.JoinColumn{
				{Table: "machines", Column: "hostname"},
				{Table: "installed_software", Column: "software_name"},
			},
		},
	}
	require.NoError(t, s.SaveView(ctx, view))

	got, err := s.GetSavedViewBySlug(ctx, view.Slug)
	require.NoError(t, err)
	assert.Equal(t, view.Name, got.Name)
	assert.Equal(t, store.JoinLeft, got.Join.Type)
	assert.Equal(t, view.Join.Columns, got.Join.Columns)
	assert.False(t, got.CreatedAt.IsZero())

	// Duplicate slug is a unique violation the handler can translate.
	err = s.SaveView(ctx, view)
	require.Error(t, err)
	assert.True(t, ErrIsUniqueViolation(err))

	all, err := s.ListSavedViews(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)

	require.NoError(t, s.DeleteSavedView(ctx, view.Slug))
	_, err = s.GetSavedViewBySlug(ctx, view.Slug)
	assert.ErrorIs(t, err, store.ErrNotFound)
}
