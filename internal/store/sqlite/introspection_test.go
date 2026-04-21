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

// seedAssetWithChildren inserts a single asset plus an installed software row
// and an event referencing it. It returns the asset so tests can assert on its
// PK in row reports.
func seedAssetWithChildren(t *testing.T, s *SQLiteStore) model.Asset {
	t.Helper()
	ctx := context.Background()

	asset := makeAsset("introspect-host", model.AssetTypeServer)
	asset.OSFamily = "linux"
	require.NoError(t, s.UpsertAsset(ctx, asset))

	sw := model.InstalledSoftware{
		SoftwareName: "openssl",
		Version:      "3.0.0",
	}
	require.NoError(t, s.UpsertSoftware(ctx, asset.ID, []model.InstalledSoftware{sw}))

	run := model.ScanRun{
		ID:        uuid.Must(uuid.NewV7()),
		StartedAt: time.Now().UTC().Truncate(time.Second),
		Status:    model.ScanStatusCompleted,
	}
	require.NoError(t, s.CreateScanRun(ctx, run))

	evt := model.AssetEvent{
		ID:        uuid.Must(uuid.NewV7()),
		EventType: model.EventAssetDiscovered,
		AssetID:   asset.ID,
		ScanRunID: run.ID,
		Severity:  model.SeverityLow,
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, s.InsertEvents(ctx, []model.AssetEvent{evt}))

	return asset
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
	require.Contains(t, names, "assets")

	assets := names["assets"]
	require.NotEmpty(t, assets.Columns)
	assert.Equal(t, []string{"id"}, assets.PrimaryKey)
}

func TestDescribeTable_AssetsColumns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	schema, err := s.DescribeTable(ctx, "assets")
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.Equal(t, "assets", schema.Name)
	assert.Equal(t, []string{"id"}, schema.PrimaryKey)

	byName := make(map[string]store.ColumnSchema, len(schema.Columns))
	for _, c := range schema.Columns {
		byName[c.Name] = c
	}
	require.Contains(t, byName, "hostname")
	require.Contains(t, byName, "asset_type")
	assert.True(t, byName["hostname"].NotNull)
}

func TestDescribeTable_UnknownTableReturnsErr(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.DescribeTable(ctx, "this_table_does_not_exist")
	assert.ErrorIs(t, err, store.ErrUnknownTable)
}

func TestListRows_AssetsPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a := makeAsset("paging-"+string(rune('a'+i)), model.AssetTypeServer)
		require.NoError(t, s.UpsertAsset(ctx, a))
	}

	rows, total, err := s.ListRows(ctx, store.RowsFilter{Table: "assets", Limit: 2})
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

	_, _, err := s.ListRows(ctx, store.RowsFilter{Table: "assets; DROP TABLE assets; --"})
	assert.ErrorIs(t, err, store.ErrUnknownTable,
		"identifier-injection attempt must be rejected against the live catalog")

	rows, err := s.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err, "assets table must still exist after injection attempt")
	_ = rows
}

func TestListRows_ClampsToIntrospectionRowLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Insert 3 rows, but request a pathological limit to ensure the Store caps
	// it at IntrospectionRowLimit rather than honoring it literally.
	for i := 0; i < 3; i++ {
		require.NoError(t, s.UpsertAsset(ctx, makeAsset("clamp-"+string(rune('a'+i)), model.AssetTypeServer)))
	}

	// Limit above the cap should still succeed and return all 3 rows.
	rows, _, err := s.ListRows(ctx, store.RowsFilter{
		Table: "assets",
		Limit: store.IntrospectionRowLimit * 10,
	})
	require.NoError(t, err)
	assert.Len(t, rows, 3)
}

func TestGetRowReport_AssetWithChildrenAndParents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	asset := seedAssetWithChildren(t, s)

	report, err := s.GetRowReport(ctx, "assets", map[string]string{"id": asset.ID.String()})
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "assets", report.Table)

	inboundTables := make(map[string]store.RelatedRowGroup, len(report.Inbound))
	for _, g := range report.Inbound {
		inboundTables[g.Table] = g
	}
	require.Contains(t, inboundTables, "installed_software",
		"inbound group must surface installed_software children")
	require.Contains(t, inboundTables, "events",
		"inbound group must surface events referencing the asset")

	for _, g := range report.Inbound {
		assert.NotEmpty(t, g.Rows, "%s child rows must not be empty", g.Table)
	}

	// Events row itself carries outbound FKs to assets and scan_runs.
	eventsSchema, err := s.DescribeTable(ctx, "events")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(eventsSchema.ForeignKeys), 2)
}

func TestGetRowReport_UnknownTableRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetRowReport(ctx, "\"; DROP TABLE assets; --", map[string]string{"id": "x"})
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, store.ErrUnknownTable) || errors.Is(err, store.ErrUnknownColumn),
		"injection-shaped table name must be rejected, got: %v", err)
}
