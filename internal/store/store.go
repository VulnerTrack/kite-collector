package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

// ErrUnknownTable is returned when an introspection method is called with a
// table name that is not in the live content-table catalog. This protects the
// Store from identifier injection at its boundary.
var ErrUnknownTable = errors.New("unknown table")

// ErrUnknownColumn is returned when introspection references a column that is
// not part of the identified table's schema.
var ErrUnknownColumn = errors.New("unknown column")

// IntrospectionRowLimit is the hard cap on rows returned by ListRows and by
// any related-row grouping inside GetRowReport. Handlers must not exceed this.
const IntrospectionRowLimit = 1000

// IntrospectionDefaultPageSize is the default page size when a caller does not
// specify a Limit.
const IntrospectionDefaultPageSize = 200

// TableSchema describes a single content table discovered via introspection.
// RowCount is -1 when the dialect could neither read the planner estimate nor
// complete a fallback COUNT(*) under the per-table timeout.
type TableSchema struct {
	Name        string
	Columns     []ColumnSchema
	PrimaryKey  []string
	ForeignKeys []ForeignKey
	RowCount    int64
}

// ColumnSchema describes a single column of a TableSchema. Type is the
// dialect-reported type string (e.g. "TEXT", "UUID", "TIMESTAMPTZ") and is not
// normalized across dialects. Position is the 1-based ordinal.
type ColumnSchema struct {
	Name     string
	Type     string
	NotNull  bool
	Position int
}

// ForeignKey describes a single foreign key relation from a column in the
// owning TableSchema to a column of another table.
type ForeignKey struct {
	FromColumn string
	ToTable    string
	ToColumn   string
}

// RowsFilter constrains which rows are returned by ListRows. Table is required
// and is validated against the live introspected catalog before any SQL is
// constructed. OrderBy, when non-empty, must match a column of Table.
type RowsFilter struct {
	Table   string
	OrderBy string
	Limit   int
	Offset  int
}

// Row is a single result row. PrimaryKey carries stringified PK column values
// so that handlers can round-trip the row to URL query parameters without a
// separate lookup. Columns are ordered by schema position.
type Row struct {
	PrimaryKey map[string]string
	Columns    []ColumnValue
}

// ColumnValue holds one cell of a Row. Value is the native Go value returned
// by the driver; templates are responsible for stringifying it.
type ColumnValue struct {
	Value any
	Name  string
}

// RowReport is the payload rendered into the row-detail sidebar. Inbound
// groups list child rows whose foreign keys point at the primary row. Outbound
// entries are parent rows referenced by this row's own foreign keys.
type RowReport struct {
	Table    string
	Row      Row
	Inbound  []RelatedRowGroup
	Outbound []RelatedRow
}

// RelatedRowGroup carries inbound related rows from a single child table via a
// single foreign-key column. Truncated is true when the match count exceeded
// the request limit and the returned slice was capped.
type RelatedRowGroup struct {
	Table     string
	ViaColumn string
	Rows      []Row
	Truncated bool
}

// RelatedRow is a single outbound related parent row reached via the named FK
// column on the primary row.
type RelatedRow struct {
	Table     string
	ViaColumn string
	Row       Row
}

// AssetFilter constrains which assets are returned by ListAssets.
type AssetFilter struct {
	AssetType    string
	IsAuthorized string
	IsManaged    string
	Hostname     string
	Limit        int
	Offset       int
}

// EventFilter constrains which events are returned by ListEvents.
type EventFilter struct {
	AssetID   *uuid.UUID
	ScanRunID *uuid.UUID
	EventType string
	Limit     int
	Offset    int
}

// Store defines the persistence interface for the kite-collector.
// Implementations must be safe for concurrent use.
type Store interface {
	// UpsertAsset inserts a new asset or updates an existing one matched by
	// the UNIQUE(hostname, asset_type) constraint.
	UpsertAsset(ctx context.Context, asset model.Asset) error

	// UpsertAssets atomically upserts a batch of assets inside a single
	// transaction and returns the number of inserts and updates performed.
	UpsertAssets(ctx context.Context, assets []model.Asset) (inserted, updated int, err error)

	// GetAssetByID retrieves the asset identified by id.
	// Returns store.ErrNotFound when the id does not exist.
	GetAssetByID(ctx context.Context, id uuid.UUID) (*model.Asset, error)

	// GetAssetByNaturalKey retrieves the asset whose SHA-256 natural key
	// (hostname|asset_type) matches key. Returns nil when not found.
	GetAssetByNaturalKey(ctx context.Context, key string) (*model.Asset, error)

	// ListAssets returns assets matching the supplied filter.
	ListAssets(ctx context.Context, filter AssetFilter) ([]model.Asset, error)

	// GetStaleAssets returns assets whose last_seen_at is older than
	// time.Now().Add(-threshold).
	GetStaleAssets(ctx context.Context, threshold time.Duration) ([]model.Asset, error)

	// InsertEvent persists a single asset lifecycle event.
	InsertEvent(ctx context.Context, event model.AssetEvent) error

	// InsertEvents persists a batch of asset lifecycle events.
	InsertEvents(ctx context.Context, events []model.AssetEvent) error

	// ListEvents returns events matching the supplied filter.
	ListEvents(ctx context.Context, filter EventFilter) ([]model.AssetEvent, error)

	// CreateScanRun records a new scan run with status "running".
	CreateScanRun(ctx context.Context, run model.ScanRun) error

	// CompleteScanRun updates the scan run identified by id with the final
	// result counters and marks it completed (or failed on error).
	CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error

	// GetLatestScanRun returns the most recent scan run by started_at, or
	// nil when no scan runs exist.
	GetLatestScanRun(ctx context.Context) (*model.ScanRun, error)

	// GetScanRun returns the scan run identified by id, or ErrNotFound when
	// no row matches.
	GetScanRun(ctx context.Context, id uuid.UUID) (*model.ScanRun, error)

	// MarkScanCancelRequested stamps cancel_requested_at on the scan run
	// identified by id without touching its status. It returns ErrNotFound
	// when no row matches. The engine's own CompleteScanRun still owns the
	// terminal-status transition; this column just records that an operator
	// asked for cancellation.
	MarkScanCancelRequested(ctx context.Context, id uuid.UUID, at time.Time) error

	// UpsertSoftware replaces all installed software records for the given
	// asset. It deletes existing rows for assetID and inserts the new set
	// inside a single transaction (full replacement per scan).
	UpsertSoftware(ctx context.Context, assetID uuid.UUID, software []model.InstalledSoftware) error

	// ListSoftware returns all installed software records for the given asset.
	ListSoftware(ctx context.Context, assetID uuid.UUID) ([]model.InstalledSoftware, error)

	// InsertFindings persists a batch of configuration audit findings.
	InsertFindings(ctx context.Context, findings []model.ConfigFinding) error

	// ListFindings returns configuration findings matching the supplied filter.
	ListFindings(ctx context.Context, filter FindingFilter) ([]model.ConfigFinding, error)

	// InsertPostureAssessments persists a batch of posture assessments.
	InsertPostureAssessments(ctx context.Context, assessments []model.PostureAssessment) error

	// ListPostureAssessments returns posture assessments matching the filter.
	ListPostureAssessments(ctx context.Context, filter PostureFilter) ([]model.PostureAssessment, error)

	// InsertRuntimeIncident persists a single runtime incident record.
	InsertRuntimeIncident(ctx context.Context, incident model.RuntimeIncident) error

	// ListRuntimeIncidents returns runtime incidents matching the filter.
	ListRuntimeIncidents(ctx context.Context, filter IncidentFilter) ([]model.RuntimeIncident, error)

	// Migrate creates the schema tables and indexes if they do not exist.
	Migrate(ctx context.Context) error

	// ListContentTables returns every non-system content table present in the
	// live schema. System and migration tables (sqlite_*, schema_migrations,
	// pg_catalog.*, information_schema.*) are excluded. RowCount is populated
	// with the planner estimate where available and falls back to COUNT(*)
	// under a short per-table timeout; -1 signals an unavailable count.
	ListContentTables(ctx context.Context) ([]TableSchema, error)

	// DescribeTable returns the full schema of a single content table,
	// including columns, primary key, and foreign keys. It returns
	// ErrUnknownTable when table is not in the introspected catalog.
	DescribeTable(ctx context.Context, table string) (*TableSchema, error)

	// ListRows returns a page of rows from the named content table. The table
	// and OrderBy column (if set) are validated against the introspected
	// catalog before any SQL is constructed. Limit is capped at
	// IntrospectionRowLimit. total is the estimated row count (same source as
	// TableSchema.RowCount).
	ListRows(ctx context.Context, filter RowsFilter) (rows []Row, total int64, err error)

	// GetRowReport builds the full detail report for a single row addressed
	// by its primary key. It fetches the primary row, each inbound group of
	// children referencing it by FK, and the parent row for every outbound
	// FK. Missing outbound parents are tolerated (reported as absent rather
	// than error). Returns ErrUnknownTable or ErrNotFound as appropriate.
	GetRowReport(ctx context.Context, table string, pk map[string]string) (*RowReport, error)

	// Close releases all resources held by the store.
	Close() error
}

// IncidentFilter constrains which runtime incidents are returned.
type IncidentFilter struct {
	ScanRunID    *uuid.UUID
	Since        *time.Time
	IncidentType string
	Limit        int
	Offset       int
}

// FindingFilter constrains which config findings are returned by ListFindings.
type FindingFilter struct {
	AssetID   *uuid.UUID
	ScanRunID *uuid.UUID
	Auditor   string
	Severity  string
	CWEID     string
	Limit     int
	Offset    int
}

// PostureFilter constrains which posture assessments are returned.
type PostureFilter struct {
	AssetID   *uuid.UUID
	ScanRunID *uuid.UUID
	CAPECID   string
	Limit     int
	Offset    int
}
