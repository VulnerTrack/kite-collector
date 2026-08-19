package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	cloud "github.com/vulnertrack/kite-collector/internal/discovery/cloud"
	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
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
	// Description is optional human documentation for the table. The SQLite
	// store leaves it empty; documented sources (e.g. osquery's published
	// schema) fill it and the generic table UI shows it when present.
	Description string
}

// ColumnSchema describes a single column of a TableSchema. Type is the
// dialect-reported type string (e.g. "TEXT", "UUID", "TIMESTAMPTZ") and is not
// normalized across dialects. Position is the 1-based ordinal.
type ColumnSchema struct {
	Name     string
	Type     string
	NotNull  bool
	Position int
	// Description is optional human documentation for the column; see
	// TableSchema.Description.
	Description string
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
//
// WhereColumn, when non-empty, must also match a column of Table and
// constrains rows to WhereColumn = WhereValue (the value is always bound as a
// parameter, never interpolated). An empty WhereValue selects the "empty"
// bucket — rows where the column is NULL or ” — matching how facets group
// missing values.
type RowsFilter struct {
	Table       string
	OrderBy     string
	WhereColumn string
	WhereValue  string
	Limit       int
	Offset      int
}

// JoinType selects how ListJoinedRows combines the base and joined tables.
type JoinType string

// Join types supported by ListJoinedRows. Left keeps every base row —
// unmatched join columns come back NULL — which is what coverage-style
// views ("machines with and without findings") rely on.
const (
	JoinInner JoinType = "inner"
	JoinLeft  JoinType = "left"
)

// JoinColumn addresses one output column of a join: a column of either the
// base or the joined table.
type JoinColumn struct {
	Table  string
	Column string
}

// JoinFilter describes a two-table equi-join over content tables. Every
// identifier — both tables, the ON columns, and each output column — is
// validated against the introspected catalog before any SQL is constructed.
type JoinFilter struct {
	Base string
	Join string
	Type JoinType
	// ON: Join.OnJoin = Base.OnBase.
	OnBase string
	OnJoin string
	// Columns is the output projection; it must be non-empty and every
	// entry must belong to Base or Join.
	Columns []JoinColumn
	Limit   int
	Offset  int
}

// SavedView is a user-defined two-table join view created in the dashboard's
// view builder. Slug is the URL identity (/views/{slug}); the JoinFilter's
// Limit/Offset are ignored at rest and supplied per render.
type SavedView struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	Join      JoinFilter
	CreatedAt time.Time
}

// SavedViewStore is the optional persistence surface for saved views. The
// dashboard type-asserts for it: stores that do not implement it simply get
// a read-only Views experience (built-in views keep working).
type SavedViewStore interface {
	// ListSavedViews returns every saved view ordered by name.
	ListSavedViews(ctx context.Context) ([]SavedView, error)
	// GetSavedViewBySlug returns the saved view with the given slug, or
	// ErrNotFound.
	GetSavedViewBySlug(ctx context.Context, slug string) (*SavedView, error)
	// SaveView inserts a new saved view. Name and Slug must be unique.
	SaveView(ctx context.Context, view SavedView) error
	// DeleteSavedView removes the saved view with the given slug; deleting
	// an unknown slug is a no-op.
	DeleteSavedView(ctx context.Context, slug string) error
}

// FacetValue is one bucket of a column facet: a distinct value and how many
// rows carry it. Value is the stringified cell; the empty string is the
// NULL-or-” bucket.
type FacetValue struct {
	Value string
	Count int64
}

// ColumnFacet describes a facetable column — one whose distinct-value count
// is small enough to enumerate — with its most common values.
type ColumnFacet struct {
	Column   string
	Distinct int64
	Values   []FacetValue // ordered by Count DESC
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

// MachineFilter constrains which machines are returned by ListMachines.
type MachineFilter struct {
	MachineType  string
	IsAuthorized string
	IsManaged    string
	Hostname     string
	Limit        int
	Offset       int
}

// EventFilter constrains which events are returned by ListEvents.
type EventFilter struct {
	MachineID *uuid.UUID
	ScanRunID *uuid.UUID
	EventType string
	Limit     int
	Offset    int
}

// TableSource is the read-only introspection surface the dashboard's generic
// table machinery consumes: catalog, schema, paged rows, and value facets.
// The SQLite store satisfies it natively; other backends (a live osqueryd,
// future sources) implement it so their tables render through exactly the
// same catalog, grid, facet, and SQL-strip code — the UI neither knows nor
// cares where a table comes from.
type TableSource interface {
	ListContentTables(ctx context.Context) ([]TableSchema, error)
	DescribeTable(ctx context.Context, table string) (*TableSchema, error)
	ListRows(ctx context.Context, filter RowsFilter) (rows []Row, total int64, err error)
	FacetTable(ctx context.Context, table string, maxDistinct, topValues int) ([]ColumnFacet, error)
}

// Store defines the persistence interface for the kite-collector.
// Implementations must be safe for concurrent use.
type Store interface {
	// UpsertMachine inserts a new machine or updates an existing one matched by
	// the UNIQUE(hostname, machine_type) constraint.
	UpsertMachine(ctx context.Context, machine model.Machine) error

	// UpsertMachines atomically upserts a batch of machines inside a single
	// transaction and returns the number of inserts and updates performed.
	UpsertMachines(ctx context.Context, machines []model.Machine) (inserted, updated int, err error)

	// GetMachineByID retrieves the machine identified by id.
	// Returns store.ErrNotFound when the id does not exist.
	GetMachineByID(ctx context.Context, id uuid.UUID) (*model.Machine, error)

	// GetMachineByNaturalKey retrieves the machine whose SHA-256 natural key
	// (hostname|machine_type) matches key. Returns nil when not found.
	GetMachineByNaturalKey(ctx context.Context, key string) (*model.Machine, error)

	// GetMachinesByNaturalKeys batch-fetches machines whose natural keys are in
	// the supplied slice. The returned map is keyed by NaturalKey so callers
	// can perform O(1) lookups while constructing per-machine events; missing
	// keys are simply absent from the map. An empty input yields a (nil, nil)
	// return for callers to treat as "no prior state."
	GetMachinesByNaturalKeys(ctx context.Context, keys []string) (map[string]model.Machine, error)

	// ListMachines returns machines matching the supplied filter.
	ListMachines(ctx context.Context, filter MachineFilter) ([]model.Machine, error)

	// GetStaleMachines returns machines whose last_seen_at is older than
	// time.Now().Add(-threshold).
	GetStaleMachines(ctx context.Context, threshold time.Duration) ([]model.Machine, error)

	// InsertEvent persists a single machine lifecycle event.
	InsertEvent(ctx context.Context, event model.MachineEvent) error

	// InsertEvents persists a batch of machine lifecycle events.
	InsertEvents(ctx context.Context, events []model.MachineEvent) error

	// ListEvents returns events matching the supplied filter.
	ListEvents(ctx context.Context, filter EventFilter) ([]model.MachineEvent, error)

	// CreateScanRun records a new scan run with status "running".
	CreateScanRun(ctx context.Context, run model.ScanRun) error

	// CompleteScanRun updates the scan run identified by id with the final
	// result counters and marks it completed (or failed on error).
	CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error

	// GetLatestScanRun returns the most recent scan run by started_at, or
	// nil when no scan runs exist.
	GetLatestScanRun(ctx context.Context) (*model.ScanRun, error)

	// ListScanRuns returns scan runs ordered by started_at DESC, capped at
	// the given limit. Pass limit <= 0 to use the default (50). Returns an
	// empty slice (not nil) when no runs exist.
	ListScanRuns(ctx context.Context, limit int) ([]model.ScanRun, error)

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
	// machine. It deletes existing rows for machineID and inserts the new set
	// inside a single transaction (full replacement per scan).
	UpsertSoftware(ctx context.Context, machineID uuid.UUID, software []model.InstalledSoftware) error

	// ListSoftware returns all installed software records for the given machine.
	ListSoftware(ctx context.Context, machineID uuid.UUID) ([]model.InstalledSoftware, error)

	// InsertFindings persists a batch of configuration audit findings.
	InsertFindings(ctx context.Context, findings []model.ConfigFinding) error

	// ListFindings returns configuration findings matching the supplied filter.
	ListFindings(ctx context.Context, filter FindingFilter) ([]model.ConfigFinding, error)

	// InsertRuntimeIncident persists a single runtime incident record.
	InsertRuntimeIncident(ctx context.Context, incident model.RuntimeIncident) error

	// ListRuntimeIncidents returns runtime incidents matching the filter.
	ListRuntimeIncidents(ctx context.Context, filter IncidentFilter) ([]model.RuntimeIncident, error)

	// RecordHeartbeat persists a synthetic probe heartbeat. The
	// (scan_run_id, source) pair is unique; a second insert for the same
	// pair is a programming error and the implementation surfaces it.
	RecordHeartbeat(ctx context.Context, hb model.ProbeHeartbeat) error

	// ListHeartbeats returns probe heartbeats matching the supplied filter,
	// ordered by created_at DESC.
	ListHeartbeats(ctx context.Context, filter HeartbeatFilter) ([]model.ProbeHeartbeat, error)

	// Migrate creates the schema tables and indexes if they do not exist.
	Migrate(ctx context.Context) error

	// UpsertEntraSnapshot persists the in-memory Entra discovery snapshot
	// into the source-of-truth SQLite tables created by migration
	// 20260429000000. Implementations may return nil for backends that do
	// not host the entra_* tables (e.g. Postgres, where Phase 3 ontology
	// sync is skipped because the Python bridge reads SQLite directly).
	UpsertEntraSnapshot(ctx context.Context, snap *entra.Snapshot) error

	// UpsertCloudDNSSnapshot persists a cloud DNS zone enumeration snapshot
	// (RFC-0122) into the SQLite tables created by migration
	// 20260430000000_cloud_dns_discovery.sql. The Python ontology bridge
	// reads those tables read-only to upsert ClickHouse cloud_dns_zones /
	// cloud_dns_records and synchronize CloudDNSZone / DNSRecord ontology
	// entities. Implementations may return nil for backends that do not
	// host the cloud_dns_* tables.
	UpsertCloudDNSSnapshot(ctx context.Context, snap *cloud.DNSSnapshot) error

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
	// TableSchema.RowCount), or the exact filtered count when WhereColumn is
	// set.
	ListRows(ctx context.Context, filter RowsFilter) (rows []Row, total int64, err error)

	// ListJoinedRows executes a validated two-table equi-join and returns a
	// page of rows. Output column names are qualified as "table.column".
	// Rows are ordered by the base table's primary key for stable paging;
	// Limit is capped at IntrospectionRowLimit.
	ListJoinedRows(ctx context.Context, filter JoinFilter) ([]Row, error)

	// FacetTable computes value facets for the named content table: for each
	// column whose distinct-value count is at most maxDistinct, the top
	// topValues values with their row counts. Facets power the dashboard's
	// pattern-spotting rail; implementations bound each per-column probe with
	// a short timeout, skip columns that cannot be counted in time, and cap
	// how many facets they return.
	FacetTable(ctx context.Context, table string, maxDistinct, topValues int) ([]ColumnFacet, error)

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

// HeartbeatFilter constrains which probe heartbeats are returned by
// ListHeartbeats. Empty ScanRunID/Source/Status mean "any."
type HeartbeatFilter struct {
	ScanRunID *uuid.UUID
	Since     *time.Time
	Source    string
	Status    string
	Limit     int
	Offset    int
}

// FindingFilter constrains which config findings are returned by ListFindings.
type FindingFilter struct {
	MachineID *uuid.UUID
	ScanRunID *uuid.UUID
	Auditor   string
	Severity  string
	Limit     int
	Offset    int
}
