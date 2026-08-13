package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
	"github.com/vulnertrack/kite-collector/internal/store"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// SQLiteStore implements store.Store backed by a local SQLite database.
type SQLiteStore struct {
	db   *sql.DB
	path string // filesystem path of the underlying SQLite database
}

// Compile-time interface check.
var _ store.Store = (*SQLiteStore)(nil)

// connectionPragmas are applied to EVERY connection modernc.org/sqlite opens
// in the pool. They fall into two groups (SQLite treats them differently, but
// modernc runs all of them per-connection on connect, so listing them here is
// both correct and idempotent):
//
//	Persistent / file-level — safe to re-assert on every open:
//	  journal_mode(WAL)          readers never block the single writer. WAL is
//	                             sticky in the file header; re-running is a
//	                             no-op. REQUIRES all accessors on one host —
//	                             never place a WAL DB on NFS/SMB/network FS.
//	  wal_autocheckpoint(2000)   checkpoint every ~2000 WAL pages (~8 MiB at
//	                             4 KiB pages) instead of the 1000 default.
//	  journal_size_limit(64 MiB) cap the reclaimed WAL/journal file size.
//	  synchronous(1)             NORMAL — durable under WAL, ~2x faster writes.
//	  temp_store(2)              MEMORY — temp b-trees/tables in RAM.
//
//	Per-connection — NOT persisted, MUST be set on each connection:
//	  busy_timeout(5000)         contention becomes a bounded 5s wait, not an
//	                             immediate SQLITE_BUSY. The core BUSY-storm fix.
//	  foreign_keys(1)            FK enforcement is runtime state, off by
//	                             default, and cannot change inside a tx — so it
//	                             must ride connect, before any statement.
//	  cache_size(-32768)         32 MiB page cache (negative = KiB). Budget
//	                             against pool size: N connections ⇒ up to
//	                             N×32 MiB. With SetMaxOpenConns(1) below that
//	                             is 32 MiB total. (SQLite's stock default is
//	                             ~2 MiB.)
//	  mmap_size(268435456)       256 MiB memory-mapped I/O. Address-space, not
//	                             RSS; a per-DATABASE mapping cap, so many tenant
//	                             files multiply the address-space potential.
//	                             Bump to 512 MiB/1 GiB for read-heavy DBs.
//	  cache_spill(1)             let a large write tx spill dirty pages to disk
//	                             mid-transaction rather than ballooning memory.
//
// Syntax is modernc's `_pragma=name(value)` form — NOT mattn/go-sqlite3's
// `_journal_mode=WAL`, which modernc silently ignores. That silent ignore
// once meant the store ran with journal_mode=delete, busy_timeout=0 and
// foreign_keys=0, producing SQLITE_BUSY storms during multi-source scans.
// TestPragmasEffective pins every value below against the live connection.
var connectionPragmas = []string{
	"journal_mode(WAL)",
	"wal_autocheckpoint(2000)",
	"journal_size_limit(67108864)", // 64 MiB
	"synchronous(1)",               // NORMAL
	"temp_store(2)",                // MEMORY
	"busy_timeout(5000)",           // 5 s
	"foreign_keys(1)",
	"cache_size(-32768)",   // 32 MiB per connection
	"mmap_size(268435456)", // 256 MiB per mapped database
	"cache_spill(1)",
}

// New opens (or creates) a SQLite database at dbPath and returns an
// initialised SQLiteStore with the pragmas in connectionPragmas applied to
// every connection, plus a one-time PRAGMA optimize warm-up.
//
// _txlock=immediate makes write transactions take the write lock at BEGIN
// instead of failing mid-transaction when a deferred read lock cannot be
// upgraded.
func New(dbPath string) (*SQLiteStore, error) {
	dsn := dbPath + "?_txlock=immediate"
	for _, p := range connectionPragmas {
		dsn += "&_pragma=" + p
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", dbPath, err)
	}

	// Single-writer discipline: SQLite allows exactly one writer at a time,
	// so queue in Go instead of colliding in C. One connection also makes
	// the per-connection pragmas apply to every statement by construction,
	// and keeps the cache-size memory budget at a flat 32 MiB. Reads
	// serialize behind writes; both are millisecond-scale on this store,
	// and the dashboard's HTMX polls tolerate that comfortably.
	db.SetMaxOpenConns(1)

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping %s: %w", dbPath, err)
	}

	s := &SQLiteStore{db: db, path: dbPath}

	// One-time initialization: prime the query planner. On a fresh DB this is
	// a cheap no-op; on an existing one it applies SQLite's bounded analysis
	// so early queries get good plans. Best-effort — a failure here must not
	// block opening the store.
	if err := s.Optimize(ctx); err != nil {
		slog.Warn("sqlite: initial PRAGMA optimize failed (non-fatal)", "error", err)
	}

	return s, nil
}

// Optimize runs PRAGMA optimize — SQLite's recommended maintenance over a
// direct ANALYZE in current versions, because it applies a bounded strategy
// suitable for large databases. Call after significant schema/index changes
// (Migrate does) or periodically during low traffic.
func (s *SQLiteStore) Optimize(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "PRAGMA optimize;"); err != nil {
		return fmt.Errorf("pragma optimize: %w", err)
	}
	return nil
}

// Checkpoint runs a PASSIVE WAL checkpoint — folds committed WAL frames back
// into the main database without blocking readers or writers. wal_autocheckpoint
// already does this automatically; expose it for explicit low-traffic flushes
// (e.g. before backup or shutdown).
func (s *SQLiteStore) Checkpoint(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE);"); err != nil {
		return fmt.Errorf("pragma wal_checkpoint: %w", err)
	}
	return nil
}

// VacuumInto writes a transactionally-consistent copy of the database to
// dstPath using SQLite's VACUUM INTO. It reads a consistent snapshot under a
// read lock, so it is safe on a live database with concurrent writers and
// captures committed WAL frames not yet checkpointed into the main file — the
// SQLite-recommended way to snapshot an open database. dstPath must NOT
// already exist (VACUUM INTO refuses to overwrite).
func (s *SQLiteStore) VacuumInto(ctx context.Context, dstPath string) error {
	// The VACUUM INTO target is a string literal that cannot be bound as a
	// parameter; single-quote-escape it. dstPath is always an internal
	// tmpfs working path, never user input.
	esc := strings.ReplaceAll(dstPath, "'", "''")
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO '"+esc+"'"); err != nil { // #nosec G202 G701 -- VACUUM INTO cannot take bound params; dstPath single-quote-escaped, always an internal tmpfs path, never user input
		return fmt.Errorf("vacuum into %s: %w", dstPath, err)
	}
	return nil
}

// RawDB returns the underlying *sql.DB connection for raw queries.
// Use with care — this bypasses the Store interface.
func (s *SQLiteStore) RawDB() *sql.DB {
	return s.db
}

// Path returns the filesystem path of the underlying SQLite database
// (as supplied to New). Useful for diagnostics and remediation hints.
func (s *SQLiteStore) Path() string {
	return s.path
}

// isNoSuchTableErr reports whether err is the modernc.org/sqlite "no such
// table" error. Read paths used by the dashboard collapse this into an
// empty result so an un-migrated or freshly created DB file does not spam
// HTTP 500s and render errors on every HTMX poll. Write paths keep the
// raw error — callers writing to a missing table deserve to know.
func isNoSuchTableErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

// Close releases the underlying database connection pool.
func (s *SQLiteStore) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close sqlite: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Machines
// ---------------------------------------------------------------------------

const machineColumns = `id, machine_type, hostname, os_family, os_version,
	kernel_version, architecture,
	is_authorized, is_managed, environment, owner, criticality,
	discovery_source, first_seen_at, last_seen_at, tags, natural_key,
	mdm_enrollment_id, cmdb_sys_id, site, tenant, machine_tag,
	operational_status, ownership_type, enrolled_user_upn, compliance_state`

// scanMachine reads a single row from the result set into an Machine.
func scanMachine(row interface{ Scan(dest ...any) error }) (*model.Machine, error) {
	var a model.Machine
	var (
		idStr         string
		firstSeen     string
		lastSeen      string
		osFamily      sql.NullString
		osVersion     sql.NullString
		kernelVersion sql.NullString
		architecture  sql.NullString
		environment   sql.NullString
		owner         sql.NullString
		criticality   sql.NullString
		tags          sql.NullString
		naturalKey    sql.NullString

		mdmEnrollmentID   sql.NullString
		cmdbSysID         sql.NullString
		site              sql.NullString
		tenant            sql.NullString
		machineTag        sql.NullString
		operationalStatus sql.NullString
		ownershipType     sql.NullString
		enrolledUserUPN   sql.NullString
		complianceState   sql.NullString
	)
	err := row.Scan(
		&idStr,
		&a.MachineType,
		&a.Hostname,
		&osFamily,
		&osVersion,
		&kernelVersion,
		&architecture,
		&a.IsAuthorized,
		&a.IsManaged,
		&environment,
		&owner,
		&criticality,
		&a.DiscoverySource,
		&firstSeen,
		&lastSeen,
		&tags,
		&naturalKey,
		&mdmEnrollmentID,
		&cmdbSysID,
		&site,
		&tenant,
		&machineTag,
		&operationalStatus,
		&ownershipType,
		&enrolledUserUPN,
		&complianceState,
	)
	if err != nil {
		return nil, fmt.Errorf("scan machine: %w", err)
	}

	a.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse machine id: %w", err)
	}
	a.FirstSeenAt, err = time.Parse(time.RFC3339, firstSeen)
	if err != nil {
		return nil, fmt.Errorf("parse first_seen_at: %w", err)
	}
	a.LastSeenAt, err = time.Parse(time.RFC3339, lastSeen)
	if err != nil {
		return nil, fmt.Errorf("parse last_seen_at: %w", err)
	}
	a.OSFamily = osFamily.String
	a.OSVersion = osVersion.String
	a.KernelVersion = kernelVersion.String
	a.Architecture = architecture.String
	a.Environment = environment.String
	a.Owner = owner.String
	a.Criticality = criticality.String
	a.Tags = tags.String
	a.NaturalKey = naturalKey.String
	a.MDMEnrollmentID = mdmEnrollmentID.String
	a.CMDBSysID = cmdbSysID.String
	a.Site = site.String
	a.Tenant = tenant.String
	a.MachineTag = machineTag.String
	a.OperationalStatus = operationalStatus.String
	a.OwnershipType = ownershipType.String
	a.EnrolledUserUPN = enrolledUserUPN.String
	a.ComplianceState = complianceState.String

	return &a, nil
}

// UpsertMachine inserts a new machine or replaces an existing one matched by the
// UNIQUE(hostname, machine_type) constraint. The natural key is computed before
// writing.
func (s *SQLiteStore) UpsertMachine(ctx context.Context, machine model.Machine) error {
	machine.ComputeNaturalKey()

	_, err := s.db.ExecContext(
		ctx, `
		INSERT INTO machines (`+machineColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hostname, machine_type) DO UPDATE SET
			os_family        = excluded.os_family,
			os_version       = excluded.os_version,
			kernel_version   = excluded.kernel_version,
			architecture     = excluded.architecture,
			is_authorized    = excluded.is_authorized,
			is_managed       = excluded.is_managed,
			environment      = excluded.environment,
			owner            = excluded.owner,
			criticality      = excluded.criticality,
			discovery_source = excluded.discovery_source,
			last_seen_at     = excluded.last_seen_at,
			tags             = excluded.tags,
			natural_key      = excluded.natural_key,
				mdm_enrollment_id  = excluded.mdm_enrollment_id,
				cmdb_sys_id        = excluded.cmdb_sys_id,
				site               = excluded.site,
				tenant             = excluded.tenant,
				machine_tag          = excluded.machine_tag,
				operational_status = excluded.operational_status,
				ownership_type     = excluded.ownership_type,
				enrolled_user_upn  = excluded.enrolled_user_upn,
				compliance_state   = excluded.compliance_state
	`,
		machine.ID.String(),
		string(machine.MachineType),
		machine.Hostname,
		nullStr(machine.OSFamily),
		nullStr(machine.OSVersion),
		nullStr(machine.KernelVersion),
		nullStr(machine.Architecture),
		string(machine.IsAuthorized),
		string(machine.IsManaged),
		nullStr(machine.Environment),
		nullStr(machine.Owner),
		nullStr(machine.Criticality),
		machine.DiscoverySource,
		machine.FirstSeenAt.Format(time.RFC3339),
		machine.LastSeenAt.Format(time.RFC3339),
		nullStr(machine.Tags),
		machine.NaturalKey,
		nullStr(machine.MDMEnrollmentID),
		nullStr(machine.CMDBSysID),
		nullStr(machine.Site),
		nullStr(machine.Tenant),
		nullStr(machine.MachineTag),
		nullStr(machine.OperationalStatus),
		nullStr(machine.OwnershipType),
		nullStr(machine.EnrolledUserUPN),
		nullStr(machine.ComplianceState),
	)
	if err != nil {
		return fmt.Errorf("upsert machine %s: %w", machine.ID, err)
	}
	return nil
}

// PersistSourceHealth upserts a circuit-breaker health snapshot into the
// source_health table (created by RFC-0062 but, until RFC-0135, never written).
// It gives the breaker durable, queryable state across process restarts —
// though the live in-memory circuit still starts cold on restart. Implements
// safety.HealthPersister; called best-effort after every RecordSuccess/
// RecordFailure, so it uses its own short-lived background context.
func (s *SQLiteStore) PersistSourceHealth(h safety.SourceHealth) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lastSuccess, lastFailure any
	if h.LastSuccessAt != nil {
		lastSuccess = h.LastSuccessAt.UTC().Format(time.RFC3339Nano)
	}
	if h.LastFailureAt != nil {
		lastFailure = h.LastFailureAt.UTC().Format(time.RFC3339Nano)
	}

	// Written best-effort after every source success/failure while the scan
	// is still writing elsewhere — retry lock contention like the other hot
	// telemetry path (RecordHeartbeat) instead of losing breaker state.
	return withTransientRetry(3, func() error {
		return s.persistSourceHealthOnce(ctx, h, lastSuccess, lastFailure)
	})
}

// persistSourceHealthOnce performs the single upsert attempt for
// PersistSourceHealth; split out so the retry wrapper stays readable.
func (s *SQLiteStore) persistSourceHealthOnce(ctx context.Context, h safety.SourceHealth, lastSuccess, lastFailure any) error {
	_, err := s.db.ExecContext(
		ctx, `
		INSERT INTO source_health (
			source_name, state, consecutive_failures, consecutive_successes,
			failure_threshold, cooldown_seconds, last_success_at, last_failure_at,
			last_failure_reason, total_trips, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
		ON CONFLICT(source_name) DO UPDATE SET
			state                 = excluded.state,
			consecutive_failures  = excluded.consecutive_failures,
			consecutive_successes = excluded.consecutive_successes,
			failure_threshold     = excluded.failure_threshold,
			cooldown_seconds      = excluded.cooldown_seconds,
			last_success_at       = excluded.last_success_at,
			last_failure_at       = excluded.last_failure_at,
			last_failure_reason   = excluded.last_failure_reason,
			total_trips           = excluded.total_trips,
			updated_at            = excluded.updated_at
	`,
		h.SourceName,
		string(h.State),
		h.ConsecutiveFailures,
		h.ConsecutiveSuccesses,
		h.FailureThreshold,
		h.CooldownSeconds,
		lastSuccess,
		lastFailure,
		nullStr(h.LastFailureReason),
		h.TotalTrips,
	)
	if err != nil {
		return fmt.Errorf("persist source health %s: %w", h.SourceName, err)
	}
	return nil
}

// UpsertMachines atomically upserts a batch of machines inside a single
// transaction and returns counts of newly inserted and updated rows.
//
// The full BeginTx → upsert loop → Commit is wrapped in
// withTransientRetry: a transient SQLite I/O error (typically caused by
// cloud-sync agents, antivirus, or backup tools racing the WAL/SHM
// files) is retried with a fresh transaction. The transaction is
// atomic, so retrying the whole operation is safe.
func (s *SQLiteStore) UpsertMachines(ctx context.Context, machines []model.Machine) (inserted, updated int, err error) {
	// Pre-compute natural keys for the whole batch (idempotent — safe
	// to do once even if the inner closure runs multiple times).
	for i := range machines {
		machines[i].ComputeNaturalKey()
	}

	err = withTransientRetry(3, func() error {
		// Reset counters on each attempt so a partial-then-retried
		// attempt doesn't double-count.
		inserted = 0
		updated = 0

		tx, txErr := s.db.BeginTx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("begin tx: %w", txErr)
		}
		defer tx.Rollback() //nolint:errcheck

		// Batch-query existing natural keys to avoid per-row SELECT COUNT(*).
		existingKeys := make(map[string]bool, len(machines))
		if len(machines) > 0 {
			lookupErr := func() error {
				placeholders := make([]string, len(machines))
				args := make([]any, len(machines))
				for i, a := range machines {
					placeholders[i] = "?"
					args[i] = a.NaturalKey
				}
				query := `SELECT natural_key FROM machines WHERE natural_key IN (` +
					strings.Join(placeholders, ",") + `)` //#nosec G202 -- placeholders are literal "?" strings, values are in args
				rows, qErr := tx.QueryContext(ctx, query, args...)
				if qErr != nil {
					return fmt.Errorf("batch lookup existing keys: %w", qErr)
				}
				defer func() { _ = rows.Close() }()
				for rows.Next() {
					var key string
					if scanErr := rows.Scan(&key); scanErr != nil {
						return fmt.Errorf("scan existing key: %w", scanErr)
					}
					existingKeys[key] = true
				}
				if rowErr := rows.Err(); rowErr != nil {
					return fmt.Errorf("batch lookup rows: %w", rowErr)
				}
				return nil
			}()
			if lookupErr != nil {
				return lookupErr
			}
		}

		for i := range machines {
			_, execErr := tx.ExecContext(
				ctx, `
				INSERT INTO machines (`+machineColumns+`)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(hostname, machine_type) DO UPDATE SET
					os_family        = excluded.os_family,
					os_version       = excluded.os_version,
					kernel_version   = excluded.kernel_version,
					architecture     = excluded.architecture,
					is_authorized    = excluded.is_authorized,
					is_managed       = excluded.is_managed,
					environment      = excluded.environment,
					owner            = excluded.owner,
					criticality      = excluded.criticality,
					discovery_source = excluded.discovery_source,
					last_seen_at     = excluded.last_seen_at,
					tags             = excluded.tags,
					natural_key      = excluded.natural_key,
				mdm_enrollment_id  = excluded.mdm_enrollment_id,
				cmdb_sys_id        = excluded.cmdb_sys_id,
				site               = excluded.site,
				tenant             = excluded.tenant,
				machine_tag          = excluded.machine_tag,
				operational_status = excluded.operational_status,
				ownership_type     = excluded.ownership_type,
				enrolled_user_upn  = excluded.enrolled_user_upn,
				compliance_state   = excluded.compliance_state
			`,
				machines[i].ID.String(),
				string(machines[i].MachineType),
				machines[i].Hostname,
				nullStr(machines[i].OSFamily),
				nullStr(machines[i].OSVersion),
				nullStr(machines[i].KernelVersion),
				nullStr(machines[i].Architecture),
				string(machines[i].IsAuthorized),
				string(machines[i].IsManaged),
				nullStr(machines[i].Environment),
				nullStr(machines[i].Owner),
				nullStr(machines[i].Criticality),
				machines[i].DiscoverySource,
				machines[i].FirstSeenAt.Format(time.RFC3339),
				machines[i].LastSeenAt.Format(time.RFC3339),
				nullStr(machines[i].Tags),
				machines[i].NaturalKey,
				nullStr(machines[i].MDMEnrollmentID),
				nullStr(machines[i].CMDBSysID),
				nullStr(machines[i].Site),
				nullStr(machines[i].Tenant),
				nullStr(machines[i].MachineTag),
				nullStr(machines[i].OperationalStatus),
				nullStr(machines[i].OwnershipType),
				nullStr(machines[i].EnrolledUserUPN),
				nullStr(machines[i].ComplianceState),
			)
			if execErr != nil {
				return fmt.Errorf("upsert machine %s: %w", machines[i].ID, execErr)
			}

			if existingKeys[machines[i].NaturalKey] {
				updated++
			} else {
				inserted++
			}
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("commit tx: %w", commitErr)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return inserted, updated, nil
}

// GetMachineByID retrieves the machine identified by id. Returns store.ErrNotFound
// when the id does not exist.
func (s *SQLiteStore) GetMachineByID(ctx context.Context, id uuid.UUID) (*model.Machine, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE id = ?`, id.String())
	a, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get machine by id: %w", err)
	}
	return a, nil
}

// GetMachineByNaturalKey retrieves the machine whose precomputed SHA-256 natural
// key matches key. Returns (nil, nil) when no match is found.
func (s *SQLiteStore) GetMachineByNaturalKey(ctx context.Context, key string) (*model.Machine, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE natural_key = ?`, key)
	a, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get machine by natural key: %w", err)
	}
	return a, nil
}

// GetMachinesByNaturalKeys batch-fetches machines matching the supplied natural
// keys. The returned map is keyed by NaturalKey for O(1) lookup; keys with no
// matching row are absent. An empty input slice returns (nil, nil).
func (s *SQLiteStore) GetMachinesByNaturalKeys(
	ctx context.Context, keys []string,
) (map[string]model.Machine, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(keys))
	args := make([]any, len(keys))
	for i, k := range keys {
		placeholders[i] = "?"
		args[i] = k
	}
	//#nosec G202 -- placeholders are static "?" tokens; values flow via args.
	query := `SELECT ` + machineColumns + ` FROM machines WHERE natural_key IN (` +
		strings.Join(placeholders, ",") + `)`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get machines by natural keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]model.Machine, len(keys))
	for rows.Next() {
		a, err := scanMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("scan machine row: %w", err)
		}
		out[a.NaturalKey] = *a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machine rows: %w", err)
	}
	return out, nil
}

// ListMachines returns machines matching the supplied filter. An empty filter
// returns all machines (subject to Limit/Offset).
func (s *SQLiteStore) ListMachines(ctx context.Context, filter store.MachineFilter) ([]model.Machine, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.MachineType != "" {
		clauses = append(clauses, "machine_type = ?")
		args = append(args, filter.MachineType)
	}
	if filter.IsAuthorized != "" {
		clauses = append(clauses, "is_authorized = ?")
		args = append(args, filter.IsAuthorized)
	}
	if filter.IsManaged != "" {
		clauses = append(clauses, "is_managed = ?")
		args = append(args, filter.IsManaged)
	}
	if filter.Hostname != "" {
		clauses = append(clauses, "hostname = ?")
		args = append(args, filter.Hostname)
	}

	query := `SELECT ` + machineColumns + ` FROM machines`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders, values are in args
	}
	query += " ORDER BY last_seen_at DESC, id ASC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var machines []model.Machine
	for rows.Next() {
		a, err := scanMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("scan machine row: %w", err)
		}
		machines = append(machines, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machine rows: %w", err)
	}
	return machines, nil
}

// GetStaleMachines returns machines whose last_seen_at is older than the given
// threshold measured from the current time.
func (s *SQLiteStore) GetStaleMachines(ctx context.Context, threshold time.Duration) ([]model.Machine, error) {
	cutoff := time.Now().UTC().Add(-threshold).Format(time.RFC3339)
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT `+machineColumns+` FROM machines WHERE last_seen_at < ? ORDER BY last_seen_at ASC, id ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("get stale machines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var machines []model.Machine
	for rows.Next() {
		a, err := scanMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("scan stale machine row: %w", err)
		}
		machines = append(machines, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stale machine rows: %w", err)
	}
	return machines, nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const eventColumns = `id, event_type, machine_id, scan_run_id, severity, details, timestamp`

// scanEvent reads a single row from the result set into an MachineEvent.
func scanEvent(row interface{ Scan(dest ...any) error }) (*model.MachineEvent, error) {
	var e model.MachineEvent
	var (
		idStr        string
		machineIDStr string
		scanIDStr    string
		details      sql.NullString
		ts           string
	)
	err := row.Scan(
		&idStr,
		&e.EventType,
		&machineIDStr,
		&scanIDStr,
		&e.Severity,
		&details,
		&ts,
	)
	if err != nil {
		return nil, fmt.Errorf("scan event: %w", err)
	}

	e.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse event id: %w", err)
	}
	e.MachineID, err = uuid.Parse(machineIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse event machine_id: %w", err)
	}
	e.ScanRunID, err = uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse event scan_run_id: %w", err)
	}
	e.Timestamp, err = time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("parse event timestamp: %w", err)
	}
	e.Details = details.String

	return &e, nil
}

// InsertEvent persists a single machine lifecycle event.
func (s *SQLiteStore) InsertEvent(ctx context.Context, event model.MachineEvent) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO events (`+eventColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID.String(),
		string(event.EventType),
		event.MachineID.String(),
		event.ScanRunID.String(),
		string(event.Severity),
		nullStr(event.Details),
		event.Timestamp.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert event %s: %w", event.ID, err)
	}
	return nil
}

// InsertEvents persists a batch of events inside a single transaction.
//
// Wrapped in withTransientRetry with a higher attempt budget (5)
// because event loss is the most painful failure mode — events drive
// alerting, audit trails, and downstream ingestion.
func (s *SQLiteStore) InsertEvents(ctx context.Context, events []model.MachineEvent) error {
	return withTransientRetry(5, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO events (`+eventColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare insert event: %w", err)
		}
		defer func() { _ = stmt.Close() }()

		for i := range events {
			_, err := stmt.ExecContext(
				ctx,
				events[i].ID.String(),
				string(events[i].EventType),
				events[i].MachineID.String(),
				events[i].ScanRunID.String(),
				string(events[i].Severity),
				nullStr(events[i].Details),
				events[i].Timestamp.Format(time.RFC3339),
			)
			if err != nil {
				return fmt.Errorf("insert event %s: %w", events[i].ID, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		return nil
	})
}

// ListEvents returns events matching the supplied filter.
func (s *SQLiteStore) ListEvents(ctx context.Context, filter store.EventFilter) ([]model.MachineEvent, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.MachineID != nil {
		clauses = append(clauses, "machine_id = ?")
		args = append(args, filter.MachineID.String())
	}
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}

	query := `SELECT ` + eventColumns + ` FROM events`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders, values are in args
	}
	query += " ORDER BY timestamp DESC, id ASC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []model.MachineEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		events = append(events, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate event rows: %w", err)
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Scan runs
// ---------------------------------------------------------------------------

const scanRunColumns = `id, started_at, completed_at, status, total_machines,
	new_machines, updated_machines, analyzed_machines, stale_machines, coverage_percent,
	error_count, scope_config, discovery_sources,
	trigger_source, triggered_by, cancel_requested_at`

// scanScanRun reads a single row from the result set into a ScanRun.
func scanScanRun(row interface{ Scan(dest ...any) error }) (*model.ScanRun, error) {
	var r model.ScanRun
	var (
		idStr             string
		startedAt         string
		completedAt       sql.NullString
		scopeConfig       sql.NullString
		discoverySources  sql.NullString
		triggerSource     sql.NullString
		triggeredBy       sql.NullString
		cancelRequestedAt sql.NullString
	)
	err := row.Scan(
		&idStr,
		&startedAt,
		&completedAt,
		&r.Status,
		&r.TotalMachines,
		&r.NewMachines,
		&r.UpdatedMachines,
		&r.AnalyzedMachines,
		&r.StaleMachines,
		&r.CoveragePercent,
		&r.ErrorCount,
		&scopeConfig,
		&discoverySources,
		&triggerSource,
		&triggeredBy,
		&cancelRequestedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan scan run: %w", err)
	}

	r.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse scan run id: %w", err)
	}
	r.StartedAt, err = time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	if completedAt.Valid {
		t, err := time.Parse(time.RFC3339, completedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse completed_at: %w", err)
		}
		r.CompletedAt = &t
	}
	if cancelRequestedAt.Valid {
		t, err := time.Parse(time.RFC3339, cancelRequestedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse cancel_requested_at: %w", err)
		}
		r.CancelRequestedAt = &t
	}
	r.ScopeConfig = scopeConfig.String
	r.DiscoverySources = discoverySources.String
	r.TriggerSource = triggerSource.String
	r.TriggeredBy = triggeredBy.String

	return &r, nil
}

// CreateScanRun records a new scan run.
func (s *SQLiteStore) CreateScanRun(ctx context.Context, run model.ScanRun) error {
	triggerSource := run.TriggerSource
	if triggerSource == "" {
		triggerSource = "cli"
	}
	return withTransientRetry(3, func() error {
		_, err := s.db.ExecContext(
			ctx,
			`INSERT INTO scan_runs (`+scanRunColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			run.ID.String(),
			run.StartedAt.Format(time.RFC3339),
			nullTimePtr(run.CompletedAt),
			string(run.Status),
			run.TotalMachines,
			run.NewMachines,
			run.UpdatedMachines,
			run.AnalyzedMachines,
			run.StaleMachines,
			run.CoveragePercent,
			run.ErrorCount,
			nullStr(run.ScopeConfig),
			nullStr(run.DiscoverySources),
			triggerSource,
			nullStr(run.TriggeredBy),
			nullTimePtr(run.CancelRequestedAt),
		)
		if err != nil {
			return fmt.Errorf("create scan run %s: %w", run.ID, err)
		}
		return nil
	})
}

// CompleteScanRun updates an existing scan run with the final result and marks
// it as completed (or failed when the result carries a non-completed status).
func (s *SQLiteStore) CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error {
	now := time.Now().UTC().Format(time.RFC3339)
	status := string(model.ScanStatusCompleted)
	if result.Status != "" {
		status = result.Status
	}
	var notFound bool
	err := withTransientRetry(3, func() error {
		notFound = false
		res, execErr := s.db.ExecContext(
			ctx, `
		UPDATE scan_runs SET
			completed_at     = ?,
			status           = ?,
			total_machines     = ?,
			new_machines       = ?,
			updated_machines   = ?,
			analyzed_machines  = ?,
			stale_machines     = ?,
			coverage_percent = ?,
			error_count      = ?
		WHERE id = ?`,
			now,
			status,
			result.TotalMachines,
			result.NewMachines,
			result.UpdatedMachines,
			result.AnalyzedMachines,
			result.StaleMachines,
			result.CoveragePercent,
			result.ErrorCount,
			id.String(),
		)
		if execErr != nil {
			return fmt.Errorf("complete scan run %s: %w", id, execErr)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			notFound = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if notFound {
		return fmt.Errorf("scan run %s not found", id)
	}
	return nil
}

// GetLatestScanRun returns the most recent scan run ordered by started_at, or
// (nil, nil) when no scan runs exist.
func (s *SQLiteStore) GetLatestScanRun(ctx context.Context) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+scanRunColumns+` FROM scan_runs ORDER BY started_at DESC LIMIT 1`)
	r, err := scanScanRun(row)
	if errors.Is(err, sql.ErrNoRows) || isNoSuchTableErr(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest scan run: %w", err)
	}
	return r, nil
}

// ListScanRuns returns scan runs ordered by started_at DESC, capped at limit.
// limit <= 0 uses the default (50); limit is hard-capped at 1000. Returns an
// empty slice (not nil) when no runs exist or the table is missing.
func (s *SQLiteStore) ListScanRuns(ctx context.Context, limit int) ([]model.ScanRun, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT `+scanRunColumns+` FROM scan_runs ORDER BY started_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		if isNoSuchTableErr(err) {
			return []model.ScanRun{}, nil
		}
		return nil, fmt.Errorf("list scan runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]model.ScanRun, 0, limit)
	for rows.Next() {
		r, err := scanScanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list scan runs: %w", err)
	}
	return out, nil
}

// GetScanRun returns the scan run identified by id, or store.ErrNotFound when
// no row matches.
func (s *SQLiteStore) GetScanRun(ctx context.Context, id uuid.UUID) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+scanRunColumns+` FROM scan_runs WHERE id = ?`, id.String())
	r, err := scanScanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scan run %s: %w", id, err)
	}
	return r, nil
}

// MarkScanCancelRequested stamps cancel_requested_at without mutating status,
// returning store.ErrNotFound when the row does not exist.
func (s *SQLiteStore) MarkScanCancelRequested(ctx context.Context, id uuid.UUID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET cancel_requested_at = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339), id.String())
	if err != nil {
		return fmt.Errorf("mark scan cancel requested %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Installed Software
// ---------------------------------------------------------------------------

const softwareColumns = `id, machine_id, software_name, vendor, version, cpe23, package_manager, architecture`

// scanSoftware reads a single row from the result set into an InstalledSoftware.
func scanSoftware(row interface{ Scan(dest ...any) error }) (*model.InstalledSoftware, error) {
	var s model.InstalledSoftware
	var (
		idStr        string
		machineIDStr string
		vendor       sql.NullString
		cpe23        sql.NullString
		pkgMgr       sql.NullString
		arch         sql.NullString
	)
	err := row.Scan(
		&idStr,
		&machineIDStr,
		&s.SoftwareName,
		&vendor,
		&s.Version,
		&cpe23,
		&pkgMgr,
		&arch,
	)
	if err != nil {
		return nil, fmt.Errorf("scan software: %w", err)
	}

	s.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse software id: %w", err)
	}
	s.MachineID, err = uuid.Parse(machineIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse software machine_id: %w", err)
	}
	s.Vendor = vendor.String
	s.CPE23 = cpe23.String
	s.PackageManager = pkgMgr.String
	s.Architecture = arch.String

	return &s, nil
}

// UpsertSoftware replaces all installed software records for the given machine.
// It deletes existing rows and inserts the new set inside a single transaction.
func (s *SQLiteStore) UpsertSoftware(ctx context.Context, machineID uuid.UUID, software []model.InstalledSoftware) error {
	return withTransientRetry(3, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		_, err = tx.ExecContext(ctx,
			`DELETE FROM installed_software WHERE machine_id = ?`, machineID.String())
		if err != nil {
			return fmt.Errorf("delete old software for %s: %w", machineID, err)
		}

		if len(software) == 0 {
			if commitErr := tx.Commit(); commitErr != nil {
				return fmt.Errorf("commit software tx: %w", commitErr)
			}
			return nil
		}

		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO installed_software (`+softwareColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare insert software: %w", err)
		}
		defer func() { _ = stmt.Close() }()

		for i := range software {
			_, err = stmt.ExecContext(
				ctx,
				software[i].ID.String(),
				machineID.String(),
				software[i].SoftwareName,
				software[i].Vendor, // NOT NULL DEFAULT '' in schema
				software[i].Version,
				nullStr(software[i].CPE23),
				nullStr(software[i].PackageManager),
				nullStr(software[i].Architecture),
			)
			if err != nil {
				return fmt.Errorf("insert software %s: %w", software[i].SoftwareName, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		return nil
	})
}

// ListSoftware returns all installed software records for the given machine,
// ordered by software name.
func (s *SQLiteStore) ListSoftware(ctx context.Context, machineID uuid.UUID) ([]model.InstalledSoftware, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT `+softwareColumns+` FROM installed_software WHERE machine_id = ? ORDER BY software_name ASC, version ASC, id ASC`,
		machineID.String(),
	)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list software: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var software []model.InstalledSoftware
	for rows.Next() {
		sw, err := scanSoftware(rows)
		if err != nil {
			return nil, fmt.Errorf("scan software row: %w", err)
		}
		software = append(software, *sw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate software rows: %w", err)
	}
	return software, nil
}

// ---------------------------------------------------------------------------
// Config Findings
// ---------------------------------------------------------------------------

const findingColumns = `id, machine_id, scan_run_id, auditor, check_id, title,
	severity, evidence, expected, remediation,
	cis_control, timestamp, first_seen_at`

// scanFinding reads a single row into a ConfigFinding.
func scanFinding(row interface{ Scan(dest ...any) error }) (*model.ConfigFinding, error) {
	var f model.ConfigFinding
	var (
		idStr        string
		machineIDStr string
		scanIDStr    string
		expected     sql.NullString
		remediation  sql.NullString
		cisControl   sql.NullString
		ts           string
		firstSeenAt  sql.NullString
	)
	err := row.Scan(
		&idStr,
		&machineIDStr,
		&scanIDStr,
		&f.Auditor,
		&f.CheckID,
		&f.Title,
		&f.Severity,
		&f.Evidence,
		&expected,
		&remediation,
		&cisControl,
		&ts,
		&firstSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan finding: %w", err)
	}

	f.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding id: %w", err)
	}
	f.MachineID, err = uuid.Parse(machineIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding machine_id: %w", err)
	}
	f.ScanRunID, err = uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding scan_run_id: %w", err)
	}
	f.Timestamp, err = time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("parse finding timestamp: %w", err)
	}
	if firstSeenAt.Valid && firstSeenAt.String != "" {
		if t, parseErr := time.Parse(time.RFC3339, firstSeenAt.String); parseErr == nil {
			f.FirstSeenAt = t
		}
	}
	f.Expected = expected.String
	f.Remediation = remediation.String
	f.CISControl = cisControl.String

	return &f, nil
}

// InsertFindings persists a batch of config findings. Findings with
// deterministic IDs (SCA, secrets) are upserted: on conflict the scan_run_id,
// evidence, and timestamp are updated while first_seen_at is preserved.
// Findings with random IDs (system auditors) are inserted normally.
func (s *SQLiteStore) InsertFindings(ctx context.Context, findings []model.ConfigFinding) error {
	if len(findings) == 0 {
		return nil
	}
	return withTransientRetry(3, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO config_findings (`+findingColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			scan_run_id  = excluded.scan_run_id,
			evidence     = excluded.evidence,
			timestamp    = excluded.timestamp
	`)
		if err != nil {
			return fmt.Errorf("prepare insert finding: %w", err)
		}
		defer func() { _ = stmt.Close() }()

		for i := range findings {
			firstSeen := findings[i].FirstSeenAt
			if firstSeen.IsZero() {
				firstSeen = findings[i].Timestamp
			}
			_, err := stmt.ExecContext(
				ctx,
				findings[i].ID.String(),
				findings[i].MachineID.String(),
				findings[i].ScanRunID.String(),
				findings[i].Auditor,
				findings[i].CheckID,
				findings[i].Title,
				string(findings[i].Severity),
				findings[i].Evidence,
				findings[i].Expected,
				findings[i].Remediation,
				findings[i].CISControl,
				findings[i].Timestamp.Format(time.RFC3339),
				firstSeen.Format(time.RFC3339),
			)
			if err != nil {
				return fmt.Errorf("insert finding %s: %w", findings[i].ID, err)
			}
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("commit findings: %w", commitErr)
		}
		return nil
	})
}

// ListFindings returns config findings matching the supplied filter.
func (s *SQLiteStore) ListFindings(ctx context.Context, filter store.FindingFilter) ([]model.ConfigFinding, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.MachineID != nil {
		clauses = append(clauses, "machine_id = ?")
		args = append(args, filter.MachineID.String())
	}
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}
	if filter.Auditor != "" {
		clauses = append(clauses, "auditor = ?")
		args = append(args, filter.Auditor)
	}
	if filter.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, filter.Severity)
	}

	query := `SELECT ` + findingColumns + ` FROM config_findings`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders
	}
	query += " ORDER BY timestamp DESC, id ASC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isNoSuchTableErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var findings []model.ConfigFinding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		findings = append(findings, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding rows: %w", err)
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Runtime Incidents
// ---------------------------------------------------------------------------

const incidentColumns = `id, incident_type, component, error_message,
	stack_trace, scan_run_id, severity, recovered, error_code, created_at`

func (s *SQLiteStore) InsertRuntimeIncident(ctx context.Context, incident model.RuntimeIncident) error {
	var scanRunID sql.NullString
	if incident.ScanRunID != nil {
		scanRunID = sql.NullString{String: incident.ScanRunID.String(), Valid: true}
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO runtime_incidents (`+incidentColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		incident.ID.String(),
		string(incident.IncidentType),
		incident.Component,
		incident.ErrorMessage,
		nullStr(incident.StackTrace),
		scanRunID,
		incident.Severity,
		boolToInt(incident.Recovered),
		nullStr(incident.ErrorCode),
		incident.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert runtime incident %s: %w", incident.ID, err)
	}
	return nil
}

func (s *SQLiteStore) ListRuntimeIncidents(ctx context.Context, filter store.IncidentFilter) ([]model.RuntimeIncident, error) {
	var (
		clauses []string
		args    []any
	)
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}
	if filter.IncidentType != "" {
		clauses = append(clauses, "incident_type = ?")
		args = append(args, filter.IncidentType)
	}
	if filter.Since != nil {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, filter.Since.Format(time.RFC3339Nano))
	}

	query := "SELECT " + incidentColumns + " FROM runtime_incidents"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") // #nosec G202 -- clauses use parameterized placeholders, not user input
	}
	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list runtime incidents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var incidents []model.RuntimeIncident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, fmt.Errorf("scan incident row: %w", err)
		}
		incidents = append(incidents, *inc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runtime incidents: %w", err)
	}
	return incidents, nil
}

func scanIncident(row interface{ Scan(dest ...any) error }) (*model.RuntimeIncident, error) {
	var (
		inc        model.RuntimeIncident
		idStr      string
		scanRunID  sql.NullString
		stackTrace sql.NullString
		errorCode  sql.NullString
		createdAt  string
		recovered  int
	)
	err := row.Scan(
		&idStr,
		&inc.IncidentType,
		&inc.Component,
		&inc.ErrorMessage,
		&stackTrace,
		&scanRunID,
		&inc.Severity,
		&recovered,
		&errorCode,
		&createdAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan incident row: %w", err)
	}
	inc.ID, _ = uuid.Parse(idStr)
	inc.Recovered = recovered != 0
	if stackTrace.Valid {
		inc.StackTrace = stackTrace.String
	}
	if errorCode.Valid {
		inc.ErrorCode = errorCode.String
	}
	if scanRunID.Valid {
		id, _ := uuid.Parse(scanRunID.String)
		inc.ScanRunID = &id
	}
	inc.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}
	return &inc, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nullStr returns a sql.NullString that is NULL when s is empty.
func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullTimePtr formats a *time.Time as an RFC3339 sql.NullString, NULL when nil.
func nullTimePtr(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.Format(time.RFC3339), Valid: true}
}
