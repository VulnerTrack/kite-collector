package endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// Queue provides local SQLite-backed buffering for data that cannot be
// delivered to any endpoint.
type Queue struct {
	db      *sql.DB
	logger  *slog.Logger
	maxRows int // 0 = unlimited; otherwise Enqueue evicts oldest rows beyond this
}

// QueueOption configures a Queue at construction.
type QueueOption func(*Queue)

// WithMaxRows caps the queue at n rows. When Enqueue would exceed the cap the
// oldest rows are evicted (and logged as data loss). 0 disables the cap. This
// is the disk-growth backstop for a long endpoint outage: durability is
// bounded by disk, so the cap trades the oldest undelivered data for a bound.
func WithMaxRows(n int) QueueOption {
	return func(q *Queue) { q.maxRows = n }
}

// NewQueue opens or creates a SQLite queue database at the given data directory.
func NewQueue(ctx context.Context, dataDir string, logger *slog.Logger, opts ...QueueOption) (*Queue, error) {
	if logger == nil {
		logger = slog.Default()
	}

	dbPath := filepath.Join(dataDir, "queue.db")
	// Pragmas ride the DSN in modernc.org/sqlite's `_pragma=` form so they
	// apply to every pooled connection — a `db.Exec("PRAGMA ...")` only
	// configures the single connection the pool happens to hand out
	// (journal_mode persists in the file, but busy_timeout and synchronous
	// are per-connection). Mirrors internal/store/sqlite.New; the queue is a
	// lighter single-table workload, so the big page-cache/mmap allowances
	// there are omitted — WAL + busy_timeout + NORMAL are what matter here.
	dsn := dbPath + "?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=wal_autocheckpoint(2000)" +
		"&_pragma=journal_size_limit(67108864)" + // 64 MiB
		"&_pragma=synchronous(1)" + // NORMAL
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=temp_store(2)" // MEMORY
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open queue database: %w", err)
	}
	db.SetMaxOpenConns(1) // single-writer discipline (see store.New)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping queue database: %w", err)
	}

	// Create tables.
	schema := `CREATE TABLE IF NOT EXISTS queue (
		id TEXT PRIMARY KEY,
		route TEXT NOT NULL,
		payload BLOB NOT NULL,
		created_at TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0
	)`
	if _, execErr := db.ExecContext(ctx, schema); execErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create queue table: %w", execErr)
	}

	q := &Queue{db: db, logger: logger}
	for _, opt := range opts {
		opt(q)
	}
	logger.Info("offline queue initialized", "path", dbPath, "max_rows", q.maxRows)
	return q, nil
}

// Enqueue stores a payload for later delivery. When a row cap is configured
// (WithMaxRows) and the insert pushes the queue past it, the oldest rows are
// evicted so disk usage stays bounded during a long endpoint outage.
func (q *Queue) Enqueue(ctx context.Context, route string, payload []byte) error {
	id := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := q.db.ExecContext(
		ctx,
		"INSERT INTO queue (id, route, payload, created_at) VALUES (?, ?, ?, ?)",
		id, route, payload, now,
	)
	if err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	q.logger.Debug("enqueued payload for offline delivery", "route", route, "id", id)
	q.enforceCapacity(ctx)
	return nil
}

// enforceCapacity evicts the oldest rows when the queue exceeds maxRows.
// Best-effort: an eviction failure is logged, never fatal to Enqueue (the
// payload is already durably stored — losing the cap check is preferable to
// losing the just-accepted write).
func (q *Queue) enforceCapacity(ctx context.Context) {
	if q.maxRows <= 0 {
		return
	}
	var depth int
	if err := q.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM queue").Scan(&depth); err != nil {
		q.logger.Warn("queue capacity check failed", "code", string(LogCodeQueueCapacityCheckFailed), "error", err)
		return
	}
	if depth <= q.maxRows {
		return
	}
	excess := depth - q.maxRows
	res, err := q.db.ExecContext(ctx,
		`DELETE FROM queue WHERE id IN (
			SELECT id FROM queue ORDER BY created_at ASC, id ASC LIMIT ?
		)`, excess)
	if err != nil {
		q.logger.Warn("queue capacity eviction failed", "code", string(LogCodeQueueEvictFailed), "error", err)
		return
	}
	evicted, _ := res.RowsAffected()
	q.logger.Warn("offline queue over capacity; evicted oldest undelivered payloads (data loss)",
		"code", string(LogCodeQueueEvicted),
		"evicted", evicted,
		"max_rows", q.maxRows)
}

// IncrementAttempts records one more failed delivery attempt for id. The
// attempts count lets the drainer distinguish a payload the server keeps
// rejecting (poison) from a transient outage, and drop it after a bound.
func (q *Queue) IncrementAttempts(ctx context.Context, id string) error {
	if _, err := q.db.ExecContext(ctx,
		"UPDATE queue SET attempts = attempts + 1 WHERE id = ?", id); err != nil {
		return fmt.Errorf("increment attempts %s: %w", id, err)
	}
	return nil
}

// QueuedItem represents a single queued payload.
type QueuedItem struct {
	ID       string
	Route    string
	Payload  []byte
	Attempts int
}

// Peek returns up to limit items for the given route without removing them.
func (q *Queue) Peek(ctx context.Context, route string, limit int) ([]QueuedItem, error) {
	rows, err := q.db.QueryContext(
		ctx,
		"SELECT id, route, payload, attempts FROM queue WHERE route = ? ORDER BY created_at ASC LIMIT ?",
		route, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("peek queue: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []QueuedItem
	for rows.Next() {
		var item QueuedItem
		if scanErr := rows.Scan(&item.ID, &item.Route, &item.Payload, &item.Attempts); scanErr != nil {
			return nil, fmt.Errorf("scan queue row: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queue rows: %w", err)
	}
	return items, nil
}

// Remove deletes a successfully delivered item from the queue.
func (q *Queue) Remove(ctx context.Context, id string) error {
	_, err := q.db.ExecContext(ctx, "DELETE FROM queue WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("remove queue item %s: %w", id, err)
	}
	return nil
}

// Depth returns the total number of items in the queue.
func (q *Queue) Depth(ctx context.Context) (int, error) {
	var count int
	if err := q.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM queue").Scan(&count); err != nil {
		return 0, fmt.Errorf("query queue depth: %w", err)
	}
	return count, nil
}

// Close releases the database connection.
func (q *Queue) Close() error {
	if err := q.db.Close(); err != nil {
		return fmt.Errorf("close queue db: %w", err)
	}
	return nil
}
