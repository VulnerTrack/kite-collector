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
	db     *sql.DB
	logger *slog.Logger
}

// NewQueue opens or creates a SQLite queue database at the given data directory.
func NewQueue(ctx context.Context, dataDir string, logger *slog.Logger) (*Queue, error) {
	if logger == nil {
		logger = slog.Default()
	}

	dbPath := filepath.Join(dataDir, "queue.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open queue database: %w", err)
	}

	// Apply performance pragmas.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, execErr := db.ExecContext(ctx, p); execErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set pragma %q: %w", p, execErr)
		}
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

	logger.Info("offline queue initialized", "path", dbPath)
	return &Queue{db: db, logger: logger}, nil
}

// Enqueue stores a payload for later delivery.
func (q *Queue) Enqueue(ctx context.Context, route string, payload []byte) error {
	id := uuid.Must(uuid.NewV7()).String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := q.db.ExecContext(ctx,
		"INSERT INTO queue (id, route, payload, created_at) VALUES (?, ?, ?, ?)",
		id, route, payload, now,
	)
	if err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	q.logger.Debug("enqueued payload for offline delivery", "route", route, "id", id)
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
	rows, err := q.db.QueryContext(ctx,
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
