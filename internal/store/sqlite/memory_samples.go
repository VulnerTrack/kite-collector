package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

var _ store.MemorySampleStore = (*SQLiteStore)(nil)

// InsertMemorySample appends one point to a machine's RAM time series. A zero
// ID is filled with a fresh UUIDv7 so callers can leave it unset. sampled_at
// is stored as RFC3339 UTC to match the rest of the schema and to sort
// lexicographically for the time-series/prune index.
func (s *SQLiteStore) InsertMemorySample(ctx context.Context, sample model.MemorySample) error {
	if sample.ID == uuid.Nil {
		sample.ID = uuid.Must(uuid.NewV7())
	}
	when := sample.SampledAt
	if when.IsZero() {
		when = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO machine_memory_samples
		    (id, machine_id, sampled_at, total_bytes, used_bytes, used_percent)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sample.ID.String(), sample.MachineID.String(), when.UTC().Format(time.RFC3339),
		sample.TotalBytes, sample.UsedBytes, sample.UsedPercent)
	if err != nil {
		return fmt.Errorf("insert memory sample: %w", err)
	}
	return nil
}

// ListMemorySamples returns a machine's samples at or after `since`, oldest
// first, capped at `limit` (a non-positive limit means no cap). Oldest-first
// order is what a chart consumes directly.
func (s *SQLiteStore) ListMemorySamples(ctx context.Context, machineID uuid.UUID, since time.Time, limit int) ([]model.MemorySample, error) {
	query := `SELECT id, machine_id, sampled_at, total_bytes, used_bytes, used_percent
	            FROM machine_memory_samples
	           WHERE machine_id = ? AND sampled_at >= ?
	           ORDER BY sampled_at ASC`
	args := []any{machineID.String(), since.UTC().Format(time.RFC3339)}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list memory samples: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []model.MemorySample
	for rows.Next() {
		var (
			m                   model.MemorySample
			idStr, machineIDStr string
			sampledAt           string
		)
		if scanErr := rows.Scan(&idStr, &machineIDStr, &sampledAt, &m.TotalBytes, &m.UsedBytes, &m.UsedPercent); scanErr != nil {
			return nil, fmt.Errorf("scan memory sample: %w", scanErr)
		}
		if m.ID, err = uuid.Parse(idStr); err != nil {
			return nil, fmt.Errorf("parse memory sample id %q: %w", idStr, err)
		}
		if m.MachineID, err = uuid.Parse(machineIDStr); err != nil {
			return nil, fmt.Errorf("parse memory sample machine_id %q: %w", machineIDStr, err)
		}
		if m.SampledAt, err = time.Parse(time.RFC3339, sampledAt); err != nil {
			return nil, fmt.Errorf("parse memory sample sampled_at %q: %w", sampledAt, err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memory samples: %w", err)
	}
	return out, nil
}

// PruneMemorySamplesBefore deletes every sample older than cutoff and returns
// how many rows were removed. This is the retention mechanism: the sampler
// calls it with now minus the configured window each cycle.
func (s *SQLiteStore) PruneMemorySamplesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM machine_memory_samples WHERE sampled_at < ?`,
		cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("prune memory samples: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune memory samples rows affected: %w", err)
	}
	return n, nil
}
