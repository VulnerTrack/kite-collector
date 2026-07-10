package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

const heartbeatColumns = `id, scan_run_id, source, status, items_emitted, ` +
	`duration_ms, binary_hash, signature, created_at`

// RecordHeartbeat persists one ProbeHeartbeat. The (scan_run_id, source)
// unique index makes duplicate inserts surface as a SQLite constraint
// violation; the caller treats that as a registry bug, not an alert.
func (s *SQLiteStore) RecordHeartbeat(ctx context.Context, hb model.ProbeHeartbeat) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO probe_heartbeats (`+heartbeatColumns+`) `+
			`VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hb.ID.String(),
		hb.ScanRunID.String(),
		hb.Source,
		string(hb.Status),
		hb.ItemsEmitted,
		hb.DurationMS,
		hb.BinaryHash,
		hb.Signature,
		hb.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert probe heartbeat %s/%s: %w", hb.ScanRunID, hb.Source, err)
	}
	return nil
}

// ListHeartbeats returns heartbeats matching the filter, ordered by
// created_at DESC. An empty filter returns every heartbeat ever recorded;
// callers responsible for pagination via Limit/Offset.
func (s *SQLiteStore) ListHeartbeats(ctx context.Context, filter store.HeartbeatFilter) ([]model.ProbeHeartbeat, error) {
	var (
		clauses []string
		args    []any
	)
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}
	if filter.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, filter.Source)
	}
	if filter.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.Since != nil {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, filter.Since.Format(time.RFC3339Nano))
	}

	query := "SELECT " + heartbeatColumns + " FROM probe_heartbeats"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") // #nosec G202 -- clauses use parameterized placeholders
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
		return nil, fmt.Errorf("list heartbeats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []model.ProbeHeartbeat
	for rows.Next() {
		hb, scanErr := scanHeartbeat(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan heartbeat row: %w", scanErr)
		}
		out = append(out, hb)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate heartbeats: %w", err)
	}
	return out, nil
}

func scanHeartbeat(row interface {
	Scan(dest ...any) error
},
) (model.ProbeHeartbeat, error) {
	var (
		idStr, scanRunStr, source, status, binaryHash, createdAt string
		itemsEmitted, durationMS                                 int64
		signature                                                []byte
	)
	if err := row.Scan(
		&idStr, &scanRunStr, &source, &status, &itemsEmitted,
		&durationMS, &binaryHash, &signature, &createdAt,
	); err != nil {
		return model.ProbeHeartbeat{}, fmt.Errorf("scan heartbeat: %w", err)
	}
	hb := model.ProbeHeartbeat{
		Source:       source,
		Status:       model.HeartbeatStatus(status),
		ItemsEmitted: int(itemsEmitted),
		DurationMS:   durationMS,
		BinaryHash:   binaryHash,
		Signature:    signature,
	}
	id, perr := uuid.Parse(idStr)
	if perr != nil {
		return model.ProbeHeartbeat{}, fmt.Errorf("parse heartbeat id: %w", perr)
	}
	scanID, perr := uuid.Parse(scanRunStr)
	if perr != nil {
		return model.ProbeHeartbeat{}, fmt.Errorf("parse heartbeat scan_run_id: %w", perr)
	}
	hb.ID = id
	hb.ScanRunID = scanID
	parsed, perr := time.Parse(time.RFC3339Nano, createdAt)
	if perr != nil {
		return model.ProbeHeartbeat{}, fmt.Errorf("parse heartbeat created_at: %w", perr)
	}
	hb.CreatedAt = parsed
	return hb, nil
}
