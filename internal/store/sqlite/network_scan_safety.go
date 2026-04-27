package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Compile-time assertion: SQLiteStore satisfies network.EventSink so the
// scanner can be wired with NewWithSink(sqliteStore, agentID).
var _ network.EventSink = (*SQLiteStore)(nil)

// WriteScanEvent persists a single network scan envelope. Returning an error
// keeps the audit trail honest: the scanner downgrades log lines but does
// not silently drop persistence failures.
func (s *SQLiteStore) WriteScanEvent(ctx context.Context, ev network.ScanEvent) error {
	if ev.ScanID == "" {
		return fmt.Errorf("network scan event: scan_id is required")
	}
	completed := nullTimePtr(ev.CompletedAt)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO network_scan_events (
			scan_id, agent_id, scope_hash,
			started_at, completed_at,
			ips_enumerated, ips_scanned, ips_responsive,
			ports_probed_json, outcome, safety_guard_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id) DO UPDATE SET
			completed_at       = excluded.completed_at,
			ips_enumerated     = excluded.ips_enumerated,
			ips_scanned        = excluded.ips_scanned,
			ips_responsive     = excluded.ips_responsive,
			ports_probed_json  = excluded.ports_probed_json,
			outcome            = excluded.outcome,
			safety_guard_count = excluded.safety_guard_count
	`,
		ev.ScanID,
		ev.AgentID,
		ev.ScopeHash,
		ev.StartedAt.UTC().Format(time.RFC3339Nano),
		completed,
		ev.IPsEnumerated,
		ev.IPsScanned,
		ev.IPsResponsive,
		ev.PortsProbedJSON,
		ev.Outcome,
		ev.SafetyGuardCount,
	)
	if err != nil {
		return fmt.Errorf("insert network_scan_events %s: %w", ev.ScanID, err)
	}
	return nil
}

// WriteOpenPorts persists a batch of OpenPort observations under scanID
// inside a single transaction. An empty slice is a no-op.
func (s *SQLiteStore) WriteOpenPorts(
	ctx context.Context, scanID string, ports []network.OpenPort,
) error {
	if scanID == "" {
		return fmt.Errorf("network open ports: scan_id is required")
	}
	if len(ports) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx for open ports: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO network_open_ports (
			id, scan_id, ip_address, port, protocol, probe_at
		) VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare open ports insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, p := range ports {
		id, idErr := uuid.NewV7()
		if idErr != nil {
			return fmt.Errorf("uuid v7 for open port: %w", idErr)
		}
		protocol := p.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		if _, execErr := stmt.ExecContext(ctx,
			id.String(), scanID, p.IPAddress, p.Port, protocol,
			p.ProbeAt.UTC().Format(time.RFC3339Nano),
		); execErr != nil {
			return fmt.Errorf("insert open port %s:%d: %w",
				p.IPAddress, p.Port, execErr)
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit open ports: %w", commitErr)
	}
	return nil
}

// WriteGuardEvent persists a single safenet guard event. ScanID is optional
// — it is left NULL when the guard fires outside a scan (e.g. inside a
// paginated HTTP connector).
func (s *SQLiteStore) WriteGuardEvent(
	ctx context.Context, ev safenet.GuardEvent,
) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("uuid v7 for guard event: %w", err)
	}
	scanID := nullStr(ev.ScanID)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO safety_guard_events (
			id, guard_type, action_taken,
			triggered_at, input_summary,
			source_component, details_json, scan_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		id.String(),
		string(ev.GuardType),
		string(ev.Action),
		ev.TriggeredAt.UTC().Format(time.RFC3339Nano),
		ev.InputSummary,
		ev.SourceComponent,
		ev.DetailsJSON,
		scanID,
	)
	if err != nil {
		return fmt.Errorf("insert safety_guard_events %s: %w", ev.GuardType, err)
	}
	return nil
}
