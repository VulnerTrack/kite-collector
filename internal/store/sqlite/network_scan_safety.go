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

// NetworkScanEventRow is the read projection of a network_scan_events row.
// Times are kept in their RFC3339Nano string form because the DBOS bridge
// re-serialises them to ClickHouse DateTime64 directly.
type NetworkScanEventRow struct {
	ScanID           string  `json:"scan_id"`
	AgentID          string  `json:"agent_id"`
	ScopeHash        string  `json:"scope_hash"`
	StartedAt        string  `json:"started_at"`
	CompletedAt      *string `json:"completed_at,omitempty"`
	PortsProbedJSON  string  `json:"ports_probed_json"`
	Outcome          string  `json:"outcome"`
	IPsEnumerated    int64   `json:"ips_enumerated"`
	IPsScanned       int64   `json:"ips_scanned"`
	IPsResponsive    int64   `json:"ips_responsive"`
	SafetyGuardCount int64   `json:"safety_guard_count"`
}

// NetworkOpenPortRow is the read projection of a network_open_ports row.
type NetworkOpenPortRow struct {
	ID        string `json:"id"`
	ScanID    string `json:"scan_id"`
	IPAddress string `json:"ip_address"`
	Protocol  string `json:"protocol"`
	ProbeAt   string `json:"probe_at"`
	Port      int    `json:"port"`
}

// SafetyGuardEventRow is the read projection of a safety_guard_events row.
type SafetyGuardEventRow struct {
	ScanID          *string `json:"scan_id,omitempty"`
	ID              string  `json:"id"`
	GuardType       string  `json:"guard_type"`
	ActionTaken     string  `json:"action_taken"`
	TriggeredAt     string  `json:"triggered_at"`
	InputSummary    string  `json:"input_summary"`
	SourceComponent string  `json:"source_component"`
	DetailsJSON     string  `json:"details_json"`
}

// NetworkScanEventFilter constrains ListNetworkScanEvents.
type NetworkScanEventFilter struct {
	Since  *time.Time
	Limit  int
	Offset int
}

// NetworkOpenPortFilter constrains ListNetworkOpenPorts.
type NetworkOpenPortFilter struct {
	Since  *time.Time
	ScanID string
	Limit  int
	Offset int
}

// SafetyGuardEventFilter constrains ListSafetyGuardEvents.
type SafetyGuardEventFilter struct {
	Since     *time.Time
	GuardType string
	Limit     int
	Offset    int
}

// ListNetworkScanEvents returns scan events in started_at DESC order, optionally
// filtered by Since (started_at > Since). Used by the DBOS bridge to harvest
// rows for ClickHouse replication.
func (s *SQLiteStore) ListNetworkScanEvents(
	ctx context.Context, f NetworkScanEventFilter,
) ([]NetworkScanEventRow, error) {
	args := []any{}
	q := `
		SELECT scan_id, agent_id, scope_hash, started_at, completed_at,
		       ips_enumerated, ips_scanned, ips_responsive,
		       ports_probed_json, outcome, safety_guard_count
		FROM network_scan_events
	`
	if f.Since != nil {
		q += " WHERE started_at > ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	q += " ORDER BY started_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list network_scan_events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]NetworkScanEventRow, 0, 64)
	for rows.Next() {
		var r NetworkScanEventRow
		var completed sql.NullString
		if scanErr := rows.Scan(
			&r.ScanID, &r.AgentID, &r.ScopeHash, &r.StartedAt, &completed,
			&r.IPsEnumerated, &r.IPsScanned, &r.IPsResponsive,
			&r.PortsProbedJSON, &r.Outcome, &r.SafetyGuardCount,
		); scanErr != nil {
			return nil, fmt.Errorf("scan network_scan_events row: %w", scanErr)
		}
		if completed.Valid {
			v := completed.String
			r.CompletedAt = &v
		}
		out = append(out, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate network_scan_events: %w", rowsErr)
	}
	return out, nil
}

// ListNetworkOpenPorts returns open-port observations in probe_at DESC order.
func (s *SQLiteStore) ListNetworkOpenPorts(
	ctx context.Context, f NetworkOpenPortFilter,
) ([]NetworkOpenPortRow, error) {
	args := []any{}
	q := `
		SELECT id, scan_id, ip_address, port, protocol, probe_at
		FROM network_open_ports
	`
	conds := make([]string, 0, 2)
	if f.Since != nil {
		conds = append(conds, "probe_at > ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if f.ScanID != "" {
		conds = append(conds, "scan_id = ?")
		args = append(args, f.ScanID)
	}
	if len(conds) > 0 {
		q += " WHERE " + joinConds(conds)
	}
	q += " ORDER BY probe_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list network_open_ports: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]NetworkOpenPortRow, 0, 256)
	for rows.Next() {
		var r NetworkOpenPortRow
		if scanErr := rows.Scan(
			&r.ID, &r.ScanID, &r.IPAddress, &r.Port, &r.Protocol, &r.ProbeAt,
		); scanErr != nil {
			return nil, fmt.Errorf("scan network_open_ports row: %w", scanErr)
		}
		out = append(out, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate network_open_ports: %w", rowsErr)
	}
	return out, nil
}

// ListSafetyGuardEvents returns guard events in triggered_at DESC order.
func (s *SQLiteStore) ListSafetyGuardEvents(
	ctx context.Context, f SafetyGuardEventFilter,
) ([]SafetyGuardEventRow, error) {
	args := []any{}
	q := `
		SELECT id, guard_type, action_taken, triggered_at,
		       input_summary, source_component, details_json, scan_id
		FROM safety_guard_events
	`
	conds := make([]string, 0, 2)
	if f.Since != nil {
		conds = append(conds, "triggered_at > ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if f.GuardType != "" {
		conds = append(conds, "guard_type = ?")
		args = append(args, f.GuardType)
	}
	if len(conds) > 0 {
		q += " WHERE " + joinConds(conds)
	}
	q += " ORDER BY triggered_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list safety_guard_events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]SafetyGuardEventRow, 0, 64)
	for rows.Next() {
		var r SafetyGuardEventRow
		var scanID sql.NullString
		if scanErr := rows.Scan(
			&r.ID, &r.GuardType, &r.ActionTaken, &r.TriggeredAt,
			&r.InputSummary, &r.SourceComponent, &r.DetailsJSON, &scanID,
		); scanErr != nil {
			return nil, fmt.Errorf("scan safety_guard_events row: %w", scanErr)
		}
		if scanID.Valid {
			v := scanID.String
			r.ScanID = &v
		}
		out = append(out, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate safety_guard_events: %w", rowsErr)
	}
	return out, nil
}

// joinConds joins SQL conditions with " AND ". Kept local to avoid an
// import for one call site.
func joinConds(conds []string) string {
	out := ""
	for i, c := range conds {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}
