package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

var _ store.HostListenerStore = (*SQLiteStore)(nil)

// validListenerProtocol / validListenerExposure gate values against the
// host_listeners CHECK constraints so one malformed row can't fail the whole
// transactional replace.
func validListenerProtocol(p string) bool {
	switch p {
	case "tcp", "tcp6", "udp", "udp6":
		return true
	}
	return false
}

func validListenerExposure(e string) bool {
	switch e {
	case "internet", "lan", "loopback", "unknown":
		return true
	}
	return false
}

// ReplaceHostListeners atomically swaps a machine's listeners: it deletes the
// machine's existing rows and inserts the supplied set inside one transaction,
// so a socket that stopped listening does not survive as a stale row. Rows
// whose protocol is not a valid enum value are skipped (they cannot satisfy the
// CHECK); an empty exposure defaults to "unknown".
func (s *SQLiteStore) ReplaceHostListeners(ctx context.Context, machineID uuid.UUID, listeners []model.HostListener) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin host listeners tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM host_listeners WHERE machine_id = ?`, machineID.String()); err != nil {
		return fmt.Errorf("delete host listeners: %w", err)
	}

	const insert = `INSERT INTO host_listeners
		(id, machine_id, protocol, bind_address, port, exposure, pid, process_name,
		 exe, username, service, service_version, last_seen_at, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	for _, l := range listeners {
		if !validListenerProtocol(l.Protocol) {
			continue
		}
		exposure := l.Exposure
		if !validListenerExposure(exposure) {
			exposure = "unknown"
		}
		id := l.ID
		if id == uuid.Nil {
			id = uuid.Must(uuid.NewV7())
		}
		seen := l.LastSeenAt
		if seen.IsZero() {
			seen = time.Now()
		}
		collected := l.CollectedAt
		if collected.IsZero() {
			collected = seen
		}
		var pid any
		if l.PID > 0 {
			pid = l.PID
		}
		if _, err := tx.ExecContext(ctx, insert,
			id.String(), machineID.String(), l.Protocol, l.BindAddress, l.Port, exposure,
			pid, l.ProcessName, l.Exe, l.Username, l.Service, l.ServiceVersion,
			seen.UTC().Format(time.RFC3339), collected.UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("insert host listener %s:%d: %w", l.Protocol, l.Port, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host listeners: %w", err)
	}
	return nil
}

// ListHostListeners returns a machine's listeners ordered by port then protocol.
func (s *SQLiteStore) ListHostListeners(ctx context.Context, machineID uuid.UUID) ([]model.HostListener, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, protocol, bind_address, port, exposure,
		        pid, COALESCE(process_name,''), COALESCE(exe,''), COALESCE(username,''),
		        COALESCE(service,''), COALESCE(service_version,''), last_seen_at, collected_at
		   FROM host_listeners
		  WHERE machine_id = ?
		  ORDER BY port, protocol`, machineID.String())
	if err != nil {
		return nil, fmt.Errorf("list host listeners: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []model.HostListener
	for rows.Next() {
		var (
			l         model.HostListener
			idStr     string
			port      int
			pid       sql.NullInt64
			seen      string
			collected string
		)
		if scanErr := rows.Scan(&idStr, &l.Protocol, &l.BindAddress, &port, &l.Exposure,
			&pid, &l.ProcessName, &l.Exe, &l.Username, &l.Service, &l.ServiceVersion,
			&seen, &collected); scanErr != nil {
			return nil, fmt.Errorf("scan host listener: %w", scanErr)
		}
		l.MachineID = machineID
		parsedID, parseErr := uuid.Parse(idStr)
		if parseErr != nil {
			return nil, fmt.Errorf("parse host listener id %q: %w", idStr, parseErr)
		}
		l.ID = parsedID
		l.Port = uint16(port) // #nosec G115 -- CHECK constrains port to 0..65535
		if pid.Valid {
			l.PID = int32(pid.Int64) // #nosec G115 -- OS pids fit int32
		}
		l.LastSeenAt, _ = time.Parse(time.RFC3339, seen)
		l.CollectedAt, _ = time.Parse(time.RFC3339, collected)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host listeners: %w", err)
	}
	return out, nil
}
