package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/driver"
)

// WriteLoadedDrivers persists a batch of LoadedDriver records under assetID
// inside a single transaction. Each row is upserted on (asset_id, name,
// version) so re-running the collector replaces stale state in place. An
// empty slice is a no-op.
//
// IDs are auto-assigned UUID v7 when LoadedDriver.ID is the zero UUID; an
// existing ID on the input is preserved. Loaded drivers stamped this way
// can subsequently be referenced by device_bindings via the returned IDs.
func (s *SQLiteStore) WriteLoadedDrivers(
	ctx context.Context, assetID uuid.UUID, drivers []driver.LoadedDriver,
) ([]uuid.UUID, error) {
	if assetID == uuid.Nil {
		return nil, fmt.Errorf("loaded drivers: asset_id is required")
	}
	if len(drivers) == 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin tx for loaded drivers: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO loaded_drivers (
			id, asset_id, name, display_name, path, version, vendor,
			signer, signature_state, signature_algo, driver_framework,
			start_mode, state, architecture,
			on_disk_sha256, authentihash, import_hash, cpe23, description,
			taint_flags_json, dependencies_json,
			loaded_at, collected_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?,
			?, ?
		)
		ON CONFLICT(asset_id, name, version) DO UPDATE SET
			display_name      = excluded.display_name,
			path              = excluded.path,
			vendor            = excluded.vendor,
			signer            = excluded.signer,
			signature_state   = excluded.signature_state,
			signature_algo    = excluded.signature_algo,
			driver_framework  = excluded.driver_framework,
			start_mode        = excluded.start_mode,
			state             = excluded.state,
			architecture      = excluded.architecture,
			on_disk_sha256    = excluded.on_disk_sha256,
			authentihash      = excluded.authentihash,
			import_hash       = excluded.import_hash,
			cpe23             = excluded.cpe23,
			description       = excluded.description,
			taint_flags_json  = excluded.taint_flags_json,
			dependencies_json = excluded.dependencies_json,
			loaded_at         = excluded.loaded_at,
			collected_at      = excluded.collected_at,
			synced_at         = NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("prepare loaded drivers insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	ids := make([]uuid.UUID, len(drivers))
	for i, d := range drivers {
		id, idErr := assignDriverID(d.ID)
		if idErr != nil {
			return nil, idErr
		}
		ids[i] = id

		taintJSON, jErr := encodeStringArray(d.TaintFlags)
		if jErr != nil {
			return nil, fmt.Errorf("encode taint_flags %s: %w", d.Name, jErr)
		}
		depsJSON, jErr := encodeStringArray(d.Dependencies)
		if jErr != nil {
			return nil, fmt.Errorf("encode dependencies %s: %w", d.Name, jErr)
		}

		var loadedAt sql.NullString
		if !d.LoadedAt.IsZero() {
			loadedAt = sql.NullString{
				String: d.LoadedAt.UTC().Format(time.RFC3339Nano),
				Valid:  true,
			}
		}
		collectedAt := d.CollectedAt
		if collectedAt.IsZero() {
			collectedAt = time.Now().UTC()
		}

		if _, execErr := stmt.ExecContext(ctx,
			id.String(), assetID.String(), d.Name,
			nullStr(d.DisplayName), nullStr(d.Path),
			nullStr(d.Version), nullStr(d.Vendor),
			nullStr(d.Signer), d.SignatureState, nullStr(d.SignatureAlgo),
			d.DriverFramework,
			nullStr(d.StartMode), nullStr(d.State), nullStr(d.Architecture),
			nullStr(d.OnDiskSHA256), nullStr(d.Authentihash), nullStr(d.ImportHash),
			nullStr(d.CPE23), nullStr(d.Description),
			taintJSON, depsJSON,
			loadedAt, collectedAt.UTC().Format(time.RFC3339Nano),
		); execErr != nil {
			return nil, fmt.Errorf("insert loaded driver %s: %w", d.Name, execErr)
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return nil, fmt.Errorf("commit loaded drivers: %w", commitErr)
	}
	return ids, nil
}

// WriteDeviceBindings persists a batch of DeviceBinding records under
// assetID inside a single transaction. Each row is upserted on (asset_id,
// bus, address). An empty slice is a no-op.
//
// driverID may be the zero UUID, in which case the binding's driver_id
// column is left NULL — useful for PCI/USB devices with no bound driver.
func (s *SQLiteStore) WriteDeviceBindings(
	ctx context.Context, assetID uuid.UUID, bindings []driver.DeviceBinding,
) error {
	if assetID == uuid.Nil {
		return fmt.Errorf("device bindings: asset_id is required")
	}
	if len(bindings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx for device bindings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO device_bindings (
			id, asset_id, driver_id,
			bus, address, vendor_id, device_id,
			subsystem_vid, subsystem_did, class,
			driver_name, hardware_id, collected_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asset_id, bus, address) DO UPDATE SET
			driver_id     = excluded.driver_id,
			vendor_id     = excluded.vendor_id,
			device_id     = excluded.device_id,
			subsystem_vid = excluded.subsystem_vid,
			subsystem_did = excluded.subsystem_did,
			class         = excluded.class,
			driver_name   = excluded.driver_name,
			hardware_id   = excluded.hardware_id,
			collected_at  = excluded.collected_at,
			synced_at     = NULL
	`)
	if err != nil {
		return fmt.Errorf("prepare device bindings insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, b := range bindings {
		id, idErr := assignDriverID(b.ID)
		if idErr != nil {
			return idErr
		}
		var driverID sql.NullString
		if b.DriverID != uuid.Nil {
			driverID = sql.NullString{String: b.DriverID.String(), Valid: true}
		}
		if _, execErr := stmt.ExecContext(ctx,
			id.String(), assetID.String(), driverID,
			b.Bus, b.Address,
			nullStr(b.VendorID), nullStr(b.DeviceID),
			nullStr(b.SubsystemVID), nullStr(b.SubsystemDID), nullStr(b.Class),
			nullStr(b.DriverName), nullStr(b.HardwareID), now,
		); execErr != nil {
			return fmt.Errorf("insert device binding %s/%s: %w", b.Bus, b.Address, execErr)
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit device bindings: %w", commitErr)
	}
	return nil
}

// LoadedDriverRow is the read projection of a loaded_drivers row. Times are
// kept in their RFC3339Nano string form because the DBOS bridge re-serialises
// them to ClickHouse DateTime64 directly.
type LoadedDriverRow struct {
	LoadedAt        *string `json:"loaded_at,omitempty"`
	DisplayName     *string `json:"display_name,omitempty"`
	Path            *string `json:"path,omitempty"`
	Version         *string `json:"version,omitempty"`
	Vendor          *string `json:"vendor,omitempty"`
	Signer          *string `json:"signer,omitempty"`
	SignatureAlgo   *string `json:"signature_algo,omitempty"`
	StartMode       *string `json:"start_mode,omitempty"`
	State           *string `json:"state,omitempty"`
	Architecture    *string `json:"architecture,omitempty"`
	OnDiskSHA256    *string `json:"on_disk_sha256,omitempty"`
	Authentihash    *string `json:"authentihash,omitempty"`
	ImportHash      *string `json:"import_hash,omitempty"`
	CPE23           *string `json:"cpe23,omitempty"`
	Description     *string `json:"description,omitempty"`
	ID              string  `json:"id"`
	AssetID         string  `json:"asset_id"`
	Name            string  `json:"name"`
	SignatureState  string  `json:"signature_state"`
	DriverFramework string  `json:"driver_framework"`
	TaintFlagsJSON  string  `json:"taint_flags_json"`
	DependenciesRaw string  `json:"dependencies_json"`
	CollectedAt     string  `json:"collected_at"`
}

// DeviceBindingRow is the read projection of a device_bindings row.
type DeviceBindingRow struct {
	DriverID     *string `json:"driver_id,omitempty"`
	VendorID     *string `json:"vendor_id,omitempty"`
	DeviceID     *string `json:"device_id,omitempty"`
	SubsystemVID *string `json:"subsystem_vid,omitempty"`
	SubsystemDID *string `json:"subsystem_did,omitempty"`
	Class        *string `json:"class,omitempty"`
	DriverName   *string `json:"driver_name,omitempty"`
	HardwareID   *string `json:"hardware_id,omitempty"`
	ID           string  `json:"id"`
	AssetID      string  `json:"asset_id"`
	Bus          string  `json:"bus"`
	Address      string  `json:"address"`
	CollectedAt  string  `json:"collected_at"`
}

// LoadedDriverFilter constrains ListLoadedDrivers.
type LoadedDriverFilter struct {
	AssetID string
	Limit   int
	Offset  int
}

// ListLoadedDrivers returns loaded driver rows in collected_at DESC order,
// optionally scoped to a single asset. Returns an empty slice (not error)
// when the table is missing — convenient on a freshly migrated DB.
func (s *SQLiteStore) ListLoadedDrivers(
	ctx context.Context, f LoadedDriverFilter,
) ([]LoadedDriverRow, error) {
	q := `
		SELECT id, asset_id, name, display_name, path, version, vendor,
		       signer, signature_state, signature_algo, driver_framework,
		       start_mode, state, architecture,
		       on_disk_sha256, authentihash, import_hash, cpe23, description,
		       taint_flags_json, dependencies_json,
		       loaded_at, collected_at
		FROM loaded_drivers
	`
	args := []any{}
	if f.AssetID != "" {
		q += " WHERE asset_id = ?"
		args = append(args, f.AssetID)
	}
	q += " ORDER BY collected_at DESC, name ASC"
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
		if isNoSuchTableErr(err) {
			return []LoadedDriverRow{}, nil
		}
		return nil, fmt.Errorf("list loaded_drivers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]LoadedDriverRow, 0, 64)
	for rows.Next() {
		var r LoadedDriverRow
		if scanErr := rows.Scan(
			&r.ID, &r.AssetID, &r.Name,
			&r.DisplayName, &r.Path, &r.Version, &r.Vendor,
			&r.Signer, &r.SignatureState, &r.SignatureAlgo,
			&r.DriverFramework, &r.StartMode, &r.State, &r.Architecture,
			&r.OnDiskSHA256, &r.Authentihash, &r.ImportHash,
			&r.CPE23, &r.Description,
			&r.TaintFlagsJSON, &r.DependenciesRaw,
			&r.LoadedAt, &r.CollectedAt,
		); scanErr != nil {
			return nil, fmt.Errorf("scan loaded_drivers: %w", scanErr)
		}
		out = append(out, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate loaded_drivers: %w", rowsErr)
	}
	return out, nil
}

// DeviceBindingFilter constrains ListDeviceBindings.
type DeviceBindingFilter struct {
	AssetID string
	Limit   int
	Offset  int
}

// ListDeviceBindings returns device binding rows in collected_at DESC order,
// optionally scoped to a single asset.
func (s *SQLiteStore) ListDeviceBindings(
	ctx context.Context, f DeviceBindingFilter,
) ([]DeviceBindingRow, error) {
	q := `
		SELECT id, asset_id, driver_id, bus, address,
		       vendor_id, device_id, subsystem_vid, subsystem_did,
		       class, driver_name, hardware_id, collected_at
		FROM device_bindings
	`
	args := []any{}
	if f.AssetID != "" {
		q += " WHERE asset_id = ?"
		args = append(args, f.AssetID)
	}
	q += " ORDER BY collected_at DESC, bus ASC, address ASC"
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
		if isNoSuchTableErr(err) {
			return []DeviceBindingRow{}, nil
		}
		return nil, fmt.Errorf("list device_bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]DeviceBindingRow, 0, 64)
	for rows.Next() {
		var r DeviceBindingRow
		if scanErr := rows.Scan(
			&r.ID, &r.AssetID, &r.DriverID, &r.Bus, &r.Address,
			&r.VendorID, &r.DeviceID, &r.SubsystemVID, &r.SubsystemDID,
			&r.Class, &r.DriverName, &r.HardwareID, &r.CollectedAt,
		); scanErr != nil {
			return nil, fmt.Errorf("scan device_bindings: %w", scanErr)
		}
		out = append(out, r)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate device_bindings: %w", rowsErr)
	}
	return out, nil
}

// MarkLoadedDriversSynced stamps synced_at = unixepoch() on the listed IDs.
// Used by the DBOS bridge once rows are confirmed in ClickHouse.
func (s *SQLiteStore) MarkLoadedDriversSynced(ctx context.Context, ids []string) error {
	return s.markSynced(ctx, "loaded_drivers", ids)
}

// MarkDeviceBindingsSynced stamps synced_at = unixepoch() on the listed IDs.
func (s *SQLiteStore) MarkDeviceBindingsSynced(ctx context.Context, ids []string) error {
	return s.markSynced(ctx, "device_bindings", ids)
}

func (s *SQLiteStore) markSynced(ctx context.Context, table string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx mark synced %s: %w", table, err)
	}
	defer func() { _ = tx.Rollback() }()

	// Table name comes from a fixed allowlist set by the calling exported
	// method; user input is never interpolated here.
	q := fmt.Sprintf("UPDATE %s SET synced_at = unixepoch() WHERE id = ?", table)
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return fmt.Errorf("prepare mark synced %s: %w", table, err)
	}
	defer func() { _ = stmt.Close() }()

	for _, id := range ids {
		if _, execErr := stmt.ExecContext(ctx, id); execErr != nil {
			return fmt.Errorf("update %s id=%s: %w", table, id, execErr)
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit mark synced %s: %w", table, commitErr)
	}
	return nil
}

// assignDriverID returns existing UUID if non-zero, otherwise mints a UUID v7.
func assignDriverID(existing uuid.UUID) (uuid.UUID, error) {
	if existing != uuid.Nil {
		return existing, nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("uuid v7 for driver row: %w", err)
	}
	return id, nil
}

// encodeStringArray serialises a string slice to a JSON array string,
// returning "[]" for nil/empty input. Stable output (preserves order).
func encodeStringArray(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal string array: %w", err)
	}
	return string(b), nil
}
