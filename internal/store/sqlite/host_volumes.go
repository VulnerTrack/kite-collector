package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

var _ store.HostVolumeStore = (*SQLiteStore)(nil)

// validVolumeEncryption / validVolumeEncryptionState gate values against the
// host_volumes CHECK constraints so one malformed row can't fail the whole
// transactional replace.
func validVolumeEncryption(e string) bool {
	switch e {
	case "none", "luks", "luks2", "bitlocker", "filevault2", "apfs-encrypted", "unknown":
		return true
	}
	return false
}

func validVolumeEncryptionState(s string) bool {
	switch s {
	case "locked", "unlocked", "unknown":
		return true
	}
	return false
}

// capacityValue converts a collected capacity counter to the INTEGER SQLite
// stores. Zero means "not measured" (an unstattable mount), which is stored as
// NULL so it reads as unknown instead of "0 bytes"; anything past MaxInt64 is
// clamped rather than wrapped negative.
func capacityValue(v uint64) any {
	if v == 0 {
		return nil
	}
	if v > math.MaxInt64 {
		return int64(math.MaxInt64)
	}
	return int64(v)
}

// ReplaceHostVolumes upserts a machine's mounted filesystems and prunes the
// mounts that have gone away, in one transaction.
//
// Unlike ReplaceHostListeners this is not delete-then-insert: host_volumes is
// keyed on (machine_id, mount_point) and the DBOS bridge builds capacity
// timelines from it, so a volume must keep its row identity across rescans.
// Pruning keys on collected_at — every row this run touched carries the run's
// timestamp, so anything still holding an older one is a mount that no longer
// exists. That avoids an IN (...) list, which would blow past the SQLite
// variable limit on a storage server near MaxVolumes mounts.
//
// synced_at is reset to NULL on every upsert: capacity is time-varying, so a
// rescan genuinely produces new data for the sync bridge to ship.
func (s *SQLiteStore) ReplaceHostVolumes(ctx context.Context, machineID uuid.UUID, volumes []model.HostVolume) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin host volumes tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const upsert = `INSERT INTO host_volumes
		(id, machine_id, mount_point, device, filesystem, label, fs_uuid,
		 size_bytes, used_bytes, inodes_total, inodes_used,
		 read_only, removable, bootable, encryption, encryption_state,
		 mount_opts, last_seen_at, collected_at, synced_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(machine_id, mount_point) DO UPDATE SET
			device           = excluded.device,
			filesystem       = excluded.filesystem,
			label            = excluded.label,
			fs_uuid          = excluded.fs_uuid,
			size_bytes       = excluded.size_bytes,
			used_bytes       = excluded.used_bytes,
			inodes_total     = excluded.inodes_total,
			inodes_used      = excluded.inodes_used,
			read_only        = excluded.read_only,
			removable        = excluded.removable,
			bootable         = excluded.bootable,
			encryption       = excluded.encryption,
			encryption_state = excluded.encryption_state,
			mount_opts       = excluded.mount_opts,
			last_seen_at     = excluded.last_seen_at,
			collected_at     = excluded.collected_at,
			synced_at        = NULL`

	// One timestamp for the whole run so the prune below can identify every
	// row this pass touched with a single equality test.
	runStamp := time.Now().UTC().Format(time.RFC3339)
	for _, v := range volumes {
		if v.CollectedAt.IsZero() {
			continue
		}
		runStamp = v.CollectedAt.UTC().Format(time.RFC3339)
		break
	}

	for _, v := range volumes {
		if v.MountPoint == "" {
			continue
		}
		encryption := v.Encryption
		if !validVolumeEncryption(encryption) {
			encryption = "unknown"
		}
		encState := v.EncryptionState
		if !validVolumeEncryptionState(encState) {
			encState = "unknown"
		}
		id := v.ID
		if id == uuid.Nil {
			id = uuid.Must(uuid.NewV7())
		}
		seen := v.LastSeenAt
		if seen.IsZero() {
			seen = time.Now()
		}
		if _, err := tx.ExecContext(ctx, upsert,
			id.String(), machineID.String(), v.MountPoint, v.Device, v.Filesystem,
			v.Label, v.FSUUID,
			capacityValue(v.SizeBytes), capacityValue(v.UsedBytes),
			capacityValue(v.InodesTotal), capacityValue(v.InodesUsed),
			boolToInt(v.ReadOnly), boolToInt(v.Removable), boolToInt(v.Bootable),
			encryption, encState, v.MountOpts,
			seen.UTC().Format(time.RFC3339), runStamp); err != nil {
			return fmt.Errorf("upsert host volume %s: %w", v.MountPoint, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM host_volumes WHERE machine_id = ? AND collected_at <> ?`,
		machineID.String(), runStamp); err != nil {
		return fmt.Errorf("prune stale host volumes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit host volumes: %w", err)
	}
	return nil
}

// ListHostVolumes returns a machine's volumes ordered by mount point.
func (s *SQLiteStore) ListHostVolumes(ctx context.Context, machineID uuid.UUID) ([]model.HostVolume, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, mount_point, COALESCE(device,''), COALESCE(filesystem,''),
		        COALESCE(label,''), COALESCE(fs_uuid,''), COALESCE(mount_opts,''),
		        size_bytes, used_bytes, inodes_total, inodes_used,
		        read_only, removable, bootable, encryption, encryption_state,
		        last_seen_at, collected_at
		   FROM host_volumes
		  WHERE machine_id = ?
		  ORDER BY mount_point`, machineID.String())
	if err != nil {
		return nil, fmt.Errorf("list host volumes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []model.HostVolume
	for rows.Next() {
		var (
			v                                   model.HostVolume
			idStr                               string
			size, used, inodesTotal, inodesUsed sql.NullInt64
			readOnly, removable, bootable       int
			seen, collected                     string
		)
		if scanErr := rows.Scan(&idStr, &v.MountPoint, &v.Device, &v.Filesystem,
			&v.Label, &v.FSUUID, &v.MountOpts,
			&size, &used, &inodesTotal, &inodesUsed,
			&readOnly, &removable, &bootable, &v.Encryption, &v.EncryptionState,
			&seen, &collected); scanErr != nil {
			return nil, fmt.Errorf("scan host volume: %w", scanErr)
		}
		v.MachineID = machineID
		parsedID, parseErr := uuid.Parse(idStr)
		if parseErr != nil {
			return nil, fmt.Errorf("parse host volume id %q: %w", idStr, parseErr)
		}
		v.ID = parsedID
		v.SizeBytes = nullInt64ToUint64(size)
		v.UsedBytes = nullInt64ToUint64(used)
		v.InodesTotal = nullInt64ToUint64(inodesTotal)
		v.InodesUsed = nullInt64ToUint64(inodesUsed)
		v.ReadOnly = readOnly != 0
		v.Removable = removable != 0
		v.Bootable = bootable != 0
		v.LastSeenAt, _ = time.Parse(time.RFC3339, seen)
		v.CollectedAt, _ = time.Parse(time.RFC3339, collected)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host volumes: %w", err)
	}
	return out, nil
}

func nullInt64ToUint64(n sql.NullInt64) uint64 {
	if !n.Valid || n.Int64 < 0 {
		return 0
	}
	return uint64(n.Int64)
}
