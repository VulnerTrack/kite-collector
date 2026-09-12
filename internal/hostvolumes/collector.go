// Package hostvolumes wires the (previously unused) gopsutil volumes collector
// into persistence: it enumerates the local host's mounted filesystems with
// their capacity metrics and encryption posture, and saves the set to
// host_volumes — upserting each mount and pruning the ones that have gone away.
//
// This is what makes the dashboard's Volumes page real. The collector, the
// table and the page all already existed; nothing ran the collector, so the
// table stayed empty and the page permanently showed zero rows.
//
// Collection is cross-platform (gopsutil/v4/disk for capacity, per-OS probes
// for LUKS / BitLocker / FileVault) and strictly read-only: it queries mount
// tables and metadata, never mounts, unmounts, or modifies a volume.
package hostvolumes

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/volumes"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// Collector enumerates and persists the local host's volumes.
type Collector struct {
	store    store.Store
	volumes  volumes.Collector
	sink     store.HostVolumeStore
	logger   *slog.Logger
	hostname string
	now      func() time.Time
}

// New builds a Collector when the store persists host volumes. A nil volume
// collector uses the production gopsutil one. Returns (nil, false) for a store
// without HostVolumeStore support, so the caller can skip wiring the ticker.
func New(st store.Store, vc volumes.Collector, logger *slog.Logger) (*Collector, bool) {
	sink, ok := st.(store.HostVolumeStore)
	if !ok {
		return nil, false
	}
	if vc == nil {
		vc = volumes.NewCollector()
	}
	if logger == nil {
		logger = slog.Default()
	}
	host, _ := os.Hostname()
	return &Collector{
		store:    st,
		volumes:  vc,
		sink:     sink,
		logger:   logger,
		hostname: strings.TrimSpace(host),
		now:      time.Now,
	}, true
}

// CollectAndStore enumerates the local volumes and replaces the machine's
// host_volumes set. It is a quiet no-op before the first scan has written the
// local machine.
//
// A collect error that still yielded rows (gopsutil reports per-mount failures
// on macOS system volumes even as root) persists what it got: a partial
// inventory beats none. A collect error with no rows returns without touching
// the store, so a transient failure cannot prune a machine's entire volume set.
func (c *Collector) CollectAndStore(ctx context.Context) error {
	machineID, ok := c.resolveLocalMachineID(ctx)
	if !ok {
		return nil
	}
	raw, err := c.volumes.Collect(ctx)
	if err != nil && len(raw) == 0 {
		return fmt.Errorf("collect volumes: %w", err)
	}
	if err != nil {
		c.logger.Warn("host volumes collection degraded; storing partial inventory",
			"code", string(LogCodeCollectDegraded), "volumes", len(raw), "error", err)
	}

	now := c.now().UTC()
	out := make([]model.HostVolume, 0, len(raw))
	for _, v := range raw {
		seen := v.LastSeenAt
		if seen.IsZero() {
			seen = now
		}
		collected := v.CollectedAt
		if collected.IsZero() {
			collected = now
		}
		out = append(out, model.HostVolume{
			MachineID:       machineID,
			MountPoint:      v.MountPoint,
			Device:          v.Device,
			Filesystem:      v.Filesystem,
			Label:           v.Label,
			FSUUID:          v.FSUUID,
			MountOpts:       v.MountOpts,
			Encryption:      string(v.Encryption),
			EncryptionState: string(v.EncryptionState),
			SizeBytes:       v.SizeBytes,
			UsedBytes:       v.UsedBytes,
			InodesTotal:     v.InodesTotal,
			InodesUsed:      v.InodesUsed,
			ReadOnly:        v.ReadOnly,
			Removable:       v.Removable,
			Bootable:        v.Bootable,
			LastSeenAt:      seen,
			CollectedAt:     collected,
		})
	}

	if err := c.sink.ReplaceHostVolumes(ctx, machineID, out); err != nil {
		return fmt.Errorf("store host volumes: %w", err)
	}
	return nil
}

// resolveLocalMachineID finds this host's store row: exact hostname match
// first, then the row the local agent wrote for itself. Mirrors the memory
// sampler, the listeners collector, and the dashboard resolution.
func (c *Collector) resolveLocalMachineID(ctx context.Context) (uuid.UUID, bool) {
	machines, err := c.store.ListMachines(ctx, store.MachineFilter{Limit: 5000})
	if err != nil {
		return uuid.Nil, false
	}
	var fallback *model.Machine
	for i := range machines {
		if c.hostname != "" && strings.EqualFold(strings.TrimSpace(machines[i].Hostname), c.hostname) {
			return machines[i].ID, true
		}
		src := strings.ToLower(strings.TrimSpace(machines[i].DiscoverySource))
		if fallback == nil && (src == "local_controller" || src == "agent") {
			fallback = &machines[i]
		}
	}
	if fallback != nil {
		return fallback.ID, true
	}
	return uuid.Nil, false
}
