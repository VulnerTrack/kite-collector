// Package memoryseries samples the local host's RAM at a fixed cadence and
// persists it as a durable per-machine time series (store.MemorySampleStore),
// pruning anything older than the retention window each cycle.
//
// Collection is cross-platform: it reads memory through gopsutil (via
// telemetry/hostmetrics), which supports Linux, macOS, Windows and the BSDs,
// so the same sampler runs unchanged on every OS the collector targets.
package memoryseries

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/telemetry/hostmetrics"
)

// MemReader reads the current memory statistics. Production passes a thin
// wrapper over hostmetrics.Collect; tests inject a fake.
type MemReader func(context.Context) (hostmetrics.MemStat, error)

// DefaultMemReader reads memory via the standard gopsutil-backed source.
func DefaultMemReader(ctx context.Context) (hostmetrics.MemStat, error) {
	m, err := hostmetrics.Memory(ctx)
	if err != nil {
		return m, fmt.Errorf("hostmetrics memory: %w", err)
	}
	return m, nil
}

// Sampler collects and stores one memory sample per tick for the local machine.
type Sampler struct {
	store     store.Store
	samples   store.MemorySampleStore
	read      MemReader
	retention time.Duration
	logger    *slog.Logger
	hostname  string
	now       func() time.Time
}

// New builds a Sampler if the store persists memory samples. It returns
// (nil, false) for a store without MemorySampleStore support, so the caller can
// skip wiring the ticker entirely.
func New(st store.Store, read MemReader, retention time.Duration, logger *slog.Logger) (*Sampler, bool) {
	ms, ok := st.(store.MemorySampleStore)
	if !ok {
		return nil, false
	}
	if read == nil {
		read = DefaultMemReader
	}
	if logger == nil {
		logger = slog.Default()
	}
	host, _ := os.Hostname()
	return &Sampler{
		store:     st,
		samples:   ms,
		read:      read,
		retention: retention,
		logger:    logger,
		hostname:  strings.TrimSpace(host),
		now:       time.Now,
	}, true
}

// SampleOnce records one memory point for the local machine and prunes the
// retention window. It is a quiet no-op when the local machine is not in the
// store yet (before the first scan writes it) — the next tick catches it.
func (s *Sampler) SampleOnce(ctx context.Context) error {
	machineID, ok := s.resolveLocalMachineID(ctx)
	if !ok {
		return nil
	}
	mem, err := s.read(ctx)
	if err != nil {
		return fmt.Errorf("read memory: %w", err)
	}
	if err := s.samples.InsertMemorySample(ctx, model.MemorySample{
		MachineID:   machineID,
		SampledAt:   s.now().UTC(),
		TotalBytes:  mem.Total,
		UsedBytes:   mem.Used,
		UsedPercent: mem.UsedPercent,
	}); err != nil {
		return fmt.Errorf("store memory sample: %w", err)
	}
	// Retention is best-effort: a prune failure must not drop the sample we
	// just stored, so it is logged, not returned.
	if s.retention > 0 {
		if _, err := s.samples.PruneMemorySamplesBefore(ctx, s.now().Add(-s.retention)); err != nil {
			s.logger.Warn("memoryseries: prune failed",
				"code", "agent.memory_series.prune_failed", "error", err)
		}
	}
	return nil
}

// resolveLocalMachineID finds the store row for this host: an exact hostname
// match first, then the row the local agent wrote for itself. Mirrors the
// dashboard's local-asset resolution so both agree on "this machine".
func (s *Sampler) resolveLocalMachineID(ctx context.Context) (uuid.UUID, bool) {
	machines, err := s.store.ListMachines(ctx, store.MachineFilter{Limit: 5000})
	if err != nil {
		return uuid.Nil, false
	}
	var fallback *model.Machine
	for i := range machines {
		if s.hostname != "" && strings.EqualFold(strings.TrimSpace(machines[i].Hostname), s.hostname) {
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
