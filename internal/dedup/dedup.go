package dedup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// Deduplicator reconciles newly discovered machines against the persistent
// store. For each incoming machine it computes a natural key (SHA-256 of
// hostname|machine_type) and looks up an existing record:
//
//   - If found: the existing machine's LastSeenAt is updated, and any new
//     metadata (OS info, interfaces, software) is merged. The existing ID
//     and FirstSeenAt are preserved.
//   - If not found: a new UUID v7 is assigned and FirstSeenAt = now.
//
// The returned slice contains machines in a state ready for upsert. Callers
// can distinguish new from updated machines by checking whether FirstSeenAt
// equals LastSeenAt (new) or not (updated).
type Deduplicator struct {
	store   store.Store
	metrics *metrics.Metrics
	clock   func() time.Time
}

// Option configures a Deduplicator.
type Option func(*Deduplicator)

// WithClock overrides the time source used during deduplication. Useful for
// deterministic tests.
func WithClock(fn func() time.Time) Option {
	return func(d *Deduplicator) { d.clock = fn }
}

// New creates a Deduplicator backed by the given store. An optional
// *metrics.Metrics can be passed to record dedup skip counters; pass nil
// to disable metrics.
func New(s store.Store, m *metrics.Metrics, opts ...Option) *Deduplicator {
	d := &Deduplicator{store: s, metrics: m, clock: time.Now}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Result groups deduplication output so callers can inspect what changed.
type Result struct {
	// Machines contains all deduplicated machines, ready for persistence.
	Machines []model.Machine
	// NewCount is the number of machines that were not previously known.
	NewCount int
	// UpdatedCount is the number of machines that already existed.
	UpdatedCount int
}

// Deduplicate reconciles incoming machines against the store and returns a
// Result with the merged machine list and counts.
func (d *Deduplicator) Deduplicate(ctx context.Context, machines []model.Machine) (*Result, error) {
	now := d.clock().UTC()

	result := &Result{
		Machines: make([]model.Machine, 0, len(machines)),
	}

	// Deduplicate within the incoming batch itself by natural key so we
	// don't process the same hostname|type combination twice.
	seen := make(map[string]struct{}, len(machines))

	for i := range machines {
		machine := &machines[i]
		machine.ComputeNaturalKey()

		if _, dup := seen[machine.NaturalKey]; dup {
			slog.Info(
				"intra-batch duplicate skipped",
				"code", string(LogCodeDedupSkipIntraBatch),
				"hostname", machine.Hostname,
				"machine_type", machine.MachineType,
				"natural_key", machine.NaturalKey,
			)
			if d.metrics != nil {
				d.metrics.DedupSkipped.Inc()
			}
			continue
		}
		seen[machine.NaturalKey] = struct{}{}

		existing, err := d.store.GetMachineByNaturalKey(ctx, machine.NaturalKey)
		if err != nil {
			return nil, fmt.Errorf("dedup: lookup natural key %s: %w", machine.NaturalKey, err)
		}
		// Dual-key grace window: rows written before the natural-key
		// separator migration carry the legacy '|' digest. Look those
		// up too so we update them in place instead of creating a
		// duplicate row that the operator has to reconcile later.
		if existing == nil {
			legacy := machine.LegacyNaturalKey()
			if legacy != machine.NaturalKey {
				existing, err = d.store.GetMachineByNaturalKey(ctx, legacy)
				if err != nil {
					return nil, fmt.Errorf("dedup: lookup legacy key %s: %w", legacy, err)
				}
			}
		}

		if existing != nil {
			// Merge: preserve identity, update volatile fields.
			merged := mergeMachine(existing, machine, now)
			result.Machines = append(result.Machines, merged)
			result.UpdatedCount++

			slog.Debug(
				"existing machine merged into batch",
				"code", string(LogCodeDedupUpdated),
				"id", merged.ID,
				"hostname", merged.Hostname,
				"natural_key", merged.NaturalKey,
			)
		} else {
			// New machine — assign identity.
			machine.ID = uuid.Must(uuid.NewV7())
			machine.FirstSeenAt = now
			machine.LastSeenAt = now
			result.Machines = append(result.Machines, *machine)
			result.NewCount++

			slog.Debug(
				"new machine assigned identity",
				"code", string(LogCodeDedupNew),
				"id", machine.ID,
				"hostname", machine.Hostname,
				"natural_key", machine.NaturalKey,
			)
		}
	}

	slog.Info(
		"dedup pass complete",
		"code", string(LogCodeDedupCompleted),
		"total", len(result.Machines),
		"new", result.NewCount,
		"updated", result.UpdatedCount,
		"input_machines", len(machines),
	)

	return result, nil
}

// mergeMachine creates a merged Machine that preserves the existing identity
// (ID, FirstSeenAt, NaturalKey) while incorporating newer metadata from the
// incoming discovery.
func mergeMachine(existing *model.Machine, incoming *model.Machine, now time.Time) model.Machine {
	merged := *existing
	merged.LastSeenAt = now

	// Update OS family only when the existing record is blank (stable field).
	if incoming.OSFamily != "" && existing.OSFamily == "" {
		merged.OSFamily = incoming.OSFamily
	}

	// Mutable fields: always prefer incoming non-empty values so that
	// newer discovery data wins over stale records.
	if incoming.OSVersion != "" {
		merged.OSVersion = incoming.OSVersion
	}

	// Always prefer a more specific discovery source when the existing one
	// is empty.
	if incoming.DiscoverySource != "" && existing.DiscoverySource == "" {
		merged.DiscoverySource = incoming.DiscoverySource
	}

	// Merge tags: prefer incoming if non-empty.
	if incoming.Tags != "" && incoming.Tags != "null" {
		merged.Tags = incoming.Tags
	}

	// Mutable fields: always prefer incoming non-empty values.
	if incoming.Environment != "" {
		merged.Environment = incoming.Environment
	}
	if incoming.Owner != "" && existing.Owner == "" {
		merged.Owner = incoming.Owner
	}
	if incoming.Criticality != "" && existing.Criticality == "" {
		merged.Criticality = incoming.Criticality
	}

	return merged
}
