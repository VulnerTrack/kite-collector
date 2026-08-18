package dedup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/sanitize"
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

	// Group the batch by natural key, preserving first-appearance order, then
	// fold each group's intra-batch duplicates into a single machine BEFORE
	// touching the store. Two local sources (e.g. the osquery source and the
	// agent probe) both emit a machine for the same host every scan; folding
	// them — rather than dropping all but the first — keeps each source's
	// unique data (osquery's Tags, the agent's fields) instead of losing the
	// loser's, and the fold is order-independent so the persisted record does
	// not flip between scans (RFC-0151 OQ4).
	order := make([]string, 0, len(machines))
	groups := make(map[string][]model.Machine, len(machines))
	for i := range machines {
		// Sanitize BEFORE ComputeNaturalKey so dedup keys derive from the
		// cleaned hostname — every source funnels through here, making this
		// the single boundary where machine text is guaranteed valid UTF-8.
		sanitizeMachine(&machines[i])
		machines[i].ComputeNaturalKey()
		key := machines[i].NaturalKey
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], machines[i])
	}

	for _, key := range order {
		members := groups[key]
		machine := foldIntraBatch(members, now)
		if collapsed := len(members) - 1; collapsed > 0 {
			slog.Info(
				"intra-batch duplicates merged",
				"code", string(LogCodeDedupMergeIntraBatch),
				"hostname", machine.Hostname,
				"machine_type", machine.MachineType,
				"natural_key", key,
				"merged", collapsed,
			)
			if d.metrics != nil {
				d.metrics.DedupSkipped.Add(float64(collapsed))
			}
		}

		existing, err := d.store.GetMachineByNaturalKey(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("dedup: lookup natural key %s: %w", key, err)
		}
		// Dual-key grace window: rows written before the natural-key
		// separator migration carry the legacy '|' digest. Look those
		// up too so we update them in place instead of creating a
		// duplicate row that the operator has to reconcile later.
		if existing == nil {
			legacy := machine.LegacyNaturalKey()
			if legacy != key {
				existing, err = d.store.GetMachineByNaturalKey(ctx, legacy)
				if err != nil {
					return nil, fmt.Errorf("dedup: lookup legacy key %s: %w", legacy, err)
				}
			}
		}

		if existing != nil {
			// Merge: preserve identity, update volatile fields.
			merged := mergeMachine(existing, &machine, now)
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
			result.Machines = append(result.Machines, machine)
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

// foldIntraBatch merges every same-natural-key machine from one scan batch
// into a single machine in a DETERMINISTIC order, so the result does not
// depend on the nondeterministic order discovery sources finish in.
//
// Members are ordered by DiscoverySource (then by material content as a
// stable tiebreak) and folded left-to-right through mergeMachine. Because
// mergeMachine's volatile fields are last-writer-wins, the highest-sorted
// source wins them — and it wins them the SAME way on every scan, so a host
// discovered by more than one local source no longer flips OSVersion (and
// friends) batch to batch. The lowest-sorted source is the base, so its
// sticky fields (identity-adjacent: DiscoverySource, Architecture) are
// likewise stable. Nothing is dropped: each source contributes its non-empty
// fields per the merge rules.
func foldIntraBatch(members []model.Machine, now time.Time) model.Machine {
	if len(members) == 1 {
		return members[0]
	}
	sorted := make([]model.Machine, len(members))
	copy(sorted, members)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].DiscoverySource != sorted[j].DiscoverySource {
			return sorted[i].DiscoverySource < sorted[j].DiscoverySource
		}
		// Same source AND same natural key: a pathological duplicate. Break
		// the tie on material content so the fold stays deterministic even
		// then, rather than depending on batch arrival order.
		return sorted[i].MaterialFingerprint() < sorted[j].MaterialFingerprint()
	})
	acc := sorted[0]
	for i := 1; i < len(sorted); i++ {
		acc = mergeMachine(&acc, &sorted[i], now)
	}
	return acc
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

	// Merge tags by UNION, not overwrite. Two sources discovering the same
	// host (e.g. the local agent and osquery) each contribute distinct tag
	// keys — hardware_uuid and file_events_24h from osquery, software facts
	// from the agent. Overwriting with incoming would silently drop whichever
	// source lost the dedup race, so union the JSON objects with incoming
	// winning on key conflicts.
	merged.Tags = mergeTagsJSON(existing.Tags, incoming.Tags)

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

// mergeTagsJSON unions two JSON tag objects, incoming keys winning on
// conflict. Empty/"null"/non-object inputs are treated as no tags. If both
// sides carry tags but either fails to parse as an object, the non-empty
// input is preferred (incoming first) rather than dropping data — a merge
// must never lose more than the overwrite it replaces.
func mergeTagsJSON(existing, incoming string) string {
	ex := parseTagObject(existing)
	in := parseTagObject(incoming)

	switch {
	case ex == nil && in == nil:
		// Neither parsed as an object: keep whichever raw string has content,
		// incoming preferred (matches the prior overwrite semantics).
		if incoming != "" && incoming != "null" {
			return incoming
		}
		return existing
	case ex == nil:
		return incoming
	case in == nil:
		return existing
	}

	for k, v := range in {
		ex[k] = v // incoming wins on conflict
	}
	out, err := json.Marshal(ex)
	if err != nil {
		// Marshalling a map[string]json.RawMessage should not fail; if it
		// somehow does, fall back to the incoming raw string rather than
		// emitting a broken merge.
		if incoming != "" && incoming != "null" {
			return incoming
		}
		return existing
	}
	return string(out)
}

// parseTagObject decodes s into a JSON object map, or returns nil if s is
// empty, "null", or not a JSON object.
func parseTagObject(s string) map[string]json.RawMessage {
	if s == "" || s == "null" {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil || m == nil {
		return nil
	}
	return m
}

// sanitizeMachine runs the standard sanitize pipeline (encoding repair,
// ANSI/invisible-rune removal, trim) over every machine text field that
// originates outside kite — discovery probes, remote-tool output, MDM/CMDB
// connector APIs — so persisted records, JSON APIs, and proto3 OTLP string
// fields (which reject invalid UTF-8 at marshal) all see clean text.
// Kite-authored fields (DiscoverySource, TenantID, NaturalKey) are skipped.
func sanitizeMachine(m *model.Machine) {
	for _, f := range []*string{
		&m.Hostname, &m.OSFamily, &m.OSVersion, &m.KernelVersion,
		&m.Architecture, &m.Environment, &m.Owner, &m.Criticality,
		&m.Tags, &m.MDMEnrollmentID, &m.CMDBSysID, &m.Site, &m.Tenant,
		&m.MachineTag, &m.OperationalStatus, &m.OwnershipType,
		&m.EnrolledUserUPN, &m.ComplianceState,
	} {
		*f = sanitize.Clean(*f)
	}
}
