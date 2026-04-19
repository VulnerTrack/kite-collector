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

// Deduplicator reconciles newly discovered assets against the persistent
// store. For each incoming asset it computes a natural key (SHA-256 of
// hostname|asset_type) and looks up an existing record:
//
//   - If found: the existing asset's LastSeenAt is updated, and any new
//     metadata (OS info, interfaces, software) is merged. The existing ID
//     and FirstSeenAt are preserved.
//   - If not found: a new UUID v7 is assigned and FirstSeenAt = now.
//
// The returned slice contains assets in a state ready for upsert. Callers
// can distinguish new from updated assets by checking whether FirstSeenAt
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
	// Assets contains all deduplicated assets, ready for persistence.
	Assets []model.Asset
	// NewCount is the number of assets that were not previously known.
	NewCount int
	// UpdatedCount is the number of assets that already existed.
	UpdatedCount int
}

// Deduplicate reconciles incoming assets against the store and returns a
// Result with the merged asset list and counts.
func (d *Deduplicator) Deduplicate(ctx context.Context, assets []model.Asset) (*Result, error) {
	now := d.clock().UTC()

	result := &Result{
		Assets: make([]model.Asset, 0, len(assets)),
	}

	// Deduplicate within the incoming batch itself by natural key so we
	// don't process the same hostname|type combination twice.
	seen := make(map[string]struct{}, len(assets))

	for i := range assets {
		asset := &assets[i]
		asset.ComputeNaturalKey()

		if _, dup := seen[asset.NaturalKey]; dup {
			slog.Info("dedup: skipping intra-batch duplicate",
				"hostname", asset.Hostname,
				"asset_type", asset.AssetType,
			)
			if d.metrics != nil {
				d.metrics.DedupSkipped.Inc()
			}
			continue
		}
		seen[asset.NaturalKey] = struct{}{}

		existing, err := d.store.GetAssetByNaturalKey(ctx, asset.NaturalKey)
		if err != nil {
			return nil, fmt.Errorf("dedup: lookup natural key %s: %w", asset.NaturalKey, err)
		}

		if existing != nil {
			// Merge: preserve identity, update volatile fields.
			merged := mergeAsset(existing, asset, now)
			result.Assets = append(result.Assets, merged)
			result.UpdatedCount++

			slog.Debug("dedup: updated existing asset",
				"id", merged.ID,
				"hostname", merged.Hostname,
			)
		} else {
			// New asset — assign identity.
			asset.ID = uuid.Must(uuid.NewV7())
			asset.FirstSeenAt = now
			asset.LastSeenAt = now
			result.Assets = append(result.Assets, *asset)
			result.NewCount++

			slog.Debug("dedup: new asset",
				"id", asset.ID,
				"hostname", asset.Hostname,
			)
		}
	}

	slog.Info("dedup: completed",
		"total", len(result.Assets),
		"new", result.NewCount,
		"updated", result.UpdatedCount,
	)

	return result, nil
}

// mergeAsset creates a merged Asset that preserves the existing identity
// (ID, FirstSeenAt, NaturalKey) while incorporating newer metadata from the
// incoming discovery.
func mergeAsset(existing *model.Asset, incoming *model.Asset, now time.Time) model.Asset {
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
