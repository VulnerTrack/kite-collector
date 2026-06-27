package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// AmbiguousMergeResolution describes what the deduper did with the
// incoming asset when it detected a signal-based collision spanning
// multiple existing asset records. The data path always parks the
// incoming asset (Resolution = "deferred"); the operator decides
// out-of-band whether to merge into one candidate, create a new asset,
// or reject the signal as noise.
type AmbiguousMergeResolution string

const (
	// AmbiguousResolutionDeferred is the only value the data path itself
	// writes — manual review or the TTL default-action job resolves the
	// event into one of the operator-facing values below.
	AmbiguousResolutionDeferred AmbiguousMergeResolution = "deferred"
	// AmbiguousResolutionMergeInto records that an operator merged the
	// incoming asset into a specific existing asset_id.
	AmbiguousResolutionMergeInto AmbiguousMergeResolution = "merge_into"
	// AmbiguousResolutionCreateNew records that the candidates are
	// genuinely distinct physical assets and the incoming asset deserves
	// its own row.
	AmbiguousResolutionCreateNew AmbiguousMergeResolution = "create_new"
	// AmbiguousResolutionRejectSignal records that the colliding signal
	// is noise (misconfigured discoverer, hypervisor bug) and future
	// observations of the same (signal_kind, signal_hash) should be
	// suppressed without raising an event.
	AmbiguousResolutionRejectSignal AmbiguousMergeResolution = "reject_signal"
)

// AmbiguousMerge is the event emitted when a Fingerprinter signal lookup
// in the alias graph would have produced multiple distinct asset_ids.
// The deduper never picks among them silently — the alias-graph promotion
// rule is conservative on purpose. Operators triage these via the
// dashboard or via the TTL-default job that auto-resolves after a grace
// period (default 30 days, action: create_new).
type AmbiguousMerge struct {
	DetectedAt      time.Time                `json:"detected_at"`
	Signal          AmbiguousSignal          `json:"signal"`
	TenantID        string                   `json:"tenant_id"`
	DiscoverySource string                   `json:"discovery_source"`
	Resolution      AmbiguousMergeResolution `json:"resolution"`
	Candidates      []AmbiguousCandidate     `json:"candidates"`
	Incoming        model.Asset              `json:"incoming"`
	EventID         uuid.UUID                `json:"event_id"`
}

// AmbiguousSignal records the canonical signal that produced the
// collision. Hash is the hex of SHA-256(Bytes); Value is the
// canonicalized human-readable form when the signal is not sensitive
// (e.g. cloud instance_id) and is left blank for sensitive signals
// (e.g. machine-id, TPM EK) where the hash alone is sufficient context.
type AmbiguousSignal struct {
	Kind  string `json:"kind"`
	Hash  string `json:"hash"`
	Value string `json:"value,omitempty"`
}

// AmbiguousCandidate is one of the existing assets that matched the
// colliding signal. The slice is sorted by Confidence DESC then
// LastSeenAt DESC by the deduper before emission so the operator sees
// the strongest evidence first — but the deduper never picks for them.
type AmbiguousCandidate struct {
	FirstSeenAt  time.Time       `json:"first_seen_at"`
	LastSeenAt   time.Time       `json:"last_seen_at"`
	Hostname     string          `json:"hostname"`
	AssetType    model.AssetType `json:"asset_type"`
	OtherSignals []string        `json:"other_signals"`
	AssetID      uuid.UUID       `json:"asset_id"`
	Confidence   uint8           `json:"confidence"`
}

// NewAmbiguousMerge builds an AmbiguousMerge event with a freshly
// assigned EventID and a Deferred resolution. Callers supply the
// in-process clock so tests can pin DetectedAt deterministically.
func NewAmbiguousMerge(
	now time.Time,
	tenant, source string,
	incoming model.Asset,
	sig Signal,
	value string,
	candidates []AmbiguousCandidate,
) AmbiguousMerge {
	h := sha256.Sum256(sig.Bytes)
	return AmbiguousMerge{
		EventID:         uuid.Must(uuid.NewV7()),
		TenantID:        tenant,
		DetectedAt:      now.UTC(),
		DiscoverySource: source,
		Incoming:        incoming,
		Signal: AmbiguousSignal{
			Kind:  sig.Kind,
			Hash:  hex.EncodeToString(h[:]),
			Value: value,
		},
		Candidates: candidates,
		Resolution: AmbiguousResolutionDeferred,
	}
}

// AliasEdge is one row in the alias graph: an asset has observed
// (signal_kind, signal_hash) at some confidence, from some source. The
// graph index is over (signal_kind, signal_hash) so a single signal can
// be looked up across all assets that have ever exhibited it.
type AliasEdge struct {
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	SignalKind  string     `json:"signal_kind"`
	SignalHash  string     `json:"signal_hash"`
	Source      string     `json:"source"`
	AssetID     uuid.UUID  `json:"asset_id"`
	Confidence  Confidence `json:"confidence"`
}

// AliasEdgesFromSignals converts the signal slice returned by a
// Fingerprinter into the AliasEdge rows that should be upserted into
// asset_aliases for an asset. Each signal becomes one edge; the
// resulting rows can be batched into a single transaction by the store.
func AliasEdgesFromSignals(assetID uuid.UUID, source string, conf Confidence, now time.Time, sigs []Signal) []AliasEdge {
	out := make([]AliasEdge, 0, len(sigs))
	for _, s := range sigs {
		h := sha256.Sum256(s.Bytes)
		out = append(out, AliasEdge{
			AssetID:     assetID,
			SignalKind:  s.Kind,
			SignalHash:  hex.EncodeToString(h[:]),
			Confidence:  conf,
			Source:      source,
			FirstSeenAt: now.UTC(),
			LastSeenAt:  now.UTC(),
		})
	}
	return out
}

// AliasLookup is the contract a store implementation provides so the
// deduper can resolve cross-source merges through the alias graph. The
// store-side implementation is intentionally a separate interface from
// store.Store so the alias-graph migration can ship independently and
// so test-time fakes stay small.
type AliasLookup interface {
	// FindByAlias returns every AliasEdge that matches the (kind, hash)
	// pair. The deduper passes the result to ResolveAmbiguous() to
	// decide whether to merge, defer, or proceed.
	FindByAlias(kind, hash string) ([]AliasEdge, error)
}

// ResolveAmbiguous classifies the outcome of an alias-graph lookup.
//
//   - len(edges)==0 → no prior knowledge of this signal; insert.
//   - len(edges)==1 → unambiguous match; merge into the matched asset.
//   - len(edges)>1 with all rows pointing at a single asset_id → still
//     unambiguous; collapse.
//   - otherwise → ambiguous; the caller emits an AmbiguousMerge event
//     and parks the incoming asset.
//
// The returned bool is true when the result is unambiguous (the caller
// may proceed); the uuid is the canonical asset_id when applicable.
func ResolveAmbiguous(edges []AliasEdge) (canonical uuid.UUID, unambiguous bool) {
	if len(edges) == 0 {
		return uuid.Nil, true
	}
	first := edges[0].AssetID
	for _, e := range edges[1:] {
		if e.AssetID != first {
			return uuid.Nil, false
		}
	}
	return first, true
}
